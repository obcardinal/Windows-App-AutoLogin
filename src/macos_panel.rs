use anyhow::Context;
use block2::RcBlock;
use core_foundation::runloop::{CFRunLoopGetMain, CFRunLoopWakeUp};
use eframe::egui;
use objc2::{rc::Retained, runtime::ProtocolObject};
use objc2_app_kit::{
    NSApplication, NSColor, NSEvent, NSFloatingWindowLevel, NSNormalWindowLevel, NSStatusItem,
    NSView, NSWindow, NSWindowButton, NSWindowCollectionBehavior, NSWindowDidResignKeyNotification,
    NSWindowStyleMask,
};
use objc2_foundation::{
    MainThreadMarker, NSNotificationCenter, NSObjectProtocol, NSPoint, NSRect, NSRunLoop, NSSize,
};
use objc2_quartz_core::{kCAGravityBottomLeft, CALayer, CAMetalLayer};
use std::cell::Cell;
use std::sync::{Arc, Mutex};
use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};

const MAX_WIRE_BYTES: usize = 240;
const MAX_COORDINATE: f64 = 100_000.0;
const MAX_SCREEN_SIZE: f64 = 32_768.0;
const PANEL_GAP: f64 = 6.0;
const PANEL_CORNER_RADIUS: f64 = 12.0;

/// WindowServer counts each mouse-down once for the entire login session. AppKit
/// can deliver the resulting focus loss and status-item action in either process first.
pub(crate) fn left_mouse_press_id() -> u64 {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGEventSourceCounterForEventType(state: i32, event_type: u32) -> u32;
    }
    // SAFETY: Both constants are public CoreGraphics values, and no pointers cross FFI.
    const COMBINED_SESSION_STATE: i32 = 0;
    const LEFT_MOUSE_DOWN: u32 = 1;
    u64::from(unsafe { CGEventSourceCounterForEventType(COMBINED_SESSION_STATE, LEFT_MOUSE_DOWN) })
        + 1
}

pub(crate) struct PanelFocusObserver {
    window: Retained<NSWindow>,
    token: Retained<ProtocolObject<dyn NSObjectProtocol>>,
    focus_loss: Arc<Mutex<Option<(u64, Option<NSPoint>)>>>,
}

impl PanelFocusObserver {
    pub(crate) fn install(
        handle: &impl HasWindowHandle,
        ctx: egui::Context,
    ) -> anyhow::Result<Self> {
        let window = native_window(handle)?;
        let focus_loss = Arc::new(Mutex::new(None));
        let loss = focus_loss.clone();
        let callback = RcBlock::new(move |_| {
            let press_id = left_mouse_press_id();
            // AppKit can deactivate the panel before delivering mouseDown to
            // the status item. Capture the pointer here, before a later UI
            // frame or a mouse-up changes the state of the gesture.
            let mouse_down = (NSEvent::pressedMouseButtons() & 1 != 0).then(NSEvent::mouseLocation);
            tracing::debug!(target: "waal::panel", press_id, left_button_down = mouse_down.is_some(), "Panel resigned key");
            *loss.lock().unwrap_or_else(|e| e.into_inner()) = Some((press_id, mouse_down));
            ctx.request_repaint();
        });
        // SAFETY: Observe only our root NSWindow. The synchronous block captures
        // thread-safe state, and Drop unregisters this exact token.
        let token = unsafe {
            NSNotificationCenter::defaultCenter().addObserverForName_object_queue_usingBlock(
                Some(NSWindowDidResignKeyNotification),
                Some(&window),
                None,
                &callback,
            )
        };
        Ok(Self {
            window,
            token,
            focus_loss,
        })
    }

    pub(crate) fn take_focus_loss(&self) -> Option<(u64, Option<NSPoint>)> {
        self.focus_loss
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .filter(|_| !self.window.isKeyWindow())
    }
}

impl Drop for PanelFocusObserver {
    fn drop(&mut self) {
        // SAFETY: token was returned by this notification center during install.
        unsafe { NSNotificationCenter::defaultCenter().removeObserver((*self.token).as_ref()) };
    }
}

/// Geometry remains in AppKit screen points from capture through placement.
/// Scaling a global screen origin by one display's DPI breaks mixed-DPI layouts.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct PanelAnchor {
    pub(crate) icon_x: f64,
    pub(crate) icon_y: f64,
    pub(crate) icon_width: f64,
    pub(crate) icon_height: f64,
    pub(crate) screen_x: f64,
    pub(crate) screen_y: f64,
    pub(crate) screen_width: f64,
    pub(crate) screen_height: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Presentation {
    Window,
    Panel(PanelAnchor),
}

#[derive(Clone, Copy)]
struct PendingPanelResize {
    window_number: isize,
    anchor: PanelAnchor,
    size: NSSize,
}

thread_local! {
    // Each UI process owns one root window. A newer layout supersedes a resize
    // requested before AppKit returned to its main run loop.
    static PENDING_PANEL_RESIZE: Cell<Option<PendingPanelResize>> = const { Cell::new(None) };
}

impl Presentation {
    pub(crate) fn from_status_item(status_item: &NSStatusItem) -> Option<Self> {
        let mtm = MainThreadMarker::new()?;
        if !status_item.isVisible() {
            return None;
        }
        let window = status_item.button(mtm)?.window()?;
        let icon = window.frame();
        let screen = window.screen()?.visibleFrame();
        let anchor = PanelAnchor {
            icon_x: icon.origin.x,
            icon_y: icon.origin.y,
            icon_width: icon.size.width,
            icon_height: icon.size.height,
            screen_x: screen.origin.x,
            screen_y: screen.origin.y,
            screen_width: screen.size.width,
            screen_height: screen.size.height,
        };
        anchor.is_valid().then_some(Self::Panel(anchor))
    }

    pub(crate) fn encode(self) -> String {
        let Self::Panel(anchor) = self else {
            return "window".to_string();
        };
        if !anchor.is_valid() {
            return "window".to_string();
        }
        // AppKit coordinates need only sub-point precision. Fixed precision
        // keeps this parent-to-child control payload strictly bounded.
        format!(
            "panel:{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3}",
            anchor.icon_x,
            anchor.icon_y,
            anchor.icon_width,
            anchor.icon_height,
            anchor.screen_x,
            anchor.screen_y,
            anchor.screen_width,
            anchor.screen_height,
        )
    }

    pub(crate) fn decode(value: &str) -> Option<Self> {
        if value == "window" {
            return Some(Self::Window);
        }
        if value.len() > MAX_WIRE_BYTES || value.bytes().any(|byte| byte.is_ascii_control()) {
            return None;
        }
        let payload = value.strip_prefix("panel:")?;
        if !payload
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b','))
        {
            return None;
        }
        let mut parts = payload.split(',');
        let mut values = [0.0; 8];
        for value in &mut values {
            *value = parts.next()?.parse::<f64>().ok()?;
        }
        if parts.next().is_some() {
            return None;
        }
        let [icon_x, icon_y, icon_width, icon_height, screen_x, screen_y, screen_width, screen_height] =
            values;
        let anchor = PanelAnchor {
            icon_x,
            icon_y,
            icon_width,
            icon_height,
            screen_x,
            screen_y,
            screen_width,
            screen_height,
        };
        anchor.is_valid().then_some(Self::Panel(anchor))
    }
}

impl PanelAnchor {
    pub(crate) fn contains_status_point(self, point: NSPoint) -> bool {
        (self.icon_x..self.icon_x + self.icon_width).contains(&point.x)
            && (self.icon_y..self.icon_y + self.icon_height).contains(&point.y)
    }

    fn is_valid(self) -> bool {
        [self.icon_x, self.icon_y, self.screen_x, self.screen_y]
            .into_iter()
            .all(|value| value.is_finite() && value.abs() <= MAX_COORDINATE)
            && self.icon_width.is_finite()
            && (1.0..=512.0).contains(&self.icon_width)
            && self.icon_height.is_finite()
            && (1.0..=256.0).contains(&self.icon_height)
            && [self.screen_width, self.screen_height]
                .into_iter()
                .all(|value| value.is_finite() && (64.0..=MAX_SCREEN_SIZE).contains(&value))
    }

    fn origin_for_size(self, size: NSSize) -> NSPoint {
        let min_x = self.screen_x + PANEL_GAP;
        let min_y = self.screen_y + PANEL_GAP;
        // Keep the content size when changing modes. If an unusually small
        // display cannot contain it, anchor to its visible lower-left edge
        // instead of producing an invalid clamp range or an off-screen origin.
        let max_x = (self.screen_x + self.screen_width - size.width - PANEL_GAP).max(min_x);
        let max_y = (self.screen_y + self.screen_height - size.height - PANEL_GAP).max(min_y);
        NSPoint::new(
            (self.icon_x + self.icon_width / 2.0 - size.width / 2.0).clamp(min_x, max_x),
            (self.icon_y - PANEL_GAP - size.height).clamp(min_y, max_y),
        )
    }
}

pub(crate) fn configure_viewport(
    viewport: egui::ViewportBuilder,
    presentation: Presentation,
) -> egui::ViewportBuilder {
    let panel = matches!(presentation, Presentation::Panel(_));
    viewport
        // The rendering surface needs alpha from creation, including when a regular
        // window later switches to a panel without recreating the renderer.
        .with_transparent(true)
        .with_decorations(!panel)
        .with_resizable(!panel)
        .with_window_level(if panel {
            egui::WindowLevel::AlwaysOnTop
        } else {
            egui::WindowLevel::Normal
        })
}

pub(crate) fn apply(
    handle: &impl HasWindowHandle,
    presentation: Presentation,
) -> anyhow::Result<()> {
    let window = native_window(handle)?;
    apply_to_window(&window, presentation)
}

pub(crate) fn resize_anchored_panel(
    handle: &impl HasWindowHandle,
    anchor: PanelAnchor,
    native_size: egui::Vec2,
) -> anyhow::Result<()> {
    let window = native_window(handle)?;
    anyhow::ensure!(
        !window
            .styleMask()
            .intersects(NSWindowStyleMask::Titled | NSWindowStyleMask::FullScreen),
        "anchored resizing requires a borderless panel"
    );
    anyhow::ensure!(
        anchor.is_valid() && native_size.is_finite() && native_size.min_elem() > 0.0,
        "invalid panel geometry"
    );
    let pending = PendingPanelResize {
        window_number: window.windowNumber(),
        anchor,
        size: NSSize::new(f64::from(native_size.x), f64::from(native_size.y)),
    };
    if PENDING_PANEL_RESIZE.replace(Some(pending)).is_none() {
        // The renderer still has to present this frame at its original size.
        // winit can draw from a before-wait observer; wake the loop so the
        // deferred resize does not have to wait for another input event.
        // SAFETY: The block captures nothing and CFRunLoopGetMain returns
        // the process's live main run loop.
        unsafe {
            NSRunLoop::mainRunLoop().performBlock(&RcBlock::new(apply_pending_panel_resize));
            CFRunLoopWakeUp(CFRunLoopGetMain());
        }
    }
    Ok(())
}

fn apply_pending_panel_resize() {
    let Some(pending) = PENDING_PANEL_RESIZE.take() else {
        return;
    };
    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let Some(window) =
        NSApplication::sharedApplication(mtm).windowWithWindowNumber(pending.window_number)
    else {
        return;
    };
    if !window.isVisible()
        || window.isMiniaturized()
        || window
            .styleMask()
            .intersects(NSWindowStyleMask::Titled | NSWindowStyleMask::FullScreen)
    {
        return;
    }
    // setContentSize keeps the bottom edge of a borderless window fixed. Move
    // and size it together so the top stays beneath the icon as the content grows.
    let current = window.frame();
    let frame = NSRect::new(pending.anchor.origin_for_size(pending.size), pending.size);
    if frame != current {
        window.setFrame_display(frame, false);
        window.invalidateShadow();
    }
}

pub(crate) fn is_fullscreen(handle: &impl HasWindowHandle) -> anyhow::Result<bool> {
    Ok(native_window(handle)?
        .styleMask()
        .contains(NSWindowStyleMask::FullScreen))
}

fn native_window(handle: &impl HasWindowHandle) -> anyhow::Result<Retained<NSWindow>> {
    let _mtm = MainThreadMarker::new()
        .ok_or_else(|| anyhow::anyhow!("macOS presentation requires the main thread"))?;
    let raw = handle
        .window_handle()
        .map_err(|error| anyhow::anyhow!("native window is unavailable: {error}"))?
        .as_raw();
    let RawWindowHandle::AppKit(raw) = raw else {
        anyhow::bail!("macOS presentation requires an AppKit window");
    };
    // SAFETY: HasWindowHandle keeps the AppKit view alive during this call;
    // AppKitWindowHandle documents ns_view as an NSView pointer. Every AppKit
    // operation remains on the main thread and winit retains its own delegate.
    let view = unsafe { raw.ns_view.cast::<NSView>().as_ref() };
    view.window().context("AppKit view has no window")
}

fn pin_metal_drawable(layer: &CALayer) {
    // While the next drawable is rendering, keep the previous frame at its
    // original pixel scale. The Metal surface can be the view layer itself
    // or the sublayer installed by raw-window-metal.
    if layer.downcast_ref::<CAMetalLayer>().is_some() {
        // The macOS Metal drawable is vertically flipped. Its lower-left
        // gravity keeps the first row of the UI against the title bar.
        // SAFETY: This immutable QuartzCore constant is available on all supported macOS versions.
        layer.setContentsGravity(unsafe { kCAGravityBottomLeft });
    } else {
        // SAFETY: Only inspect the app's layer tree, synchronously on AppKit's main thread.
        if let Some(children) = unsafe { layer.sublayers() } {
            for child in children.iter() {
                pin_metal_drawable(&child);
            }
        }
    }
}

fn apply_to_window(window: &NSWindow, presentation: Presentation) -> anyhow::Result<()> {
    if let Some(mut pending) = PENDING_PANEL_RESIZE.take() {
        if let Presentation::Panel(anchor) = presentation {
            pending.anchor = anchor;
            PENDING_PANEL_RESIZE.set(Some(pending));
        }
    }
    if window.styleMask().contains(NSWindowStyleMask::FullScreen) {
        // AppKit owns the asynchronous fullscreen transition. The UI requests
        // its exit before retrying Panel; rewriting the style mask here would
        // bypass that transition and desynchronize winit's window state.
        anyhow::ensure!(
            matches!(presentation, Presentation::Window),
            "menu bar presentation is waiting for fullscreen exit"
        );
        return Ok(());
    }
    let content_size = window.contentRectForFrameRect(window.frame()).size;
    if !content_size.width.is_finite()
        || !content_size.height.is_finite()
        || content_size.width <= 0.0
        || content_size.height <= 0.0
    {
        anyhow::bail!("AppKit window has an invalid content size");
    }
    let content_view = window
        .contentView()
        .context("AppKit window has no content view")?;
    content_view.setWantsLayer(true);
    let layer = content_view
        .layer()
        .context("AppKit content view has no layer")?;
    pin_metal_drawable(&layer);
    let panel = matches!(presentation, Presentation::Panel(_));
    // Preserve the renderer's layer and clip its complete contents, including
    // popups and the toolbar, to the panel's native shape.
    layer.setCornerRadius(if panel { PANEL_CORNER_RADIUS } else { 0.0 });
    layer.setMasksToBounds(panel);
    layer.setBorderWidth(0.0);
    window.setOpaque(!panel);
    let background = if panel {
        NSColor::clearColor()
    } else {
        NSColor::windowBackgroundColor()
    };
    window.setBackgroundColor(Some(&background));
    window.setHasShadow(true);
    match presentation {
        Presentation::Panel(anchor) => {
            anyhow::ensure!(anchor.is_valid(), "invalid menu bar panel geometry");
            window.setStyleMask(NSWindowStyleMask::Borderless);
            window.setContentSize(content_size);
            window.setMovable(false);
            window.setMovableByWindowBackground(false);
            window.setLevel(NSFloatingWindowLevel);
            // The UI orders the root out on focus loss. AppKit's automatic
            // hiding can order it back in on activation after an explicit toggle.
            window.setHidesOnDeactivate(false);
            window.setCollectionBehavior(
                NSWindowCollectionBehavior::MoveToActiveSpace
                    | NSWindowCollectionBehavior::FullScreenAuxiliary
                    | NSWindowCollectionBehavior::Transient,
            );
            window.setFrameOrigin(anchor.origin_for_size(window.frame().size));
        }
        Presentation::Window => {
            window.setStyleMask(
                NSWindowStyleMask::Titled
                    | NSWindowStyleMask::Closable
                    | NSWindowStyleMask::Miniaturizable
                    | NSWindowStyleMask::Resizable,
            );
            window.setContentSize(content_size);
            window.setMovable(true);
            window.setMovableByWindowBackground(false);
            window.setLevel(NSNormalWindowLevel);
            window.setHidesOnDeactivate(false);
            window.setCollectionBehavior(
                NSWindowCollectionBehavior::FullScreenNone
                    | NSWindowCollectionBehavior::FullScreenDisallowsTiling,
            );
            if let Some(button) = window.standardWindowButton(NSWindowButton::ZoomButton) {
                button.setEnabled(false);
            }
            if let Some(screen) = window.screen() {
                let frame = window.constrainFrameRect_toScreen(window.frame(), Some(&screen));
                window.setFrameOrigin(frame.origin);
            }
        }
    }
    window.invalidateShadow();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor() -> PanelAnchor {
        PanelAnchor {
            icon_x: 1_200.0,
            icon_y: 876.0,
            icon_width: 28.0,
            icon_height: 24.0,
            screen_x: 0.0,
            screen_y: 0.0,
            screen_width: 1_440.0,
            screen_height: 876.0,
        }
    }

    #[test]
    fn presentation_wire_round_trips_supported_modes() {
        for mode in [Presentation::Window, Presentation::Panel(anchor())] {
            let encoded = mode.encode();
            assert!(encoded.len() <= MAX_WIRE_BYTES);
            assert_eq!(Presentation::decode(&encoded), Some(mode));
        }
    }

    #[test]
    fn presentation_wire_rejects_invalid_or_unbounded_geometry() {
        for input in [
            "window\n",
            "window ",
            "panel:0,0,28,24,0,0,1440",
            "panel:0,0,28,24,0,0,1440,876,1",
            "panel:NaN,0,28,24,0,0,1440,876",
            "panel:inf,0,28,24,0,0,1440,876",
            "panel:100001,0,28,24,0,0,1440,876",
            "panel:0,0,-28,24,0,0,1440,876",
            "panel:0,0,28,0,0,0,1440,876",
            "panel:0,0,28,24,0,0,0,876",
            "panel:0,0,28,24,0,0,32769,876",
            "panel:0,0,28,24,0,0,1440,876\r",
            "panel:0,0,28,24,0,0,1440,876\nexit",
        ] {
            assert_eq!(Presentation::decode(input), None, "{input:?}");
        }
        assert!(Presentation::decode(&"1".repeat(MAX_WIRE_BYTES + 1)).is_none());
    }

    #[test]
    fn panel_placement_is_below_icon_and_clamped_at_right_edge() {
        let origin = anchor().origin_for_size(NSSize::new(640.0, 420.0));
        assert_eq!(origin, NSPoint::new(794.0, 450.0));
    }

    #[test]
    fn changing_panel_height_keeps_the_same_top_edge_under_the_icon() {
        let anchor = anchor();
        for height in [420.0, 240.0, 580.0] {
            let origin = anchor.origin_for_size(NSSize::new(640.0, height));
            assert_eq!(origin.x, 794.0);
            assert_eq!(origin.y + height, anchor.icon_y - PANEL_GAP);
        }
    }

    #[test]
    fn panel_placement_keeps_native_points_on_negative_origin_screen() {
        let mut anchor = anchor();
        anchor.icon_x = -1_400.0;
        anchor.icon_y = 676.0;
        anchor.screen_x = -1_440.0;
        anchor.screen_y = -200.0;
        let origin = anchor.origin_for_size(NSSize::new(640.0, 420.0));
        assert_eq!(origin, NSPoint::new(-1_434.0, 250.0));
        assert_eq!(
            Presentation::decode(&Presentation::Panel(anchor).encode()),
            Some(Presentation::Panel(anchor))
        );
    }

    #[test]
    fn panel_placement_handles_small_screen_without_invalid_clamp_range() {
        let mut anchor = anchor();
        anchor.screen_width = 400.0;
        anchor.screen_height = 300.0;
        assert_eq!(
            anchor.origin_for_size(NSSize::new(640.0, 420.0)),
            NSPoint::new(6.0, 6.0)
        );
    }
}

use anyhow::Context;
use eframe::egui;
use objc2::rc::Retained;
use objc2_app_kit::{
    NSFloatingWindowLevel, NSNormalWindowLevel, NSStatusItem, NSView, NSWindow,
    NSWindowCollectionBehavior, NSWindowStyleMask,
};
use objc2_foundation::{MainThreadMarker, NSPoint, NSSize};
use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};

const MAX_WIRE_BYTES: usize = 240;
const MAX_COORDINATE: f64 = 100_000.0;
const MAX_SCREEN_SIZE: f64 = 32_768.0;
const PANEL_GAP: f64 = 6.0;

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

fn apply_to_window(window: &NSWindow, presentation: Presentation) -> anyhow::Result<()> {
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
    match presentation {
        Presentation::Panel(anchor) => {
            anyhow::ensure!(anchor.is_valid(), "invalid menu bar panel geometry");
            window.setStyleMask(NSWindowStyleMask::Borderless);
            window.setContentSize(content_size);
            window.setMovable(false);
            window.setMovableByWindowBackground(false);
            window.setLevel(NSFloatingWindowLevel);
            window.setHidesOnDeactivate(true);
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
            window.setCollectionBehavior(NSWindowCollectionBehavior::Default);
            if let Some(screen) = window.screen() {
                let frame = window.constrainFrameRect_toScreen(window.frame(), Some(&screen));
                window.setFrameOrigin(frame.origin);
            }
        }
    }
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

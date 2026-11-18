use super::{APP_ICON, APP_NAME, AUTHOR, CONTACTS, HOMEPAGE, VERSION};
use std::cell::Cell;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{COLORREF, HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::SystemServices::{SS_CENTER, SS_ICON};
use windows::Win32::UI::HiDpi::{
    GetDpiForSystem, SetThreadDpiAwarenessContext, DPI_AWARENESS_CONTEXT,
    DPI_AWARENESS_CONTEXT_SYSTEM_AWARE,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyState, SetFocus, VK_ESCAPE, VK_SHIFT, VK_TAB,
};
use windows::Win32::UI::Shell::{
    DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass, ShellExecuteW,
};
use windows::Win32::UI::WindowsAndMessaging::*;

const AUTHOR_ID: usize = 100;
const CONTACT_ID_START: usize = 101;
const LINK_SUBCLASS_ID: usize = 0x5741_4142;
const WIDTH: i32 = 360;
const HEIGHT: i32 = 275;
const RELEASE_ROW_HEIGHT: i32 = 20;
const RELEASE_TO_AUTHOR_SPACING: i32 = 15;
const CONTACT_ICON_SIZE: i32 = 14;
const CONTACT_ITEM_SPACING: i32 = 18;

thread_local! {
    static ABOUT_WINDOW: Cell<HWND> = const { Cell::new(HWND(std::ptr::null_mut())) };
    static CLASS_REGISTERED: Cell<bool> = const { Cell::new(false) };
}

struct WindowResources {
    fonts: Vec<HFONT>,
    icons: Vec<HICON>,
}

impl Drop for WindowResources {
    fn drop(&mut self) {
        // The window owns these resources until WM_NCDESTROY, after its children are gone.
        unsafe {
            for font in &self.fonts {
                let _ = DeleteObject(HGDIOBJ(font.0));
            }
            for icon in &self.icons {
                let _ = DestroyIcon(*icon);
            }
        }
    }
}

struct DpiContext(DPI_AWARENESS_CONTEXT);

impl Drop for DpiContext {
    fn drop(&mut self) {
        // Restore winit's thread policy. The created window retains its own DPI context.
        unsafe { SetThreadDpiAwarenessContext(self.0) };
    }
}

pub(super) fn show() -> anyhow::Result<()> {
    // All callers run on the existing supervisor/UI thread; winit dispatches native messages.
    unsafe {
        let existing = ABOUT_WINDOW.get();
        if !existing.0.is_null() && IsWindow(Some(existing)).as_bool() {
            let _ = ShowWindow(existing, SW_RESTORE);
            let _ = SetForegroundWindow(existing);
            return Ok(());
        }

        let previous_dpi = SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_SYSTEM_AWARE);
        anyhow::ensure!(
            !previous_dpi.0.is_null(),
            "could not set About window DPI context"
        );
        let _dpi_context = DpiContext(previous_dpi);
        let dpi = GetDpiForSystem().max(96);
        let scale = |value: i32| (value * dpi as i32 + 48) / 96;
        let instance = HINSTANCE(GetModuleHandleW(None)?.0);
        if !CLASS_REGISTERED.get() {
            let class = WNDCLASSW {
                lpfnWndProc: Some(window_proc),
                hInstance: instance,
                hCursor: LoadCursorW(None, IDC_ARROW)?,
                hbrBackground: GetSysColorBrush(COLOR_WINDOW),
                lpszClassName: w!("WindowsAppAutoLoginAbout"),
                ..Default::default()
            };
            anyhow::ensure!(
                RegisterClassW(&class) != 0,
                "could not register About window"
            );
            CLASS_REGISTERED.set(true);
        }

        let mut resources = Box::new(WindowResources {
            fonts: Vec::new(),
            icons: Vec::new(),
        });
        for (height, weight, underline) in [(21, 600, false), (13, 400, false), (13, 400, true)] {
            let font = CreateFontW(
                -scale(height),
                0,
                0,
                0,
                weight,
                0,
                underline as u32,
                0,
                DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY,
                DEFAULT_PITCH.0 as u32,
                w!("Segoe UI"),
            );
            anyhow::ensure!(!font.0.is_null(), "could not create About font");
            resources.fonts.push(font);
        }
        let app_icon = image::load_from_memory(APP_ICON)?
            .resize_exact(
                scale(64) as u32,
                scale(64) as u32,
                image::imageops::FilterType::Lanczos3,
            )
            .to_rgba8();
        resources.icons.push(icon_from_rgba(
            app_icon.width(),
            app_icon.height(),
            app_icon.as_raw(),
        )?);
        let color = GetSysColor(COLOR_WINDOWTEXT);
        for contact in CONTACTS {
            let image = egui_extras::image::load_svg_bytes_with_size(
                contact.icon_svg,
                eframe::egui::load::SizeHint::Size {
                    width: scale(CONTACT_ICON_SIZE) as u32,
                    height: scale(CONTACT_ICON_SIZE) as u32,
                    maintain_aspect_ratio: false,
                },
                &Default::default(),
            )
            .map_err(anyhow::Error::msg)?;
            let rgba = image
                .pixels
                .iter()
                .flat_map(|pixel| {
                    [
                        color as u8,
                        (color >> 8) as u8,
                        (color >> 16) as u8,
                        pixel.a(),
                    ]
                })
                .collect::<Vec<_>>();
            resources.icons.push(icon_from_rgba(
                image.width() as u32,
                image.height() as u32,
                &rgba,
            )?);
        }

        let release_label = release_label();
        let release_height = if release_label.is_some() {
            RELEASE_ROW_HEIGHT + RELEASE_TO_AUTHOR_SPACING
        } else {
            0
        };
        let style = WS_CAPTION | WS_SYSMENU;
        let mut bounds = RECT {
            right: scale(WIDTH),
            bottom: scale(HEIGHT + release_height),
            ..Default::default()
        };
        AdjustWindowRectEx(&mut bounds, style, false, WS_EX_DLGMODALFRAME)?;
        let width = bounds.right - bounds.left;
        let height = bounds.bottom - bounds.top;
        let title = wide(&format!("About {APP_NAME}"));
        let hwnd = CreateWindowExW(
            WS_EX_DLGMODALFRAME,
            w!("WindowsAppAutoLoginAbout"),
            PCWSTR(title.as_ptr()),
            style,
            (GetSystemMetrics(SM_CXSCREEN) - width) / 2,
            (GetSystemMetrics(SM_CYSCREEN) - height) / 2,
            width,
            height,
            None,
            None,
            Some(instance),
            None,
        )?;
        if let Err(error) =
            create_content(hwnd, instance, &resources, release_label.as_deref(), scale)
        {
            // Destroy controls before dropping the fonts and icons they reference.
            let _ = DestroyWindow(hwnd);
            return Err(error);
        }
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(resources) as isize);
        ABOUT_WINDOW.set(hwnd);
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetForegroundWindow(hwnd);
        if let Ok(author) = GetDlgItem(Some(hwnd), AUTHOR_ID as i32) {
            let _ = SetFocus(Some(author));
        }
    }
    Ok(())
}

unsafe fn create_content(
    hwnd: HWND,
    instance: HINSTANCE,
    resources: &WindowResources,
    release_label: Option<&str>,
    scale: impl Fn(i32) -> i32,
) -> anyhow::Result<()> {
    let control = |class, text: &str, style, id, x, y, width, height, font: HFONT| {
        let text = wide(text);
        let child = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                class,
                PCWSTR(text.as_ptr()),
                WS_CHILD | WS_VISIBLE | style,
                scale(x),
                scale(y),
                scale(width),
                scale(height),
                Some(hwnd),
                Some(HMENU(id as *mut _)),
                Some(instance),
                None,
            )
        }?;
        unsafe {
            SendMessageW(
                child,
                WM_SETFONT,
                Some(WPARAM(font.0 as usize)),
                Some(LPARAM(1)),
            )
        };
        Ok::<HWND, windows::core::Error>(child)
    };
    let icon = control(
        w!("STATIC"),
        APP_NAME,
        WINDOW_STYLE(SS_ICON.0),
        0,
        148,
        20,
        64,
        64,
        resources.fonts[1],
    )?;
    unsafe {
        SendMessageW(
            icon,
            STM_SETICON,
            Some(WPARAM(resources.icons[0].0 as usize)),
            None,
        );
        SendMessageW(
            hwnd,
            WM_SETICON,
            Some(WPARAM(ICON_BIG as usize)),
            Some(LPARAM(resources.icons[0].0 as isize)),
        );
    }
    let centered = WINDOW_STYLE(SS_CENTER.0);
    control(
        w!("STATIC"),
        APP_NAME,
        centered,
        0,
        10,
        100,
        340,
        28,
        resources.fonts[0],
    )?;
    control(
        w!("STATIC"),
        &format!("Version {VERSION}"),
        centered,
        0,
        10,
        132,
        340,
        20,
        resources.fonts[1],
    )?;
    // Match the reference's six-point top spacer and fifteen-point release/author gap.
    let mut author_top = 158;
    if let Some(release_label) = release_label {
        control(
            w!("STATIC"),
            release_label,
            centered,
            0,
            10,
            author_top,
            340,
            RELEASE_ROW_HEIGHT,
            resources.fonts[1],
        )?;
        author_top += RELEASE_ROW_HEIGHT + RELEASE_TO_AUTHOR_SPACING;
    }
    control(
        w!("STATIC"),
        "Author",
        centered,
        0,
        10,
        author_top,
        340,
        20,
        resources.fonts[1],
    )?;
    let author = control(
        w!("BUTTON"),
        AUTHOR,
        WS_TABSTOP | WINDOW_STYLE(BS_FLAT as u32),
        AUTHOR_ID,
        60,
        author_top + 20,
        240,
        28,
        resources.fonts[2],
    )?;
    install_link_keyboard(author)?;
    let contact_item_width = CONTACT_ICON_SIZE + CONTACT_ITEM_SPACING;
    let contact_row_left = (WIDTH - CONTACTS.len() as i32 * contact_item_width) / 2;
    for (index, contact) in CONTACTS.iter().enumerate() {
        let button = control(
            w!("BUTTON"),
            contact.label,
            WS_TABSTOP | WINDOW_STYLE((BS_FLAT | BS_ICON) as u32),
            CONTACT_ID_START + index,
            contact_row_left + index as i32 * contact_item_width,
            author_top + 68,
            contact_item_width,
            28,
            resources.fonts[1],
        )?;
        unsafe {
            SendMessageW(
                button,
                BM_SETIMAGE,
                Some(WPARAM(IMAGE_ICON.0 as usize)),
                Some(LPARAM(resources.icons[index + 1].0 as isize)),
            )
        };
        install_link_keyboard(button)?;
    }
    Ok(())
}

fn release_label() -> Option<String> {
    let date =
        chrono::NaiveDate::parse_from_str(option_env!("WAAL_RELEASE_DATE")?, "%Y-%m-%d").ok()?;
    Some(format!("Released {}", date.format("%b %-d, %Y")))
}

fn install_link_keyboard(hwnd: HWND) -> anyhow::Result<()> {
    // No borrowed callback state; the native child owns the subclass until destruction.
    anyhow::ensure!(
        unsafe { SetWindowSubclass(hwnd, Some(link_proc), LINK_SUBCLASS_ID, 0) }.as_bool(),
        "could not configure About link keyboard navigation"
    );
    Ok(())
}

unsafe extern "system" fn link_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _: usize,
    _: usize,
) -> LRESULT {
    unsafe {
        if message == WM_KEYDOWN {
            if let Ok(parent) = GetParent(hwnd) {
                if wparam.0 == VK_ESCAPE.0 as usize {
                    let _ = PostMessageW(Some(parent), WM_CLOSE, WPARAM(0), LPARAM(0));
                    return LRESULT(0);
                }
                if wparam.0 == VK_TAB.0 as usize {
                    if let Ok(next) =
                        GetNextDlgTabItem(parent, Some(hwnd), GetKeyState(VK_SHIFT.0 as i32) < 0)
                    {
                        let _ = SetFocus(Some(next));
                    }
                    return LRESULT(0);
                }
            }
        }
        if message == WM_NCDESTROY {
            let _ = RemoveWindowSubclass(hwnd, Some(link_proc), LINK_SUBCLASS_ID);
        }
        DefSubclassProc(hwnd, message, wparam, lparam)
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe {
        match message {
            WM_COMMAND if (wparam.0 >> 16) == BN_CLICKED as usize && lparam.0 != 0 => {
                let id = wparam.0 & 0xffff;
                let url = if id == AUTHOR_ID {
                    Some(HOMEPAGE)
                } else {
                    id.checked_sub(CONTACT_ID_START)
                        .and_then(|index| CONTACTS.get(index))
                        .map(|link| link.url)
                };
                if let Some(url) = url {
                    let url = wide(url);
                    if ShellExecuteW(
                        Some(hwnd),
                        w!("open"),
                        PCWSTR(url.as_ptr()),
                        PCWSTR::null(),
                        PCWSTR::null(),
                        SW_SHOWNORMAL,
                    )
                    .0 as isize
                        <= 32
                    {
                        tracing::warn!("Could not open About contact link");
                    }
                }
                return LRESULT(0);
            }
            WM_CTLCOLORSTATIC => {
                let hdc = HDC(wparam.0 as *mut _);
                SetBkColor(hdc, COLORREF(GetSysColor(COLOR_WINDOW)));
                SetTextColor(hdc, COLORREF(GetSysColor(COLOR_WINDOWTEXT)));
                return LRESULT(GetSysColorBrush(COLOR_WINDOW).0 as isize);
            }
            WM_CLOSE => {
                let _ = DestroyWindow(hwnd);
                return LRESULT(0);
            }
            WM_NCDESTROY => {
                let pointer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut WindowResources;
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                if !pointer.is_null() {
                    drop(Box::from_raw(pointer));
                }
                if ABOUT_WINDOW.get() == hwnd {
                    ABOUT_WINDOW.set(HWND(std::ptr::null_mut()));
                }
            }
            _ => {}
        }
        DefWindowProcW(hwnd, message, wparam, lparam)
    }
}

fn icon_from_rgba(width: u32, height: u32, rgba: &[u8]) -> anyhow::Result<HICON> {
    anyhow::ensure!(
        width > 0
            && height > 0
            && width <= 1024
            && height <= 1024
            && rgba.len() == width as usize * height as usize * 4,
        "invalid About icon dimensions"
    );
    let bitmap_info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width as i32,
            biHeight: -(height as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    unsafe {
        let mut pixels = std::ptr::null_mut();
        let color = CreateDIBSection(None, &bitmap_info, DIB_RGB_COLORS, &mut pixels, None, 0)?;
        let mask_bytes = vec![0u8; (width as usize).div_ceil(16) * 2 * height as usize];
        let mask = CreateBitmap(
            width as i32,
            height as i32,
            1,
            1,
            Some(mask_bytes.as_ptr().cast()),
        );
        if mask.0.is_null() {
            let _ = DeleteObject(HGDIOBJ(color.0));
            anyhow::bail!("could not create About icon mask");
        }
        let target = std::slice::from_raw_parts_mut(pixels.cast::<u8>(), rgba.len());
        for (source, target) in rgba.chunks_exact(4).zip(target.chunks_exact_mut(4)) {
            let alpha = source[3] as u16;
            target.copy_from_slice(&[
                ((source[2] as u16 * alpha + 127) / 255) as u8,
                ((source[1] as u16 * alpha + 127) / 255) as u8,
                ((source[0] as u16 * alpha + 127) / 255) as u8,
                source[3],
            ]);
        }
        let result = CreateIconIndirect(&ICONINFO {
            fIcon: true.into(),
            hbmMask: mask,
            hbmColor: color,
            ..Default::default()
        });
        let _ = DeleteObject(HGDIOBJ(mask.0));
        let _ = DeleteObject(HGDIOBJ(color.0));
        Ok(result?)
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

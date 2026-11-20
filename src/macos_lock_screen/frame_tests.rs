//! Offline recognition through Vision and the same classifier used on captured windows.
use super::{visit_account_line, FrameRead, LockScreenObservation};
use core_foundation::base::CFRelease;
use objc2::{
    rc::{autoreleasepool, Retained},
    AnyThread,
};
use objc2_app_kit::NSImage;
use objc2_foundation::NSData;
use std::{ffi::c_void, ptr};

#[link(name = "ImageIO", kind = "framework")]
unsafe extern "C" {
    fn CGImageSourceCreateWithData(data: *const c_void, options: *const c_void) -> *const c_void;
    fn CGImageSourceCreateImageAtIndex(
        source: *const c_void,
        index: usize,
        options: *const c_void,
    ) -> *const c_void;
}

unsafe extern "C" {
    fn CGImageGetWidth(image: *const c_void) -> usize;
    fn CGImageGetHeight(image: *const c_void) -> usize;
    fn waal_recognize_lock_frame(
        image: *const c_void,
        visitor: extern "C" fn(*mut c_void, i32, *const u8, usize, f32, f64, f64, f64, f64),
        context: *mut c_void,
    ) -> bool;
}

fn observe_frame(
    width: usize,
    height: usize,
    editor_width: usize,
    placeholder: &str,
    instruction: Option<(&str, usize, usize, usize)>,
    tile_caption: Option<&str>,
) -> LockScreenObservation {
    observe_editor(
        width,
        height,
        editor_width,
        placeholder,
        instruction,
        tile_caption,
        "#3173d0",
    )
}

fn observe_editor(
    width: usize,
    height: usize,
    editor_width: usize,
    placeholder: &str,
    instruction: Option<(&str, usize, usize, usize)>,
    tile_caption: Option<&str>,
    underline: &str,
) -> LockScreenObservation {
    read_editor(
        (width, height),
        editor_width,
        placeholder,
        underline,
        GuestCaptions {
            instruction,
            tile_caption,
            qualified_user: None,
        },
        &[],
    )
}

#[derive(Default)]
struct GuestCaptions<'a> {
    instruction: Option<(&'a str, usize, usize, usize)>,
    tile_caption: Option<&'a str>,
    qualified_user: Option<&'a str>,
}

fn read_editor(
    (width, height): (usize, usize),
    editor_width: usize,
    placeholder: &str,
    underline: &str,
    captions: GuestCaptions<'_>,
    accounts: &[&str],
) -> LockScreenObservation {
    // Window and editor sizes vary independently, as they do when resizing the RDP client.
    let center = width as f64 / 2.;
    let (extra_text, instruction_x, instruction_y, instruction_size) = captions
        .instruction
        .unwrap_or(("", width / 2, height / 5, 28));
    let top = (height as f64 * 0.56).round();
    let scale = editor_width as f64 / 300.;
    let name_size = 36_f64.max(18. / scale);
    let password_size = 15_f64.max(9. / scale);
    let tile = captions.tile_caption.map_or_else(String::new, |caption| {
        let tile_x = 38. * scale;
        let tile_y = height as f64 - 85. * scale;
        format!(
            r#"<g transform="translate({tile_x} {tile_y}) scale({scale})">
                <text font-size="18">Morgan Lane</text>
                <text y="23" font-size="16">{caption}</text>
            </g>"#
        )
    });
    let (wallpaper, account) = if let Some(qualified_user) = captions.qualified_user {
        // Decorative captions stay on the periphery, with distinct edges and
        // tones crossing behind the centered account and password controls.
        let wallpaper = format!(
            r##"<g transform="scale({width} {height})">
                 <path fill="#5f6556" d="M0 .08 Q.33 .23 .56 .02 T1 .12 V1 H0Z"/>
                 <path fill="#414b4a" d="M0 .21 Q.2 .58 .43 .38 T1 .29 V1 H0Z"/>
                 <path fill="#565b52" d="M0 .69 Q.25 .32 .54 .48 T1 .34 V1 H0Z"/>
                 <path fill="#353d43" d="M0 .82 Q.23 .48 .44 .54 T1 .43 V1 H0Z"/>
                 <path fill="#49534d" d="M0 .9 Q.15 .63 .49 .70 T1 .57 V1 H0Z"/>
               </g>
               <g font-family="Helvetica" fill="#dedfda">
                 <g transform="translate({left} {upper})"><text font-size="28">Northern Range</text>
                   <text y="34" font-size="19">Along the ridge trail</text></g>
                 <g transform="translate({right} {lower})" text-anchor="end"><text font-size="26">Mountain Atlas</text>
                   <text y="32" font-size="18">Winter edition</text></g>
               </g>"##,
            left = width * 6 / 100,
            upper = height * 27 / 100,
            right = width * 94 / 100,
            lower = height * 55 / 100,
        );
        let account = format!(
            r#"<text y="-52" text-anchor="middle" font-size="32">Lee, Rowan</text>
               <text y="-25" text-anchor="middle" font-size="15" font-family="Menlo">{qualified_user}</text>"#
        );
        (wallpaper, account)
    } else {
        (
            String::new(),
            format!(
                r#"<text y="-40" text-anchor="middle" font-size="{name_size}">Example Person</text>"#
            ),
        )
    };
    let svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">
          <rect width="100%" height="100%" fill="#263452"/>
          {wallpaper}
          <g font-family="Helvetica" fill="#eeeeee">
            <text x="{instruction_x}" y="{instruction_y}" text-anchor="middle" font-size="{instruction_size}">{extra_text}</text>
            {tile}
            <g transform="translate({center} {top}) scale({scale})">
              {account}
              <rect x="-150" y="0" width="300" height="35" fill="#181d32"/>
              <rect x="-150" y="33" width="300" height="2" fill="{underline}"/>
              <text x="-138" y="23" font-size="{password_size}">{placeholder}</text>
              <path d="M 126 18 H 138 M 132 12 L 138 18 L 132 24" fill="none"
                    stroke="#e5e6e8" stroke-width="2"/>
            </g>
          </g>
        </svg>"##
    );

    // An NSImage's default screen representation may use the host display's scale.
    // Its TIFF representation rasterizes these SVG dimensions at one pixel per point.
    autoreleasepool(|_| {
        let vector = NSImage::initWithData(NSImage::alloc(), &NSData::with_bytes(svg.as_bytes()))
            .expect("synthetic SVG");
        let tiff = vector.TIFFRepresentation().expect("synthetic bitmap");
        let mut frame = FrameRead::new(accounts);
        // NSData is toll-free bridged to CFData. ImageIO retains it for the source's lifetime.
        let success = unsafe {
            let source = CGImageSourceCreateWithData(Retained::as_ptr(&tiff).cast(), ptr::null());
            assert!(!source.is_null());
            let image = CGImageSourceCreateImageAtIndex(source, 0, ptr::null());
            CFRelease(source);
            assert!(!image.is_null());
            assert_eq!(
                (CGImageGetWidth(image), CGImageGetHeight(image)),
                (width, height)
            );
            let success = waal_recognize_lock_frame(
                image,
                visit_account_line,
                ptr::from_mut(&mut frame).cast(),
            );
            CFRelease(image);
            success
        };
        assert!(
            success,
            "could not process the synthetic {width}×{height} frame"
        );
        frame.observation(success)
    })
}

#[test]
fn recognizes_a_qualified_account_caption_on_wallpaper_at_different_guest_scales() {
    let accounts = ["robin.lee@example.test", "rowan.lee@example.test"];
    for (width, height, editor, underline) in [
        (1366, 768, 300, "#3173d0"),
        (2560, 1440, 600, "#767676"),
        (2880, 1800, 510, "#767676"),
    ] {
        assert_eq!(
            read_editor(
                (width, height),
                editor,
                "Password",
                underline,
                GuestCaptions {
                    qualified_user: Some(r"LAB\rowan.lee@example.test"),
                    ..Default::default()
                },
                &accounts,
            ),
            LockScreenObservation::AccountPassword(1),
            "{width}×{height}, editor {editor}px"
        );
    }
}

#[test]
fn rejects_a_wrong_qualified_user_and_competing_sign_in_controls() {
    let expected = ["rowan.lee@example.test"];
    for (qualified_user, placeholder, tile, instruction) in [
        (r"LAB\rowan.lee@example.net", "Password", None, None),
        (
            r"LAB\rowan.lee@example.test",
            "Password",
            Some("Other user"),
            None,
        ),
        (
            r"LAB\rowan.lee@example.test",
            "Password",
            None,
            Some(("Sign-in options", 683, 518, 18)),
        ),
        (r"LAB\rowan.lee@example.test", "PIN", None, None),
    ] {
        assert_eq!(
            read_editor(
                (1366, 768),
                300,
                placeholder,
                "#3173d0",
                GuestCaptions {
                    qualified_user: Some(qualified_user),
                    tile_caption: tile,
                    instruction
                },
                &expected,
            ),
            LockScreenObservation::Other,
            "{qualified_user:?}, {placeholder:?}, {tile:?}, {instruction:?}"
        );
    }
}

#[test]
fn reads_the_centered_editor_as_the_window_and_guest_scale_change() {
    // The overview alone can misread the 1366-wide fixture as "Pa8sword" and
    // omit the placeholder altogether on the 4K fixture.
    for (width, height, field) in [
        (704, 420, 220),
        (1366, 768, 300),
        (1920, 1080, 450),
        (3840, 2160, 330),
    ] {
        assert_eq!(
            observe_frame(width, height, field, "Password", None, None),
            LockScreenObservation::Password,
            "window {width}×{height}, editor {field}px"
        );
    }
}

#[test]
fn rejects_a_pin_a_lookalike_and_unrelated_guest_instructions() {
    for (placeholder, extra) in [
        ("PIN", ""),
        ("Kassword", ""),
        ("Kennwort", ""),
        ("Password", "Please enter a verification code"),
        ("Password", "Network maintenance"),
    ] {
        assert_eq!(
            observe_frame(
                1920,
                1080,
                340,
                placeholder,
                Some((extra, 960, 216, 28)),
                None
            ),
            LockScreenObservation::Other,
            "placeholder {placeholder:?}, extra text {extra:?}"
        );
    }
}

#[test]
fn checks_account_tiles_at_small_and_five_k_window_sizes() {
    use LockScreenObservation::{Other, Password};
    let mut mismatches = Vec::new();
    // Both scales are guest settings. Tile captions and controls keep their
    // pixel sizes on the guest as the host window changes around them.
    for (width, height, field) in [(800, 600, 369), (5120, 2880, 295)] {
        for (caption, expected) in [
            ("Work account", Password),
            ("PIN", Other),
            ("Other user", Other),
        ] {
            let result = observe_frame(width, height, field, "Password", None, Some(caption));
            if result != expected {
                mismatches.push((width, height, caption, result, expected));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "Account tile mismatches: {mismatches:?}"
    );
}

#[test]
fn recognizes_guest_instructions_crossing_an_overview_tile_boundary() {
    use LockScreenObservation::{Other, Password};
    let (width, height, editor) = (5120, 1440, 295);
    // The account stays in the middle tile. Put the unrelated instructions
    // halfway across the boundary between the first and second tiles.
    assert_eq!(
        observe_frame(width, height, editor, "Password", None, None),
        Password
    );
    assert_eq!(
        observe_frame(
            width,
            height,
            editor,
            "Password",
            Some(("Network maintenance", width / 3, height / 5, 28)),
            None
        ),
        Other
    );
}

#[test]
fn compressed_other_user_captions_veto_a_small_password_editor() {
    use LockScreenObservation::{Other, Password};
    for (tile, below, expected) in [
        ("Work account", None, Password),
        ("Other user", None, Other),
        ("Work account", Some(("Other user", 550, 388, 8)), Other),
    ] {
        assert_eq!(
            observe_frame(1100, 619, 130, "Password", below, Some(tile)),
            expected,
            "tile {tile:?}, below editor {below:?}"
        );
    }
}

#[test]
fn unfocused_editor_requires_exact_password_and_rejects_competing_labels() {
    use LockScreenObservation::{Other, Password};
    for (w, h, ew, underline) in [
        (1366, 768, 300, "#767676"),
        (3800, 1236, 580, "none"),
        (850, 1011, 300, "#767676"),
        (5120, 2880, 295, "none"),
        (1100, 619, 130, "none"),
    ] {
        assert_eq!(
            observe_editor(w, h, ew, "Password", None, Some("Work account"), underline),
            Password,
            "unfocused {w}x{h} editor {ew}"
        );
    }
    for (placeholder, tile, extra) in [
        ("Kassword", "Work account", None),
        ("PIN", "Work account", None),
        ("Password", "Other user", None),
        ("Password", "Work account", Some(("Password", 280, 90, 22))),
        (
            "Password",
            "Work account",
            Some(("Sign-in options", 540, 440, 18)),
        ),
    ] {
        assert_eq!(
            observe_editor(1366, 768, 300, placeholder, extra, Some(tile), "none"),
            Other,
            "unfocused {placeholder:?}, tile {tile:?}, extra {extra:?}"
        );
    }
    // The native reading band contains another sign-in method only a few
    // guest pixels high. A readable Password on the same frame must lose.
    for (x, y) in [(2355, 1636), (2480, 1602)] {
        assert_eq!(
            observe_editor(
                5120,
                2880,
                295,
                "Password",
                Some(("PIN", x, y, 14)),
                None,
                "none"
            ),
            Other
        );
    }
}

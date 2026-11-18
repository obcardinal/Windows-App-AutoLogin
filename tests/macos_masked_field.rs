//! In-memory fixtures for locating and classifying Windows' focused editor.
#![cfg(target_os = "macos")]

use std::ffi::c_void;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Box2d {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FieldKind {
    None,
    PlaceholderCandidate,
    Masked,
    Ambiguous,
    Unavailable,
}

#[link(name = "waal_lock_screen_capture", kind = "static")]
#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {
    fn waal_password_field(image: *const c_void, result: *mut Box2d) -> FieldKind;
    fn waal_neutral_password_field(image: *const c_void, verified_password: Box2d) -> Box2d;
}

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGColorSpaceCreateDeviceRGB() -> *const c_void;
    fn CGColorSpaceRelease(space: *const c_void);
    fn CGBitmapContextCreate(
        data: *mut c_void,
        width: usize,
        height: usize,
        bits: usize,
        stride: usize,
        space: *const c_void,
        info: u32,
    ) -> *mut c_void;
    fn CGBitmapContextCreateImage(bitmap: *mut c_void) -> *const c_void;
    fn CGContextRelease(bitmap: *mut c_void);
    fn CGImageRelease(image: *const c_void);
}

struct Fixture {
    width: usize,
    height: usize,
    data: Vec<[u8; 4]>,
}

impl Fixture {
    fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            data: vec![[27, 38, 89, 255]; width * height],
        }
    }

    // Coordinates use the same normalized Windows control geometry at each DPI.
    fn editor(
        &mut self,
        top: usize,
        size: usize,
        dots: usize,
        eye: bool,
        arrow: bool,
        focus: bool,
    ) {
        let left = (self.width - size) / 2;
        let height = (size as f64 * 0.118).round() as usize;
        for y in 0..height {
            for x in 0..size {
                let xx = x as f64 / size as f64;
                let yy = y as f64 / height as f64;
                let eye_x = (xx - 0.831) * size as f64 / height as f64;
                let dy = yy - 0.52;
                let eye_r = (eye_x / 0.18).powi(2) + (dy / 0.118).powi(2);
                let eye_ink = eye && ((0.55..=1.).contains(&eye_r) || eye_x.hypot(dy) < 0.047);
                let arrow_x = (xx - 0.940) * size as f64 / height as f64;
                let arrow_ink = arrow
                    && ((arrow_x.abs() < 0.171 && dy.abs() < 0.027)
                        || (arrow_x > -0.015
                            && arrow_x < 0.17
                            && (dy.abs() - (0.165 - arrow_x)).abs() < 0.029));
                let dot_ink = (0..dots).any(|i| {
                    let delta = (xx - (0.043 + i as f64 * 0.0294)) * size as f64 / height as f64;
                    delta.hypot(dy) < 0.092
                });
                let color = if yy >= 0.942 && focus {
                    [49, 115, 208, 255]
                } else if eye_ink || arrow_ink || dot_ink {
                    [229, 230, 232, 255]
                } else {
                    [24, 29, 50, 255]
                };
                self.data[(top + y) * self.width + left + x] = color;
            }
        }
    }

    fn with_image<T>(&mut self, inspect: impl FnOnce(*const c_void) -> T) -> T {
        unsafe {
            let space = CGColorSpaceCreateDeviceRGB();
            assert!(!space.is_null());
            let bitmap = CGBitmapContextCreate(
                self.data.as_mut_ptr().cast(),
                self.width,
                self.height,
                8,
                self.width * 4,
                space,
                0x4005,
            ); // RGBX, big-endian
            CGColorSpaceRelease(space);
            assert!(!bitmap.is_null());
            let image = CGBitmapContextCreateImage(bitmap);
            assert!(!image.is_null());
            let result = inspect(image);
            CGImageRelease(image);
            CGContextRelease(bitmap);
            result
        }
    }

    fn detect(&mut self) -> (FieldKind, Box2d) {
        self.with_image(|image| {
            let mut result = Box2d::default();
            let kind = unsafe { waal_password_field(image, &mut result) };
            (kind, result)
        })
    }
}

#[test]
fn detects_a_focused_password_with_one_or_several_mask_dots_at_desktop_scale() {
    for (width, height, field_width) in [(1920, 1080, 298), (1366, 768, 360), (704, 420, 566)] {
        for dots in [1, 5, 12] {
            let mut frame = Fixture::new(width, height);
            let top = height / 2;
            frame.editor(top, field_width, dots, true, true, true);
            let (kind, field) = frame.detect();
            assert_eq!(kind, FieldKind::Masked);
            assert!((field.x + field.w / 2. - 0.5).abs() < 0.02);
            assert!((field.w - field_width as f64 / width as f64).abs() < 0.02);
            assert!((field.y + field.h - (1. - top as f64 / height as f64)).abs() < 0.02);
        }
    }
}

#[test]
fn locates_empty_editor_for_ocr_without_confirming_a_password() {
    for (width, height, field_width) in [(1920, 1080, 298), (1366, 768, 360), (704, 420, 566)] {
        let mut frame = Fixture::new(width, height);
        let top = height / 2;
        frame.editor(top, field_width, 0, false, true, true);
        let (kind, field) = frame.detect();
        assert_eq!(kind, FieldKind::PlaceholderCandidate);
        assert!((field.x + field.w / 2. - 0.5).abs() < 0.02);
        assert!((field.w - field_width as f64 / width as f64).abs() < 0.02);
        assert!((field.y + field.h - (1. - top as f64 / height as f64)).abs() < 0.02);
    }
}

#[test]
fn only_reports_masked_when_both_dots_and_eye_are_present() {
    for (dots, eye) in [(0, true), (5, false)] {
        let mut frame = Fixture::new(1024, 768);
        frame.editor(370, 400, dots, eye, true, true);
        assert_eq!(frame.detect().0, FieldKind::PlaceholderCandidate);
    }
}

#[test]
fn rejects_editors_without_a_submit_arrow_or_focus_underline() {
    for (arrow, focus) in [(false, true), (true, false)] {
        let mut frame = Fixture::new(1024, 768);
        frame.editor(370, 400, 5, true, arrow, focus);
        assert_eq!(frame.detect().0, FieldKind::None);
    }
}

#[test]
fn rejects_multiple_editors_including_mixed_masked_and_empty() {
    for (first, second) in [(0, 0), (1, 0), (0, 5), (1, 5)] {
        let mut frame = Fixture::new(1024, 768);
        frame.editor(350, 400, first, first > 0, true, true);
        frame.editor(450, 400, second, second > 0, true, true);
        assert_eq!(frame.detect().0, FieldKind::Ambiguous);
    }
}

#[test]
fn hollow_text_glyph_is_not_a_mask_dot() {
    let mut frame = Fixture::new(1024, 768);
    frame.editor(370, 400, 1, true, true, true);
    let x = (frame.width - 400) / 2 + 17;
    let y = 370 + 24;
    for row in y - 2..=y + 2 {
        for col in x - 2..=x + 2 {
            frame.data[row * frame.width + col] = [24, 29, 50, 255];
        }
    }
    assert_eq!(frame.detect().0, FieldKind::PlaceholderCandidate);
}

#[test]
fn blue_wallpaper_touching_the_underline_does_not_enlarge_the_control() {
    let mut frame = Fixture::new(1024, 768);
    frame.editor(370, 400, 5, true, true, true);
    let left = (frame.width - 400) / 2;
    for row in 345..440 {
        for col in left - 150..left {
            frame.data[row * frame.width + col] = [49, 115, 208, 255];
        }
    }
    let (kind, field) = frame.detect();
    assert_eq!(kind, FieldKind::Masked);
    assert!((field.w - 400. / 1024.).abs() < 0.02);
}

#[test]
fn detects_fixed_size_native_controls_on_a_wide_display() {
    for dots in [0, 5] {
        let mut frame = Fixture::new(5120, 1440);
        frame.editor(750, 298, dots, dots > 0, true, true);
        let (kind, field) = frame.detect();
        let expected = if dots > 0 {
            FieldKind::Masked
        } else {
            FieldKind::PlaceholderCandidate
        };
        assert_eq!(kind, expected);
        assert!((field.w * 5120. - 298.).abs() <= 1.);
        assert!(((1. - field.y - field.h) * 1440. - 750.).abs() <= 2.);
    }
}

#[test]
fn rejects_multiple_editors_on_different_scan_strips() {
    let mut frame = Fixture::new(5120, 1440);
    frame.editor(850, 298, 0, false, true, true);
    // The second editor straddles the boundary between two strips.
    frame.editor(1155, 298, 5, true, true, true);
    assert_eq!(frame.detect().0, FieldKind::Ambiguous);
}

#[test]
fn identifies_a_small_antialiased_arrow_only_with_its_shaft() {
    // A horizontal stroke may occupy one row or share its coverage across two.
    for (shaft, split) in [(true, false), (true, true), (false, false)] {
        let mut frame = Fixture::new(1366, 768);
        let (size, top) = (182, 380);
        let left = (frame.width - size) / 2;
        frame.editor(top, size, 0, false, true, true);
        // At this scale the partially covered shaft pixels can be darker
        // than the fully covered pixels at the junction of the arrow head.
        for y in top..top + 20 {
            for x in left + size * 9 / 10..left + size * 94 / 100 {
                let pixel = &mut frame.data[y * frame.width + x];
                if pixel[0] == 229 {
                    let shared_pixel = split && x + 1 == left + size * 94 / 100;
                    *pixel = if shared_pixel {
                        [65, 68, 70, 255]
                    } else if shaft {
                        [100, 103, 105, 255]
                    } else {
                        [24, 29, 50, 255]
                    };
                    if shared_pixel {
                        frame.data[(y - 1) * frame.width + x] = [65, 68, 70, 255];
                    }
                }
            }
        }
        let expected = if shaft {
            FieldKind::PlaceholderCandidate
        } else {
            FieldKind::None
        };
        assert_eq!(frame.detect().0, expected, "shaft={shaft} split={split}");
    }
}

#[test]
fn an_unavailable_frame_is_distinct_from_a_completed_scan_with_no_field() {
    let mut field = Box2d::default();
    let kind = unsafe { waal_password_field(std::ptr::null(), &mut field) };
    assert_eq!(kind, FieldKind::Unavailable);
    assert_eq!(Fixture::new(500, 350).detect().0, FieldKind::None);
}

#[test]
fn measures_shifted_unfocused_editor_only_when_all_four_sides_enclose_the_word() {
    let (w, h) = (1280, 960);
    let (left, right, top, bottom) = (430, 970, 564, 636);
    let password = Box2d {
        x: 448. / w as f64,
        y: 1. - 612. / h as f64,
        w: 116. / w as f64,
        h: 24. / h as f64,
    };
    for (missing, softened) in [
        (None, false),
        (None, true),
        (Some(0), false),
        (Some(1), false),
        (Some(2), false),
        (Some(3), false),
    ] {
        let mut frame = Fixture::new(w, h);
        for y in top..bottom {
            for x in left..right {
                if (x == left && missing != Some(0))
                    || (x + 1 == right && missing != Some(1) && !softened)
                    || (y == top && missing != Some(2))
                    || (y + 1 == bottom && missing != Some(3))
                {
                    frame.data[y * w + x] = [90, 93, 98, 255];
                }
            }
        }
        if softened {
            // The upper and lower lines terminate at the same side. Its color
            // transition is too gradual to identify from two adjacent pixels.
            for y in top + 3..bottom - 3 {
                for x in right - 12..w {
                    let delta = (x + 12 - right).min(24) as u8 * 2;
                    frame.data[y * w + x] = [27 + delta, 38 + delta, 89 + delta, 255];
                }
            }
        }
        let rect =
            frame.with_image(|image| unsafe { waal_neutral_password_field(image, password) });
        if missing.is_some() {
            assert!(
                rect.x.is_infinite(),
                "partial outline admitted: {missing:?}"
            );
        } else {
            assert!((rect.x * w as f64 - left as f64).abs() < 3.);
            assert!((rect.w * w as f64 - (right - left) as f64).abs() <= 5.);
        }
    }
}

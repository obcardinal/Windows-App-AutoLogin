//! In-memory fixtures for Windows' focused, nonempty password control.
#![cfg(target_os = "macos")]

use std::ffi::c_void;

#[repr(C)]
#[derive(Default)]
struct Box2d {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
}

#[link(name = "waal_lock_screen_capture", kind = "static")]
unsafe extern "C" {
    fn waal_masked_field(image: *const c_void, result: *mut Box2d) -> bool;
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

    fn detect(&mut self) -> Option<Box2d> {
        let mut result = Box2d::default();
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
            let matched = waal_masked_field(image, &mut result);
            CGImageRelease(image);
            CGContextRelease(bitmap);
            matched.then_some(result)
        }
    }
}

#[test]
fn detects_a_focused_password_with_one_or_several_mask_dots_at_desktop_scale() {
    for (width, height, field_width) in [(1920, 1080, 298), (1366, 768, 360), (704, 420, 566)] {
        for dots in [1, 5, 12] {
            let mut frame = Fixture::new(width, height);
            let top = height / 2;
            frame.editor(top, field_width, dots, true, true, true);
            let field = frame.detect().expect("focused masked field");
            assert!((field.x + field.w / 2. - 0.5).abs() < 0.02);
            assert!((field.w - field_width as f64 / width as f64).abs() < 0.02);
            assert!((field.y + field.h - (1. - top as f64 / height as f64)).abs() < 0.02);
        }
    }
}

#[test]
fn ignores_empty_incomplete_and_ambiguous_controls() {
    for (dots, eye, arrow, focus) in [
        (0, true, true, true),
        (5, false, true, true),
        (5, true, false, true),
        (5, true, true, false),
    ] {
        let mut frame = Fixture::new(1024, 768);
        frame.editor(370, 400, dots, eye, arrow, focus);
        assert!(frame.detect().is_none());
    }
    let mut frame = Fixture::new(1024, 768);
    frame.editor(350, 400, 1, true, true, true);
    frame.editor(450, 400, 5, true, true, true);
    assert!(frame.detect().is_none());
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
    assert!(frame.detect().is_none());
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
    let field = frame
        .detect()
        .expect("field edge must stop at the wallpaper");
    assert!((field.w - 400. / 1024.).abs() < 0.02);
}

//! Native-pixel letterboxing of a verified Windows App remote display view.
#![cfg(target_os = "macos")]

use core_foundation::base::CFRelease;
use objc2_foundation::NSRect;
use std::ffi::c_void;

#[link(name = "waal_lock_screen_capture", kind = "static")]
unsafe extern "C" {
    fn waal_guest_content_rect(image: *const c_void) -> NSRect;
}

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGColorSpaceCreateDeviceRGB() -> *const c_void;
    fn CGBitmapContextCreate(
        data: *mut c_void,
        width: usize,
        height: usize,
        bits: usize,
        stride: usize,
        space: *const c_void,
        info: u32,
    ) -> *const c_void;
    fn CGBitmapContextCreateImage(ctx: *const c_void) -> *const c_void;
}

const BLACK: [u8; 4] = [0, 0, 0, 255];
const WALLPAPER: [u8; 4] = [25, 42, 72, 255];

struct Fixture {
    width: usize,
    height: usize,
    pixels: Vec<[u8; 4]>,
}

impl Fixture {
    fn new(width: usize, height: usize, guest: [usize; 4]) -> Self {
        let mut f = Self {
            width,
            height,
            pixels: vec![BLACK; width * height],
        };
        f.fill(guest, WALLPAPER);
        f
    }

    fn fill(&mut self, [x, y, w, h]: [usize; 4], color: [u8; 4]) {
        for row in y..y + h {
            self.pixels[row * self.width + x..row * self.width + x + w].fill(color);
        }
    }

    fn viewport(&mut self) -> Option<[usize; 4]> {
        unsafe {
            let space = CGColorSpaceCreateDeviceRGB();
            assert!(!space.is_null());
            let ctx = CGBitmapContextCreate(
                self.pixels.as_mut_ptr().cast(),
                self.width,
                self.height,
                8,
                self.width * 4,
                space,
                0x4001,
            ); // Big-endian premultiplied RGBA.
            CFRelease(space);
            assert!(!ctx.is_null());
            let image = CGBitmapContextCreateImage(ctx);
            assert!(!image.is_null());
            let r = waal_guest_content_rect(image);
            CFRelease(image);
            CFRelease(ctx);
            if !r.origin.x.is_finite() || !r.origin.y.is_finite() {
                return None;
            }
            Some([
                r.origin.x as usize,
                r.origin.y as usize,
                r.size.width as usize,
                r.size.height as usize,
            ])
        }
    }
}

#[test]
fn recovers_centered_guest_on_both_axes_to_the_pixel() {
    for (w, h, guest) in [
        (2560, 1080, [320, 0, 1920, 1080]),
        (1280, 800, [0, 40, 1280, 720]),
        (2561, 1401, [560, 250, 1440, 900]),
        (1280, 720, [0, 0, 1280, 720]),
    ] {
        assert_eq!(Fixture::new(w, h, guest).viewport(), Some(guest));
    }
}

#[test]
fn rejects_overlays_on_padding_and_preserves_marks_inside_the_guest() {
    for mark in [[9, 677], [890, 450], [522, 7], [499, 699]] {
        let mut f = Fixture::new(900, 700, [100, 50, 700, 600]);
        f.fill([mark[0], mark[1], 1, 1], [32, 32, 32, 255]);
        assert_eq!(f.viewport(), None);
    }
    let mut f = Fixture::new(900, 700, [100, 50, 700, 600]);
    f.fill([140, 625, 75, 15], [210, 210, 210, 255]); // Guest's lower-left "Other user".
    assert_eq!(f.viewport(), Some([100, 50, 700, 600]));
}

#[test]
fn preserves_dark_backgrounds_and_rejects_an_overlay_on_a_known_bar() {
    let full = [0, 0, 900, 700];
    assert_eq!(
        Fixture::new(900, 700, [20, 0, 600, 700]).viewport(),
        Some(full)
    );
    let mut f = Fixture::new(900, 700, [100, 0, 700, 700]);
    f.fill([0, 0, 1, 1], [0, 0, 0, 0]);
    assert_eq!(f.viewport(), None);
    for fill in [BLACK, [4, 4, 4, 255]] {
        f.fill(full, fill);
        assert_eq!(f.viewport(), Some(full));
        // Sparse bright labels do not define a rectangular display boundary.
        f.fill([100, 345, 700, 10], WALLPAPER);
        f.fill([445, 50, 10, 600], WALLPAPER);
        assert_eq!(f.viewport(), Some(full));
    }
}

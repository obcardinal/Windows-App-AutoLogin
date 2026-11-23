//! Real filesystem events in a disposable Vision cache. No screen or input is used.
#![cfg(target_os = "macos")]

use std::ffi::{c_char, c_void, CString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[link(name = "waal_lock_screen_capture", kind = "static")]
#[link(name = "Foundation", kind = "framework")]
#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn waal_model_cache_watch_directory(path: *const c_char) -> *mut c_void;
    fn waal_model_cache_watch_take_loss(watch: *mut c_void) -> bool;
    fn waal_model_cache_watch_stop(watch: *mut c_void);
}

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("waal-models-{:x}", rand::random::<u128>()));
        fs::create_dir(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Watch(*mut c_void);

impl Watch {
    fn start(path: &Path) -> Self {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { waal_model_cache_watch_directory(path.as_ptr()) };
        assert!(!handle.is_null());
        Self(handle)
    }

    fn take_loss(&self) -> bool {
        unsafe { waal_model_cache_watch_take_loss(self.0) }
    }

    fn expect_loss(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.take_loss() {
            assert!(Instant::now() < deadline, "cache removal was not observed");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!self.take_loss(), "the same signal was consumed twice");
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        unsafe { waal_model_cache_watch_stop(self.0) }
    }
}

#[test]
fn loss_is_reported_at_startup_and_on_file_or_directory_eviction() {
    let tmp = Fixture::new();
    let root = tmp.0.join("app-cache/e5-cache/build");
    let empty = Watch::start(&root);
    assert!(empty.take_loss());
    assert!(!empty.take_loss());
    let cold_start = Watch::start(&root);

    let architecture = root.join("model.bundle/chip.bundle");
    let hashes = architecture.join("main/main_ane");
    fs::create_dir_all(&hashes).unwrap();
    fs::write(architecture.join("chip.e5"), b"compiled").unwrap();
    assert!(
        cold_start.take_loss(),
        "a partial write hid the initial empty cache"
    );
    drop(cold_start);
    let partial = Watch::start(&root);
    assert!(partial.take_loss(), "the empty hash directory was missed");
    drop(partial);
    fs::write(hashes.join("model.anehash"), b"hash").unwrap();
    let healthy = Watch::start(&root);
    assert!(!healthy.take_loss());

    // Give the watcher that started before its tree existed a chance to
    // consume the creation batch and verify that additions are silent.
    std::thread::sleep(Duration::from_secs(2));
    assert!(!empty.take_loss());
    fs::remove_file(hashes.join("model.anehash")).unwrap();
    healthy.expect_loss();
    empty.expect_loss();
    fs::write(hashes.join("model.anehash"), b"regenerated").unwrap();
    fs::rename(&root, tmp.0.join("evicted-build")).unwrap();
    healthy.expect_loss();
    drop(empty);
    fs::create_dir_all(&architecture).unwrap();
    fs::write(architecture.join("chip.e5"), b"new model").unwrap();
    std::thread::sleep(Duration::from_secs(2));
    assert!(!healthy.take_loss());
    fs::remove_file(architecture.join("chip.e5")).unwrap();
    healthy.expect_loss();
}

#[test]
fn split_evictions_only_trigger_another_repair_if_files_are_still_missing() {
    let tmp = Fixture::new();
    let architecture = tmp.0.join("model.bundle/chip.bundle");
    let hashes = architecture.join("main/main_ane");
    fs::create_dir_all(&hashes).unwrap();
    let model = architecture.join("chip.e5");
    let hash = hashes.join("model.anehash");
    fs::write(&model, b"compiled").unwrap();
    fs::write(&hash, b"hash").unwrap();
    let watch = Watch::start(&tmp.0);
    assert!(!watch.take_loss());

    fs::remove_file(&model).unwrap();
    watch.expect_loss();
    fs::remove_file(&hash).unwrap();
    // A later batch arrives while the first repair is still working.
    std::thread::sleep(Duration::from_secs(2));
    fs::write(&model, b"compiled").unwrap();
    fs::write(&hash, b"hash").unwrap();
    assert!(
        !watch.take_loss(),
        "already repaired files triggered another repair"
    );

    std::thread::sleep(Duration::from_secs(2));
    fs::remove_file(&model).unwrap();
    watch.expect_loss();
    fs::remove_file(&hash).unwrap();
    fs::write(&model, b"compiled").unwrap();
    watch.expect_loss();
}

#[test]
fn removing_vision_compiler_staging_bundles_is_not_a_cache_loss() {
    let tmp = Fixture::new();
    let permanent = tmp.0.join("model.bundle/chip.bundle");
    fs::create_dir_all(&permanent).unwrap();
    fs::write(permanent.join("chip.e5"), b"compiled").unwrap();

    let staging = tmp.0.join("model.tmp.2998_4425912992.bundle");
    let chip = staging.join("chip.bundle");
    let hashes = chip.join("main_1024/main_ane");
    fs::create_dir_all(&hashes).unwrap();
    let watch = Watch::start(&tmp.0);
    assert!(
        !watch.take_loss(),
        "the incomplete staging tree triggered startup recovery"
    );
    fs::write(chip.join("chip.e5"), b"compiled").unwrap();
    fs::write(hashes.join("model.anehash"), b"hash").unwrap();
    std::thread::sleep(Duration::from_secs(2));
    fs::remove_dir_all(staging).unwrap();
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        !watch.take_loss(),
        "the compiler's discarded bundle triggered recovery"
    );

    fs::remove_file(permanent.join("chip.e5")).unwrap();
    watch.expect_loss();
}

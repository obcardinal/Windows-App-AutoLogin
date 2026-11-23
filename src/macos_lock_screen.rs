//! Recognizes the layout of the English Windows password screen. This is
//! visual evidence only. It does not attest the guest desktop or its identity.

use std::{
    ffi::c_void,
    slice, str,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockScreenObservation {
    Password,
    AccountPassword(usize),
    Other,
    Unavailable,
    RecognitionFailed,
}

#[link(name = "waal_lock_screen_capture", kind = "static")]
#[link(name = "Vision", kind = "framework")]
unsafe extern "C" {
    fn waal_lock_capture_supported() -> bool;
    fn waal_lock_capture_allowed() -> bool;
    fn waal_prepare_lock_recognition();
    fn waal_prepare_lock_recognition_sample() -> bool;
    fn waal_lock_capture_request() -> bool;
    fn waal_record_capture_request() -> bool;
    fn waal_open_capture_preferences() -> bool;
    fn waal_observe_lock_screen(
        pid: i32,
        window_id: u32,
        visitor: extern "C" fn(*mut c_void, i32, *const u8, usize, f32, f64, f64, f64, f64),
        context: *mut c_void,
    ) -> i32;
}

pub(crate) fn supported() -> bool {
    // The native screenshot API used by this feature shipped in macOS 14.
    unsafe { waal_lock_capture_supported() }
}

pub(crate) fn screen_recording_allowed() -> bool {
    // Preflight never displays the system permission dialog.
    unsafe { waal_lock_capture_allowed() }
}

pub(crate) fn prepare_recognition() {
    // The native worker loads Vision using only its own fixed in-memory sample.
    unsafe { waal_prepare_lock_recognition() }
}

pub(crate) const PREPARE_OCR_ARG: &str = "--prepare-lock-ocr";

pub(crate) fn prepare_recognition_sample() -> anyhow::Result<()> {
    anyhow::ensure!(
        unsafe { waal_prepare_lock_recognition_sample() },
        "Vision could not read its preparation sample."
    );
    Ok(())
}

pub(crate) fn recover_recognition() -> anyhow::Result<()> {
    // Vision can retain handles to models that macOS has evicted. A fresh
    // instance of the same executable rebuilds them in this app's cache.
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command.arg(PREPARE_OCR_ARG);
    let outcome = crate::macos_identity::run_command_with_timeout(
        &mut command,
        std::time::Duration::from_secs(180),
    )?;
    anyhow::ensure!(outcome.status.success(), "Vision preparation failed.");
    Ok(())
}

pub(crate) fn request_screen_recording() -> bool {
    // Called at startup when a linked desktop is eligible for automatic reconnect.
    static STARTUP_REQUESTED: AtomicBool = AtomicBool::new(false);
    if STARTUP_REQUESTED.swap(true, Ordering::Relaxed) {
        return screen_recording_allowed();
    }
    request_access(false)
}

pub(crate) fn request_screen_recording_on_opt_in() -> bool {
    request_access(true)
}

pub(crate) fn open_screen_recording_settings() -> bool {
    supported() && unsafe { waal_open_capture_preferences() }
}

fn request_access(user_action: bool) -> bool {
    supported()
        && request_permission(
            user_action,
            screen_recording_allowed,
            || unsafe { waal_record_capture_request() },
            || unsafe { waal_lock_capture_request() },
            || {
                open_screen_recording_settings();
            },
        )
}

fn request_permission(
    user_action: bool,
    allowed: impl Fn() -> bool,
    record_attempt: impl FnOnce() -> bool,
    request: impl FnOnce() -> bool,
    open_preferences: impl FnOnce(),
) -> bool {
    if allowed() {
        return true;
    }
    let previously_requested = record_attempt();
    if request() || allowed() {
        return true;
    }
    // macOS may suppress a second system prompt. An explicit retry should
    // still give the user a way to grant access. Startup never opens Settings.
    if user_action && previously_requested {
        open_preferences();
    }
    false
}

mod directory;
use directory::{visit_account_line, FrameRead};

pub(crate) fn observe(pid: i32, window_id: u32, usernames: &[&str]) -> LockScreenObservation {
    let mut frame = FrameRead::new(usernames);
    // The native bridge completes all callbacks before the borrowed frame goes out of scope.
    let result = unsafe {
        waal_observe_lock_screen(
            pid,
            window_id,
            visit_account_line,
            std::ptr::from_mut(&mut frame).cast(),
        )
    };
    match result {
        -1 => LockScreenObservation::RecognitionFailed,
        1 => frame.observation(true),
        _ => LockScreenObservation::Unavailable,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Label {
    Password,
    MaskedField,
    EditorBounds,
    Name,
    Address,
    Conflict,
    SmallMark,
    IconFragment,
    Other,
}

#[derive(Clone, Copy)]
struct Line {
    label: Label,
    confidence: f32,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

// Observation kinds in the native window reader.
const OVERVIEW_TEXT: i32 = 0;
const MASKED_FIELD: i32 = 1;
const VERIFIED_PLACEHOLDER: i32 = 2;
const EDITOR_BOUNDS: i32 = 3;
const CORNER_TEXT: i32 = 4;
const ACCOUNT_TEXT: i32 = 5;
const LAYOUT_TEXT: i32 = 6;

extern "C" fn visit_line(
    context: *mut c_void,
    kind: i32,
    bytes: *const u8,
    len: usize,
    confidence: f32,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
) {
    // The native reader emits all overview observations before its final
    // detail observation. The screen text is discarded in this callback.
    let lines = unsafe { &mut *context.cast::<Vec<Line>>() };
    let label = match kind {
        OVERVIEW_TEXT | CORNER_TEXT | ACCOUNT_TEXT | LAYOUT_TEXT if !bytes.is_null() => {
            let utf8 = unsafe { slice::from_raw_parts(bytes, len) };
            let text = str::from_utf8(utf8);
            let label = text.map_or(Label::Conflict, label);
            if kind == LAYOUT_TEXT && !matches!(label, Label::Conflict | Label::Address) {
                // Windows displays the input language as a short uppercase
                // abbreviation. Only a confident native read may clear a
                // garbled reading of these same glyphs by fast OCR.
                if label != Label::SmallMark
                    || confidence < 0.80
                    || !text.is_ok_and(|s| {
                        (2..=3).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_uppercase())
                    })
                {
                    return;
                }
            }
            // The accurate corner pass can veto an alternative sign-in method,
            // even when fast OCR misses the tile or garbles its caption.
            let veto = matches!(label, Label::Conflict | Label::Address);
            if (kind == CORNER_TEXT && !veto)
                || (kind == ACCOUNT_TEXT && !veto && label != Label::Name)
            {
                return;
            }
            label
        }
        MASKED_FIELD => Label::MaskedField,
        VERIFIED_PLACEHOLDER => Label::Password,
        EDITOR_BOUNDS => Label::EditorBounds,
        _ => Label::Conflict,
    };
    let line = Line {
        label,
        confidence,
        x,
        y,
        width,
        height,
    };
    if kind == VERIFIED_PLACEHOLDER
        || (kind == ACCOUNT_TEXT && label == Label::Name)
        || (kind == LAYOUT_TEXT && label == Label::SmallMark)
    {
        merge_detail(lines, line);
    } else {
        lines.push(line);
    }
}

// The overview may omit, truncate, or distort a word. Replace at
// most one reading of those same glyphs. Conflicts and adjacent lines still
// participate in classification, even if the cropped field reads "Password".
fn merge_detail(lines: &mut Vec<Line>, verified: Line) {
    let mut overlaps = lines.iter_mut().filter(|line| {
        if line.label == Label::EditorBounds {
            return false;
        }
        let dx = (line.x - verified.x).abs();
        let dy = (line.y - verified.y).abs();
        let w = line
            .width
            .min(verified.width)
            .min((line.width + verified.width) / 2.0 - dx);
        let h = line
            .height
            .min(verified.height)
            .min((line.height + verified.height) / 2.0 - dy);
        let area = w.max(0.0) * h.max(0.0);
        let fast = line.width * line.height;
        let accurate = verified.width * verified.height;
        if matches!(verified.label, Label::Name | Label::SmallMark) {
            area >= 0.50 * fast.max(accurate)
        } else {
            // The accurate crop can fit the ink more tightly on all four
            // sides. Match a near-concentric whole word or a contained
            // fragment, never an adjacent word on the same baseline.
            let same_word = dx <= 0.12 * line.width.min(verified.width)
                && dy <= 0.15 * line.height.min(verified.height)
                && w >= 0.82 * line.width.max(verified.width)
                && h >= 0.70 * line.height.max(verified.height);
            same_word || (area >= 0.85 * fast && area >= 0.33 * accurate)
        }
    });
    if let Some(same) = overlaps.next() {
        if overlaps.next().is_some() {
            lines.push(Line {
                label: Label::Conflict,
                ..verified
            });
            return;
        }
        if same.label == verified.label
            || matches!(
                same.label,
                Label::Other | Label::SmallMark | Label::IconFragment
            )
        {
            *same = verified;
            return;
        }
    }
    // The system indicator can only correct a misread mark at this location.
    // It contributes no new evidence for a password screen.
    if verified.label != Label::SmallMark {
        lines.push(verified);
    }
}

fn label(raw: &str) -> Label {
    let text = raw.trim();
    if text.eq_ignore_ascii_case("Password") {
        return Label::Password;
    }
    let lower = text.to_lowercase();
    let conflict = lower.contains("://")
        || [
            "password",
            "other user",
            "sign in",
            "sign-in",
            "microsoft account",
            "username",
            "user name",
            "switch user",
            "security key",
            "forgot",
            "verification",
            "windows hello",
        ]
        .iter()
        .any(|blocked| lower.contains(blocked))
        || lower
            .split(|c: char| !c.is_alphanumeric())
            .any(|word| matches!(word, "pin" | "passcode" | "www"));
    if conflict {
        return Label::Conflict;
    }
    if text.contains('@') {
        return Label::Address;
    }
    let mut words = text.split_whitespace();
    let count = words.clone().count();
    if (2..=4).contains(&count)
        && text.chars().count() <= 64
        && words.all(|word| {
            word.chars().filter(|c| c.is_alphabetic()).count() >= 2
                && word
                    .chars()
                    .all(|c| c.is_alphabetic() || matches!(c, '-' | '\'' | '’'))
        })
    {
        return Label::Name;
    }
    if text.chars().count() <= 3 && !text.is_empty() {
        return Label::SmallMark;
    }
    if text.chars().count() == 4 && text.chars().any(|c| c.is_ascii_punctuation()) {
        return Label::IconFragment;
    }
    Label::Other
}

fn is_tile_caption(line: &Line, editor: &Line) -> bool {
    let left = (line.x - line.width / 2.0) / editor.width;
    matches!(line.label, Label::Name | Label::Other | Label::SmallMark)
        && (0.10..=0.41).contains(&left)
        && line.width <= editor.width * 0.75
        && line.height <= editor.height * 0.62
        && line.y - line.height / 2.0 <= editor.height * 3.55
        && line.y + line.height / 2.0 < editor.y - editor.height / 2.0
}

fn is_system_icon(line: &Line, editor: &Line) -> bool {
    // On small windows OCR can read the bottom-right Windows icons as glyphs.
    matches!(line.label, Label::SmallMark | Label::IconFragment)
        && (0.12..=0.48).contains(&((1.0 - line.x) / editor.width))
        && (0.6..=1.7).contains(&(line.y / editor.height))
        && line.width <= 0.12 * editor.width
        && line.height <= 0.35 * editor.height
}

fn placeholder_in_editor(line: &Line, editor: Option<&Line>) -> bool {
    let Some(e) = editor else {
        return (0.33..=0.505).contains(&line.x)
            && (0.25..=0.55).contains(&line.y)
            && (0.006..=0.065).contains(&line.height);
    };
    let inset = ((line.x - line.width / 2.0) - (e.x - e.width / 2.0)) / e.width;
    (-0.01..=0.15).contains(&inset)
        && line.width <= 0.5 * e.width
        && (line.y - e.y).abs() <= e.height * 0.28
        && (0.15..=0.9).contains(&(line.height / e.height))
}

fn valid_line(line: &Line) -> bool {
    (0.0..=1.0).contains(&line.confidence)
        && [line.x, line.y, line.width, line.height]
            .iter()
            .all(|v| (0.0..=1.0).contains(v))
        && line.width > 0.0
        && line.height > 0.0
}

fn classify(lines: &[Line]) -> LockScreenObservation {
    use LockScreenObservation::{Other, Password};

    if lines.is_empty() || lines.len() > 16 || !lines.iter().all(valid_line) {
        return Other;
    }
    let mut account = None;
    let mut field = None;
    let mut editors = lines
        .iter()
        .filter(|line| matches!(line.label, Label::EditorBounds | Label::MaskedField));
    let editor = editors.next();
    if editors.next().is_some()
        || editor.is_some_and(|e| {
            // At the client's minimum size the sign-in group can sit slightly
            // to one side. Limit that offset to a fraction of the editor itself.
            (e.x - 0.50).abs() > (0.16 * e.width).clamp(0.03, 0.08) || !(0.20..=0.56).contains(&e.y)
        })
    {
        return Other;
    }
    for line in lines {
        // Only guest pixels reach the classifier, including the very top row.
        if matches!(line.label, Label::Conflict | Label::Address) {
            return Other;
        }
        if line.label == Label::EditorBounds {
            continue;
        }
        // Known Windows account tiles sit in the bottom-left corner. They
        // may show a short second caption even for a locked session. Reject
        // explicit alternative sign-in methods or Other user above.
        if line.y <= 0.18 && line.x < 0.18 && line.width <= 0.24 && line.height < 0.035 {
            continue;
        }
        // Tile captions start at the same inset from the left edge at every
        // guest DPI. On a small window they reach beyond the usual corner.
        if editor.is_some_and(|e| is_tile_caption(line, e) || is_system_icon(line, e)) {
            continue;
        }
        if line.label == Label::SmallMark
            && ((line.y < 0.09 && line.x > 0.65)
                || (line.x > 0.50 && line.x < 0.68 && (0.30..0.58).contains(&line.y)))
        {
            continue;
        }
        // Do not accept forms with unrelated text, duplicate names/placeholders
        // or many controls, even if they contain Password in the right place.
        match line.label {
            Label::Name
                if line.confidence >= 0.50
                    && (line.x - editor.map_or(0.50, |e| e.x)).abs() <= 0.035
                    && (0.34..=0.63).contains(&line.y)
                    && editor.map_or_else(
                        || (0.010..=0.120).contains(&line.height),
                        |e| (0.35..=2.0).contains(&(line.height / e.height)),
                    )
                    && account.is_none() =>
            {
                account = Some(line)
            }
            Label::Password
                if line.confidence >= 0.50
                    && placeholder_in_editor(line, editor)
                    && field.is_none() =>
            {
                field = Some(line)
            }
            Label::MaskedField if field.is_none() => field = Some(line),
            _ => return Other,
        }
    }
    if let (Some(name), Some(password)) = (account, field) {
        let gap = name.y - password.y;
        let aligned = match password.label {
            Label::Password => name.height >= password.height * 1.2 && password.x < name.x,
            Label::MaskedField => {
                (name.x - password.x).abs() <= 0.025
                    && name.height >= password.height * 0.45
                    && gap > (password.height + name.height) / 2.0
            }
            _ => false,
        };
        let expected_gap = editor.map_or_else(
            || (0.018..=0.145).contains(&gap),
            |e| (0.8..=3.5).contains(&(gap / e.height)),
        );
        if expected_gap && aligned {
            return Password;
        }
    }
    Other
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn repeated_opt_in_checks_access_requests_again_and_opens_the_pane_if_still_denied() {
        let requested = Cell::new(false);
        let checks = Cell::new(0);
        let requests = Cell::new(0);
        let opens = Cell::new(0);
        let attempt = |user_action| {
            request_permission(
                user_action,
                || {
                    checks.set(checks.get() + 1);
                    false
                },
                || requested.replace(true),
                || {
                    requests.set(requests.get() + 1);
                    false
                },
                || opens.set(opens.get() + 1),
            )
        };
        assert!(!attempt(true));
        assert_eq!((requests.get(), opens.get()), (1, 0));
        assert!(!attempt(true));
        assert_eq!((requests.get(), opens.get()), (2, 1));
        assert!(!attempt(false));
        assert_eq!((requests.get(), opens.get(), checks.get()), (3, 1, 6));
    }

    #[test]
    fn granted_access_and_a_new_grant_after_a_request_skip_settings() {
        assert!(request_permission(
            true,
            || true,
            || panic!("attempt"),
            || panic!("request"),
            || panic!("settings")
        ));
        assert!(request_permission(
            true,
            || false,
            || true,
            || true,
            || panic!("settings")
        ));
        let already_checked = Cell::new(false);
        assert!(request_permission(
            true,
            || already_checked.replace(true),
            || true,
            || false,
            || panic!("settings")
        ));
    }

    fn line(text: &str, x: f64, y: f64, height: f64) -> Line {
        Line {
            label: label(text),
            confidence: 0.95,
            x,
            y,
            width: 0.08,
            height,
        }
    }

    fn form() -> [Line; 2] {
        [
            line("Example Person", 0.50, 0.46, 0.027),
            line("Password", 0.45, 0.405, 0.013),
        ]
    }

    #[test]
    fn sparse_centered_name_and_password_below_are_visual_evidence() {
        let mut frame = form().to_vec();
        frame.push(line("ENG", 0.90, 0.03, 0.009));
        assert_eq!(classify(&frame), LockScreenObservation::Password);
        for text in ["Other user", "Network maintenance"] {
            let mut with_banner = frame.clone();
            with_banner.push(line(text, 0.50, 0.985, 0.012));
            assert_eq!(classify(&with_banner), LockScreenObservation::Other);
        }
    }

    #[test]
    fn windowed_layout_indicator_requires_a_matching_native_read() {
        // Geometry observed in a 1650 × 960 point window on a Retina display.
        let mut editor = line("", 0.500, 0.443, 0.023);
        editor.label = Label::EditorBounds;
        editor.width = 0.114;
        let mut password = line("Password", 0.457, 0.443, 0.012);
        password.width = 0.024;
        let mut mark = line("EN6G", 0.964, 0.028, 0.005);
        mark.width = 0.009;
        let frame = vec![
            editor,
            line("Example Person", 0.5, 0.484, 0.019),
            password,
            mark,
        ];
        assert_eq!(classify(&frame), LockScreenObservation::Other);
        let read = |lines: &mut Vec<Line>, text: &str, x: f64, confidence: f32| {
            visit_line(
                (lines as *mut Vec<Line>).cast(),
                LAYOUT_TEXT,
                text.as_ptr(),
                text.len(),
                confidence,
                x,
                mark.y,
                mark.width,
                mark.height,
            );
        };
        let mut verified = frame.clone();
        read(&mut verified, "ENG", mark.x, 1.0);
        assert_eq!(classify(&verified), LockScreenObservation::Password);
        for (text, x, confidence) in [
            ("PIN", mark.x, 1.0),
            ("Other user", mark.x, 1.0),
            ("ENG", mark.x - 0.02, 1.0),
            ("ENG", mark.x, 0.50),
            ("EN6G", mark.x, 1.0),
        ] {
            let mut lines = frame.clone();
            read(&mut lines, text, x, confidence);
            assert_eq!(classify(&lines), LockScreenObservation::Other);
        }
        let mut conflict = frame;
        conflict.last_mut().unwrap().label = Label::Conflict;
        read(&mut conflict, "ENG", mark.x, 1.0);
        assert_eq!(classify(&conflict), LockScreenObservation::Other);
    }

    #[test]
    fn native_name_read_at_large_guest_scale_only_repairs_the_same_caption() {
        // Captured guest geometry in a wide 1900 × 650 point window.
        let mut editor = line("", 0.500, 0.402, 0.057);
        editor.label = Label::EditorBounds;
        editor.width = 0.158;
        let mut password = line("Password", 0.443, 0.402, 0.020);
        password.width = 0.031;
        let mut caption = line("Unreadab1e", 0.500, 0.501, 0.046);
        caption.width = 0.144;
        let form = vec![caption, password, editor];
        let account = b"Example Person";
        let reread = |lines: &mut Vec<Line>, x: f64| {
            visit_line(
                (lines as *mut Vec<Line>).cast(),
                ACCOUNT_TEXT,
                account.as_ptr(),
                account.len(),
                1.0,
                x,
                caption.y,
                caption.width,
                caption.height,
            );
        };
        assert_eq!(classify(&form), LockScreenObservation::Other);
        let mut corrected = form.clone();
        reread(&mut corrected, caption.x);
        assert_eq!(classify(&corrected), LockScreenObservation::Password);
        let mut separate = form.clone();
        reread(&mut separate, caption.x + caption.width);
        assert_eq!(classify(&separate), LockScreenObservation::Other);
        let mut conflicting = form;
        conflicting[0].label = Label::Conflict;
        reread(&mut conflicting, caption.x);
        assert_eq!(classify(&conflicting), LockScreenObservation::Other);
    }

    #[test]
    fn compact_guest_accepts_a_shifted_group_only_with_an_aligned_name_and_editor() {
        // 640 × 512 point window, with a 640 × 480 point remote viewport.
        let mut editor = line("", 0.544, 0.374, 0.068);
        editor.label = Label::EditorBounds;
        editor.width = 0.43;
        let mut password = line("Password", 0.395, 0.374, 0.025);
        password.width = 0.091;
        let name = line("Example Person", 0.552, 0.507, 0.044);
        let mut tile = line("Work account", 0.174, 0.235, 0.021);
        tile.width = 0.048;
        assert_eq!(
            classify(&[editor, password, name, tile]),
            LockScreenObservation::Password
        );
        for (e, n, t) in [
            (editor, Line { x: 0.50, ..name }, tile),
            (Line { x: 0.65, ..editor }, name, tile),
            (
                editor,
                name,
                Line {
                    label: Label::Conflict,
                    ..tile
                },
            ),
        ] {
            assert_eq!(classify(&[e, password, n, t]), LockScreenObservation::Other);
        }
    }

    #[test]
    fn tighter_native_bounds_match_the_same_word_across_guest_dpi() {
        // Fast and Accurate bounds of the same caption at 150% and 200% DPI.
        for (fast, exact) in [
            (
                [0.4501, 0.4360, 0.0296, 0.0243],
                [0.4517, 0.4372, 0.0268, 0.0182],
            ),
            (
                [0.4365, 0.4173, 0.0333, 0.0261],
                [0.4365, 0.4167, 0.0350, 0.0211],
            ),
        ] {
            let word = |text, b: [f64; 4]| Line {
                width: b[2],
                ..line(text, b[0], b[1], b[3])
            };
            let misread = word("Passw0rd", fast);
            let correct = word("Password", exact);
            let mut lines = vec![misread];
            merge_detail(&mut lines, correct);
            assert!(matches!(lines.as_slice(), [l] if l.label == Label::Password));

            for invalid in [vec![misread, misread], vec![word("Other user", fast)]] {
                let mut lines = invalid;
                merge_detail(&mut lines, correct);
                assert!(lines.iter().any(|l| l.label == Label::Conflict));
            }
        }
    }

    #[test]
    fn accurate_crop_can_replace_one_fragment_of_the_same_word() {
        let [name, password] = form();
        let fragment = Line {
            label: Label::Other,
            width: password.width * 0.56,
            height: password.height * 0.70,
            x: password.x + password.width * 0.20,
            ..password
        };
        let mut lines = vec![name, fragment];
        merge_detail(&mut lines, password);
        assert_eq!(classify(&lines), LockScreenObservation::Password);

        // Nearby instructions, ambiguous fragments and a conflicting sign-in
        // method must still be accounted for even if the crop reads Password.
        for unexpected in [
            vec![Line {
                x: password.x + password.width,
                ..fragment
            }],
            vec![fragment, fragment],
            vec![Line {
                label: Label::Conflict,
                ..fragment
            }],
            vec![Line {
                width: password.width * 2.0,
                ..fragment
            }],
        ] {
            let mut lines = vec![name];
            lines.extend(unexpected);
            merge_detail(&mut lines, password);
            assert_eq!(classify(&lines), LockScreenObservation::Other);
        }
    }

    #[test]
    fn alternate_methods_web_forms_and_mixed_account_screens_are_not_password_evidence() {
        for value in [
            "PIN",
            "Other user",
            "user@example.org",
            "Sign-in options",
            "https://example.org",
            "Forgot your password?",
            "Use a security key",
            "Some unrelated instructions",
        ] {
            let mut frame = form().to_vec();
            frame.push(line(value, 0.33, 0.15, 0.01));
            assert_eq!(classify(&frame), LockScreenObservation::Other);
        }
        assert_eq!(classify(&form()[1..]), LockScreenObservation::Other);
    }

    #[test]
    fn accepts_only_one_high_confidence_password_in_the_expected_layout() {
        let mut frame = form();
        frame[0].x = 0.25;
        assert_eq!(classify(&frame), LockScreenObservation::Other);
        frame = form();
        frame[1].y = 0.53;
        assert_eq!(classify(&frame), LockScreenObservation::Other);
        frame = form();
        frame[1].confidence = 0.35;
        assert_eq!(classify(&frame), LockScreenObservation::Other);
        frame = form();
        frame[0].height = f64::NAN;
        assert_eq!(classify(&frame), LockScreenObservation::Other);
        let mut duplicate = form().to_vec();
        duplicate.push(form()[1]);
        assert_eq!(classify(&duplicate), LockScreenObservation::Other);
    }

    #[test]
    fn pixel_confirmed_mask_needs_a_single_centered_name_directly_above_it() {
        let mut masked = line("", 0.50, 0.42, 0.031);
        masked.label = Label::MaskedField;
        masked.width = 0.16;
        let mut name = line("Example Person", 0.50, 0.483, 0.029);
        // Vision's fast recognizer commonly returns 0.5 for clean labels.
        name.confidence = 0.5;
        let corner = line("Account tile", 0.095, 0.116, 0.015);
        assert_eq!(
            classify(&[name, masked, corner]),
            LockScreenObservation::Password
        );
        assert_eq!(classify(&[masked]), LockScreenObservation::Other);
        assert_eq!(
            classify(&[name, masked, masked]),
            LockScreenObservation::Other
        );
        assert_eq!(
            classify(&[name, masked, line("Other user", 0.10, 0.11, 0.015)]),
            LockScreenObservation::Other
        );
        masked.x = 0.55;
        assert_eq!(classify(&[name, masked]), LockScreenObservation::Other);
        masked.x = 0.50;
        masked.y = name.y - 0.01;
        assert_eq!(classify(&[name, masked]), LockScreenObservation::Other);
        assert_eq!(
            classify(&[name, line("••••", 0.42, 0.42, 0.02)]),
            LockScreenObservation::Other
        );
    }
}

#[cfg(test)]
#[path = "macos_lock_screen/frame_tests.rs"]
mod frame_tests;

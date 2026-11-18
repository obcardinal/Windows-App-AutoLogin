//! Recognizes the layout of the English Windows password screen. This is
//! visual evidence only. It does not attest the guest desktop or its identity.

use std::{ffi::c_void, slice, str};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockScreenObservation {
    Password,
    Other,
    Unavailable,
}

#[link(name = "waal_lock_screen_capture", kind = "static")]
#[link(name = "Vision", kind = "framework")]
unsafe extern "C" {
    fn waal_lock_capture_supported() -> bool;
    fn waal_lock_capture_allowed() -> bool;
    fn waal_observe_lock_screen(
        pid: i32,
        window_id: u32,
        visitor: extern "C" fn(*mut c_void, *const u8, usize, f32, f64, f64, f64, f64),
        context: *mut c_void,
    ) -> bool;
}

pub(crate) fn supported() -> bool {
    // The native screenshot API used by this feature shipped in macOS 14.
    unsafe { waal_lock_capture_supported() }
}

pub(crate) fn screen_recording_allowed() -> bool {
    // Preflight never displays the system permission dialog.
    unsafe { waal_lock_capture_allowed() }
}

pub(crate) fn observe(pid: i32, window_id: u32) -> LockScreenObservation {
    let mut lines = Vec::<Line>::new();
    // The native bridge calls visit_line synchronously, finishes all visits
    // before returning, and never registers the context with async callbacks.
    let success = unsafe {
        waal_observe_lock_screen(
            pid,
            window_id,
            visit_line,
            (&mut lines as *mut Vec<Line>).cast(),
        )
    };
    if success {
        classify(&lines)
    } else {
        LockScreenObservation::Unavailable
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Label {
    Password,
    MaskedField,
    Name,
    Conflict,
    SmallMark,
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

extern "C" fn visit_line(
    context: *mut c_void,
    bytes: *const u8,
    len: usize,
    confidence: f32,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
) {
    // A null text pointer denotes a pixel-confirmed masked field. Other
    // pointers and the byte length are valid for this synchronous visit.
    let lines = unsafe { &mut *context.cast::<Vec<Line>>() };
    let label = if bytes.is_null() {
        Label::MaskedField
    } else {
        let utf8 = unsafe { slice::from_raw_parts(bytes, len) };
        str::from_utf8(utf8).map_or(Label::Other, label)
    };
    // Discard the actual screen text, including any possible display name.
    lines.push(Line {
        label,
        confidence,
        x,
        y,
        width,
        height,
    });
}

fn label(raw: &str) -> Label {
    let text = raw.trim();
    if text.eq_ignore_ascii_case("Password") {
        return Label::Password;
    }
    let lower = text.to_lowercase();
    let conflict = lower.contains('@')
        || lower.contains("://")
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
    Label::Other
}

fn classify(lines: &[Line]) -> LockScreenObservation {
    use LockScreenObservation::{Other, Password};

    if lines.is_empty() || lines.len() > 16 {
        return Other;
    }
    let mut account = None;
    let mut field = None;
    for line in lines {
        if !line.confidence.is_finite()
            || !(0.0..=1.0).contains(&line.confidence)
            || ![line.x, line.y, line.width, line.height]
                .iter()
                .all(|v| (0.0..=1.0).contains(v))
            || line.width == 0.0
            || line.height == 0.0
        {
            return Other;
        }
        // Vision's y-axis points upwards. The native window title is above
        // the guest. Keep ambiguous/conflicting text inside the guest visible
        // to the classifier, even when outside the expected password field.
        if line.y > 0.965 {
            continue;
        }
        if line.label == Label::Conflict {
            return Other;
        }
        // Known Windows account tiles sit in the bottom-left corner. They
        // may show a short second caption even for a locked session. Reject
        // explicit alternative sign-in methods or Other user above.
        if line.y <= 0.18 && line.x < 0.18 && line.width <= 0.24 && line.height < 0.035 {
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
                    && (0.465..=0.535).contains(&line.x)
                    && (0.34..=0.63).contains(&line.y)
                    && (0.010..=0.120).contains(&line.height)
                    && account.is_none() =>
            {
                account = Some(line)
            }
            Label::Password
                if line.confidence >= 0.50
                    && (0.33..=0.505).contains(&line.x)
                    && (0.25..=0.55).contains(&line.y)
                    && (0.006..=0.065).contains(&line.height)
                    && field.is_none() =>
            {
                field = Some(line)
            }
            Label::MaskedField
                if (0.47..=0.53).contains(&line.x)
                    && (0.25..=0.55).contains(&line.y)
                    && (0.065..=0.45).contains(&line.width)
                    && (0.012..=0.085).contains(&line.height)
                    && field.is_none() =>
            {
                field = Some(line)
            }
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
        if (0.018..=0.145).contains(&gap) && aligned {
            return Password;
        }
    }
    Other
}

#[cfg(test)]
mod tests {
    use super::*;
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
        frame.extend([
            line("Cloud PC title", 0.50, 0.985, 0.012),
            line("ENG", 0.90, 0.03, 0.009),
        ]);
        assert_eq!(classify(&frame), LockScreenObservation::Password);
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

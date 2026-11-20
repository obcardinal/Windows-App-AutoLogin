//! A managed Windows desktop can show a display name and a directory login
//! over wallpaper containing text. Keep only the index of an exact local
//! account match. The session must independently resolve to the same account.
use super::{classify, label, valid_line, visit_line, Label, Line, LockScreenObservation};
use std::{ffi::c_void, slice, str};

// PairedAccountText in the native reader, emitted only above a measured editor.
const PAIRED_ACCOUNT_TEXT: i32 = 8;

pub(super) struct FrameRead<'a> {
    usernames: &'a [&'a str],
    lines: Vec<Line>,
    pair: Vec<(Line, Option<usize>)>,
}

impl<'a> FrameRead<'a> {
    pub(super) fn new(usernames: &'a [&'a str]) -> Self {
        Self {
            usernames,
            lines: Vec::new(),
            pair: Vec::new(),
        }
    }

    pub(super) fn observation(self, success: bool) -> LockScreenObservation {
        use LockScreenObservation::{AccountPassword, Other, Password, Unavailable};
        if !success {
            return Unavailable;
        }
        if self.pair.is_empty() {
            return classify(&self.lines);
        }
        let [first, second] = self.pair.as_slice() else {
            return Other;
        };
        let (name, login) = if first.0.y > second.0.y {
            (first, second)
        } else {
            (second, first)
        };
        let Some(account) = login.1 else {
            return Other;
        };
        let (name, login) = (&name.0, &login.0);
        let Some(editor) = self
            .lines
            .iter()
            .find(|l| matches!(l.label, Label::EditorBounds | Label::MaskedField))
            .copied()
        else {
            return Other;
        };
        if name.label != Label::Name
            || login.label != Label::Address
            || ![name, login].into_iter().all(|l| {
                valid_line(l)
                    && l.confidence >= 0.75
                    && (l.x - editor.x).abs() <= 0.09 * editor.width
            })
            || !(0.8..=2.1).contains(&((login.y - editor.y) / editor.height))
            || name.y - name.height * 0.5 <= login.y + login.height * 0.5
            || name.height < login.height * 1.2
            || !self.lines.iter().all(valid_line)
        {
            return Other;
        }

        let mut controls = Vec::new();
        let (mut name_seen, mut login_seen) = (false, false);
        for line in self.lines {
            // Correct at most one fast read of each accurately confirmed row.
            let seen = if matches!(line.label, Label::Name | Label::Other) && same_row(&line, name)
            {
                Some(&mut name_seen)
            } else if matches!(line.label, Label::Address | Label::Other) && same_row(&line, login)
            {
                Some(&mut login_seen)
            } else {
                None
            };
            if let Some(seen) = seen {
                if *seen {
                    return Other;
                }
                *seen = true;
                continue;
            }
            // Peripheral copy can be part of the wallpaper. Keep all explicit
            // sign-in conflicts and all text overlapping the credential group.
            let dx = (line.x - editor.x).abs();
            let outside_group = dx > editor.width * 0.8
                && (dx - line.width * 0.5 > editor.width * 0.72
                    || (line.y - editor.y).abs() - line.height * 0.5 > editor.height * 4.0);
            if outside_group
                && matches!(
                    line.label,
                    Label::Name | Label::Other | Label::SmallMark | Label::IconFragment
                )
            {
                continue;
            }
            controls.push(line);
        }
        controls.push(*name);
        if classify(&controls) == Password {
            AccountPassword(account)
        } else {
            Other
        }
    }
}

fn same_row(fast: &Line, accurate: &Line) -> bool {
    let overlap = |a: f64, wa: f64, b: f64, wb: f64| {
        ((a + wa * 0.5).min(b + wb * 0.5) - (a - wa * 0.5).max(b - wb * 0.5)).max(0.0)
    };
    overlap(fast.x, fast.width, accurate.x, accurate.width)
        * overlap(fast.y, fast.height, accurate.y, accurate.height)
        >= 0.5 * (fast.width * fast.height).max(accurate.width * accurate.height)
}

fn directory_account(text: &str, usernames: &[&str]) -> Option<usize> {
    let (domain, upn) = text.trim().split_once('\\')?;
    if domain.is_empty()
        || !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        || !upn.contains('@')
        || upn.contains('\\')
        || upn.contains(char::is_whitespace)
    {
        return None;
    }
    let mut matches = usernames
        .iter()
        .enumerate()
        .filter(|(_, username)| upn.eq_ignore_ascii_case(username.trim()));
    let (index, _) = matches.next()?;
    matches.next().is_none().then_some(index)
}

pub(super) extern "C" fn visit_account_line(
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
    // The native reader invokes the callback synchronously and never retains it.
    let frame = unsafe { &mut *context.cast::<FrameRead<'_>>() };
    if kind != PAIRED_ACCOUNT_TEXT {
        visit_line(
            std::ptr::from_mut(&mut frame.lines).cast(),
            kind,
            bytes,
            len,
            confidence,
            x,
            y,
            width,
            height,
        );
        return;
    }
    let text = if bytes.is_null() {
        ""
    } else {
        str::from_utf8(unsafe { slice::from_raw_parts(bytes, len) }).unwrap_or("")
    };
    let account = directory_account(text, frame.usernames);
    let label = if account.is_some() {
        Label::Address
    } else {
        // Windows may use the directory's “Surname, Given” display format.
        label(&text.replacen(',', " ", 1))
    };
    frame.pair.push((
        Line {
            label,
            confidence,
            x,
            y,
            width,
            height,
        },
        account,
    ));
}

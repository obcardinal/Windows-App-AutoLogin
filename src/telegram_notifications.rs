use keyring::Entry;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::CONTENT_TYPE;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub(crate) const BOT_URL: &str = "https://t.me/windows_app_autologin_bot";
const PAIR_URL: &str = "https://obcardinal.com/windows-app-autologin/api/v1/pair";
const UNLINK_URL: &str = "https://obcardinal.com/windows-app-autologin/api/v1/unlink";
const NOTIFY_URL: &str = "https://obcardinal.com/windows-app-autologin/api/v1/notify";
const SERVICE: &str = "WindowsAppAutoLogin.Telegram";
const ACCOUNT: &str = "device-token";
const CODE_LENGTH: usize = 16;
const TOKEN_LENGTH: usize = 43;
const MAX_PAIR_REPLY_BYTES: usize = 512;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const STORE_ERROR: &str = "Could not access the Telegram link in system secure storage.";
const LINK_BUSY: &str = "Could not change the Telegram link. Try again in a moment.";
const RELAY_ERROR: &str = "Could not reach the Telegram notification service. Try again later.";
const INVALID_CODE: &str = "Enter the 16-character pairing code from the Telegram bot.";
const INVALID_REPLY: &str = "The notification service returned an invalid pairing response.";
type Result<T> = std::result::Result<T, &'static str>;

fn is_url_safe_secret(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn entry() -> Result<Entry> {
    Entry::new(SERVICE, ACCOUNT).map_err(|_| STORE_ERROR)
}

fn stored_token(entry: &Entry) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match entry.get_secret() {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(_) => Err(STORE_ERROR),
    }
}

fn valid_token(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes)
        .ok()
        .filter(|s| is_url_safe_secret(s, TOKEN_LENGTH))
}

pub(crate) fn is_linked() -> Result<bool> {
    Ok(stored_token(&entry()?)?.is_some())
}

fn post(url: &'static str) -> Result<RequestBuilder> {
    let client = Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .connect_timeout(Duration::from_secs(3))
        .build()
        .map_err(|_| RELAY_ERROR)?;
    // A per-request timeout also bounds the entire response-body read.
    Ok(client.post(url).timeout(REQUEST_TIMEOUT))
}

fn authenticated_request(url: &'static str, token: &str) -> Result<RequestBuilder> {
    Ok(post(url)?
        .bearer_auth(token)
        .header(CONTENT_TYPE, "application/json")
        .body("{}"))
}

fn authenticated_post(url: &'static str, token: &str) -> Result<StatusCode> {
    let response = authenticated_request(url, token)?
        .send()
        .map_err(|_| RELAY_ERROR)?;
    Ok(response.status())
}

#[derive(Serialize)]
struct PairRequest<'a> {
    code: &'a str,
}

#[derive(Deserialize)]
struct PairReply<'a> {
    device_token: &'a str,
}

fn parse_pair_reply(bytes: &[u8]) -> Result<Zeroizing<String>> {
    if bytes.len() > MAX_PAIR_REPLY_BYTES {
        return Err(INVALID_REPLY);
    }
    let reply: PairReply<'_> = serde_json::from_slice(bytes).map_err(|_| INVALID_REPLY)?;
    if !is_url_safe_secret(reply.device_token, TOKEN_LENGTH) {
        return Err(INVALID_REPLY);
    }
    Ok(Zeroizing::new(reply.device_token.to_owned()))
}

fn paired_token(response: Response) -> Result<Zeroizing<String>> {
    match response.status() {
        StatusCode::OK => {}
        StatusCode::UNAUTHORIZED => {
            return Err("This code expired or was already used. Request a new code in Telegram.")
        }
        StatusCode::TOO_MANY_REQUESTS => return Err("Too many pairing attempts. Try again later."),
        _ => return Err(RELAY_ERROR),
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PAIR_REPLY_BYTES + 1));
    response
        .take(MAX_PAIR_REPLY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RELAY_ERROR)?;
    parse_pair_reply(&bytes)
}

pub(crate) fn pair(code: &str) -> Result<()> {
    let code = code.trim();
    if !is_url_safe_secret(code, CODE_LENGTH) {
        return Err(INVALID_CODE);
    }
    let _link_lock = crate::single_instance::try_lock_telegram_link().map_err(|_| LINK_BUSY)?;
    let entry = entry()?;
    if stored_token(&entry)?.is_some() {
        return Err("This computer is already linked. Disconnect it before pairing again.");
    }
    let response = post(PAIR_URL)?
        .json(&PairRequest { code })
        .send()
        .map_err(|_| RELAY_ERROR)?;
    let token = paired_token(response)?;
    if entry.set_secret(token.as_bytes()).is_err() {
        let _ = authenticated_post(UNLINK_URL, token.as_str());
        return Err(STORE_ERROR);
    }
    Ok(())
}

fn delete_token(entry: &Entry) -> Result<()> {
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(STORE_ERROR),
    }
}

pub(crate) fn unlink() -> Result<()> {
    let _link_lock = crate::single_instance::try_lock_telegram_link().map_err(|_| LINK_BUSY)?;
    let entry = entry()?;
    let Some(bytes) = stored_token(&entry)? else {
        return Ok(());
    };
    if let Some(token) = valid_token(&bytes) {
        match authenticated_post(UNLINK_URL, token)? {
            StatusCode::OK | StatusCode::UNAUTHORIZED => {}
            _ => return Err(RELAY_ERROR),
        }
    }
    delete_token(&entry)
}

pub(crate) fn pair_from_stdin() -> Result<()> {
    use std::io::IsTerminal;
    // Interactive terminals echo typed input. Settings provides masked entry.
    if std::io::stdin().is_terminal() {
        return Err("Pass the pairing code via standard input or enter it in Settings.");
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(CODE_LENGTH + 3));
    std::io::stdin()
        .lock()
        .take(CODE_LENGTH as u64 + 3)
        .read_to_end(&mut bytes)
        .map_err(|_| INVALID_CODE)?;
    if bytes.len() > CODE_LENGTH + 2 {
        return Err(INVALID_CODE);
    }
    pair(std::str::from_utf8(&bytes).map_err(|_| INVALID_CODE)?)
}

pub(crate) fn send_reminder(requested_at: Instant) -> Result<()> {
    let entry = entry()?;
    let bytes = stored_token(&entry)?.ok_or("Telegram notifications are disconnected.")?;
    let token = valid_token(&bytes)
        .ok_or("The saved Telegram link is invalid. Disconnect and pair again.")?;
    // Do not wake the phone late if macOS had to wait for Keychain access.
    if requested_at.elapsed() >= REQUEST_TIMEOUT {
        return Err("The reminder expired while accessing system secure storage.");
    }
    match authenticated_post(NOTIFY_URL, token)? {
        StatusCode::OK => Ok(()),
        StatusCode::TOO_MANY_REQUESTS => {
            Err("A reminder was sent recently. Try again in one minute.")
        }
        StatusCode::UNAUTHORIZED => {
            // Another process may have paired again while the request was in flight.
            if let Ok(_lock) = crate::single_instance::try_lock_telegram_link() {
                if stored_token(&entry)?.as_deref() == Some(&*bytes) {
                    delete_token(&entry)?;
                }
            }
            Err("This Telegram link has been revoked. Request a new code in Telegram.")
        }
        _ => Err(RELAY_ERROR),
    }
}

#[derive(Default)]
struct ReminderState {
    in_flight: bool,
    last_started: Option<Instant>,
}

impl ReminderState {
    fn start(&mut self, now: Instant) -> bool {
        if self.in_flight
            || self
                .last_started
                .is_some_and(|start| now.duration_since(start) < Duration::from_secs(60))
        {
            return false;
        }
        self.in_flight = true;
        self.last_started = Some(now);
        true
    }
}

pub(crate) fn schedule_reminder() {
    use std::sync::Mutex;
    static STATE: Mutex<ReminderState> = Mutex::new(ReminderState {
        in_flight: false,
        last_started: None,
    });
    let Ok(mut state) = STATE.try_lock() else {
        return;
    };
    let requested_at = Instant::now();
    if !state.start(requested_at) {
        return;
    }
    // Never queue a replay. A blocked system keychain or a slow relay occupies
    // at most one worker, independently of the credential and UI threads.
    if std::thread::Builder::new()
        .name("telegram-reminder".into())
        .spawn(move || {
            let _ = send_reminder(requested_at);
            if let Ok(mut state) = STATE.lock() {
                state.in_flight = false;
            }
        })
        .is_err()
    {
        state.in_flight = false;
        state.last_started = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_issued_code_and_token_formats() {
        assert!(is_url_safe_secret("Ab_cd-Ef90123456", CODE_LENGTH));
        for code in [
            "",
            "abcdefghijklmnopq",
            "abcdefghijklmno\n",
            "abcdefghijklmno/",
        ] {
            assert!(!is_url_safe_secret(code, CODE_LENGTH));
        }
        let bytes =
            serde_json::to_vec(&serde_json::json!({"device_token": "x".repeat(TOKEN_LENGTH)}))
                .unwrap();
        assert_eq!(parse_pair_reply(&bytes).unwrap().len(), TOKEN_LENGTH);
        assert!(parse_pair_reply(br#"{"device_token":"short"}"#).is_err());
        assert!(parse_pair_reply(&vec![b' '; MAX_PAIR_REPLY_BYTES + 1]).is_err());
    }

    #[test]
    fn reminder_request_contains_only_the_scoped_authorization_and_empty_json() {
        let request = authenticated_request(NOTIFY_URL, "test-device-token")
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.url().as_str(), NOTIFY_URL);
        assert_eq!(request.body().unwrap().as_bytes(), Some(&b"{}"[..]));
        let auth = &request.headers()[reqwest::header::AUTHORIZATION];
        assert!(auth.is_sensitive());
        assert_eq!(auth.as_bytes(), b"Bearer test-device-token");
    }

    #[test]
    fn drops_duplicates_and_bounds_in_flight_work() {
        let start = Instant::now();
        let mut state = ReminderState::default();
        assert!(state.start(start));
        assert!(!state.start(start + Duration::from_secs(90)));
        state.in_flight = false;
        assert!(!state.start(start + Duration::from_secs(59)));
        assert!(state.start(start + Duration::from_secs(60)));
    }
}

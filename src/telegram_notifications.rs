use keyring::Entry;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::CONTENT_TYPE;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const BOT_URL: &str = "https://t.me/windows_app_autologin_bot";
const PAIR_URL: &str = "https://obcardinal.com/windows-app-autologin/api/v1/pair";
const UNLINK_URL: &str = "https://obcardinal.com/windows-app-autologin/api/v1/unlink";
const NOTIFY_URL: &str = "https://obcardinal.com/windows-app-autologin/api/v1/notify";
const SERVICE: &str = "WindowsAppAutoLogin.Telegram";
const ACCOUNT: &str = "device-token";
const CODE_LENGTH: usize = 16;
const TOKEN_LENGTH: usize = 43;
const START_PAYLOAD_LENGTH: usize = 32;
const PAIR_TTL_SECONDS: u32 = 300;
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

fn stored_record(entry: &Entry) -> Result<Option<Zeroizing<Vec<u8>>>> {
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

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum LinkState {
    Unlinked,
    Pending { url: String },
    Linked,
    Expired,
}

// One Keychain item makes promotion atomic. Existing active items retain their
// original raw-token format. Pending items contain the validated start response.
enum SavedLink<'a> {
    Linked(&'a str),
    Pending(StartReply<'a>),
}

impl<'a> SavedLink<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if let Some(token) = valid_token(bytes) {
            return Ok(Self::Linked(token));
        }
        parse_start_reply(bytes).map(Self::Pending)
    }

    fn token(&self) -> &str {
        match self {
            Self::Linked(token) => token,
            Self::Pending(reply) => reply.device_token,
        }
    }
}

fn link_lock() -> Result<std::fs::File> {
    crate::single_instance::try_lock_telegram_link().map_err(|_| LINK_BUSY)
}

fn post(url: &'static str) -> Result<RequestBuilder> {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    let client = match CLIENT.get() {
        Some(client) => client,
        None => {
            let client = Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .no_proxy()
                .connect_timeout(Duration::from_secs(3))
                .build()
                .map_err(|_| RELAY_ERROR)?;
            CLIENT.get_or_init(|| client)
        }
    };
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
#[serde(deny_unknown_fields)]
struct PairReply<'a> {
    device_token: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartReply<'a> {
    device_token: &'a str,
    start_payload: &'a str,
    expires_in: u32,
}

impl StartReply<'_> {
    fn url(&self) -> String {
        format!("{BOT_URL}?start={}", self.start_payload)
    }
}

fn parse_start_reply(bytes: &[u8]) -> Result<StartReply<'_>> {
    if bytes.len() > MAX_PAIR_REPLY_BYTES {
        return Err(INVALID_REPLY);
    }
    let reply: StartReply<'_> = serde_json::from_slice(bytes).map_err(|_| INVALID_REPLY)?;
    if !is_url_safe_secret(reply.device_token, TOKEN_LENGTH)
        || !is_url_safe_secret(reply.start_payload, START_PAYLOAD_LENGTH)
        || reply.expires_in != PAIR_TTL_SECONDS
    {
        return Err(INVALID_REPLY);
    }
    Ok(reply)
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

fn read_reply(response: Response) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PAIR_REPLY_BYTES + 1));
    response
        .take(MAX_PAIR_REPLY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RELAY_ERROR)?;
    if bytes.len() > MAX_PAIR_REPLY_BYTES {
        return Err(INVALID_REPLY);
    }
    Ok(bytes)
}

fn paired_token(response: Response) -> Result<Zeroizing<String>> {
    match response.status() {
        StatusCode::OK => {}
        StatusCode::UNAUTHORIZED => {
            return Err(
                "This pairing code expired or was already used. Open Settings to link Telegram.",
            )
        }
        StatusCode::TOO_MANY_REQUESTS => return Err("Too many pairing attempts. Try again later."),
        _ => return Err(RELAY_ERROR),
    }
    parse_pair_reply(&read_reply(response)?)
}

enum PairAction<'a> {
    Start,
    Status(&'a str),
}

fn action_request(action: PairAction<'_>) -> Result<RequestBuilder> {
    let request = post(PAIR_URL)?.header(CONTENT_TYPE, "application/json");
    Ok(match action {
        PairAction::Start => request.body(r#"{"action":"start"}"#),
        PairAction::Status(token) => request.bearer_auth(token).body(r#"{"action":"status"}"#),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RemoteStatus {
    Pending,
    Linked,
    #[serde(skip)]
    Gone,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusReply {
    status: RemoteStatus,
}

fn remote_status(token: &str) -> Result<RemoteStatus> {
    let response = action_request(PairAction::Status(token))?
        .send()
        .map_err(|_| RELAY_ERROR)?;
    match response.status() {
        StatusCode::OK => {
            let reply: StatusReply =
                serde_json::from_slice(&read_reply(response)?).map_err(|_| INVALID_REPLY)?;
            Ok(reply.status)
        }
        StatusCode::GONE => Ok(RemoteStatus::Gone),
        StatusCode::TOO_MANY_REQUESTS => Err("Too many link checks. Try again later."),
        _ => Err(RELAY_ERROR),
    }
}

// Caller holds the link lock from reading the record through committing status.
// A local clock or an old link's deadline cannot invalidate a confirmed Start.
fn apply_status(entry: &Entry, link: &SavedLink<'_>, status: RemoteStatus) -> Result<LinkState> {
    match status {
        RemoteStatus::Pending => match link {
            SavedLink::Pending(reply) => Ok(LinkState::Pending { url: reply.url() }),
            SavedLink::Linked(_) => Err(INVALID_REPLY),
        },
        RemoteStatus::Linked => {
            if let SavedLink::Pending(reply) = link {
                entry
                    .set_secret(reply.device_token.as_bytes())
                    .map_err(|_| STORE_ERROR)?;
            }
            Ok(LinkState::Linked)
        }
        RemoteStatus::Gone => {
            delete_token(entry)?;
            Ok(LinkState::Expired)
        }
    }
}

fn current_state(entry: &Entry, check_active: bool) -> Result<LinkState> {
    let Some(bytes) = stored_record(entry)? else {
        return Ok(LinkState::Unlinked);
    };
    let link = SavedLink::parse(&bytes)?;
    if !check_active && matches!(link, SavedLink::Linked(_)) {
        return Ok(LinkState::Linked);
    }
    apply_status(entry, &link, remote_status(link.token())?)
}

pub(crate) fn link_state() -> Result<LinkState> {
    let _lock = link_lock()?;
    current_state(&entry()?, false)
}

pub(crate) fn refresh_link() -> Result<LinkState> {
    let _lock = link_lock()?;
    current_state(&entry()?, true)
}

pub(crate) fn begin_link() -> Result<LinkState> {
    let _lock = link_lock()?;
    let entry = entry()?;
    match current_state(&entry, false)? {
        LinkState::Expired | LinkState::Unlinked => {}
        current => return Ok(current),
    }
    let response = action_request(PairAction::Start)?
        .send()
        .map_err(|_| RELAY_ERROR)?;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::TOO_MANY_REQUESTS => return Err("Too many pairing attempts. Try again later."),
        _ => return Err(RELAY_ERROR),
    }
    let bytes = read_reply(response)?;
    let reply = parse_start_reply(&bytes)?;
    if entry.set_secret(&bytes).is_err() {
        let _ = authenticated_post(UNLINK_URL, reply.device_token);
        return Err(STORE_ERROR);
    }
    Ok(LinkState::Pending { url: reply.url() })
}

fn pair(code: &str) -> Result<()> {
    let code = code.trim();
    if !is_url_safe_secret(code, CODE_LENGTH) {
        return Err(INVALID_CODE);
    }
    let _link_lock = link_lock()?;
    let entry = entry()?;
    match current_state(&entry, false)? {
        LinkState::Linked => {
            return Err("This computer is already linked. Disconnect it before pairing again.")
        }
        LinkState::Pending { .. } => {
            return Err("This computer has a pending link. Finish or cancel it in Settings.")
        }
        LinkState::Unlinked | LinkState::Expired => {}
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

fn revoke(entry: &Entry, link: &SavedLink<'_>) -> Result<()> {
    match authenticated_post(UNLINK_URL, link.token())? {
        StatusCode::OK | StatusCode::UNAUTHORIZED | StatusCode::GONE => delete_token(entry),
        _ => Err(RELAY_ERROR),
    }
}

pub(crate) fn unlink() -> Result<()> {
    let _lock = link_lock()?;
    let entry = entry()?;
    let Some(bytes) = stored_record(&entry)? else {
        return Ok(());
    };
    match SavedLink::parse(&bytes) {
        Ok(link) => revoke(&entry, &link),
        Err(_) => delete_token(&entry),
    }
}

pub(crate) fn cancel_pending(expected_url: &str) -> Result<LinkState> {
    let _lock = link_lock()?;
    let entry = entry()?;
    cancel_saved_pending(&entry, expected_url)
}

fn cancel_saved_pending(entry: &Entry, expected_url: &str) -> Result<LinkState> {
    let Some(bytes) = stored_record(entry)? else {
        return Ok(LinkState::Unlinked);
    };
    let link = SavedLink::parse(&bytes)?;
    let SavedLink::Pending(reply) = &link else {
        return Ok(LinkState::Linked);
    };
    let url = reply.url();
    if url != expected_url {
        return Ok(LinkState::Pending { url });
    }
    revoke(entry, &link)?;
    Ok(LinkState::Unlinked)
}

pub(crate) fn pair_from_stdin() -> Result<()> {
    use std::io::IsTerminal;
    // Interactive terminals echo typed input. Settings can link via Telegram Start.
    if std::io::stdin().is_terminal() {
        return Err(
            "Pass a legacy pairing code via standard input or use Link Telegram in Settings.",
        );
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
    let bytes = stored_record(&entry)?.ok_or("Telegram notifications are disconnected.")?;
    let link = SavedLink::parse(&bytes)
        .map_err(|_| "The saved Telegram link is invalid. Disconnect and link again.")?;
    // Do not wake the phone late if macOS had to wait for Keychain access.
    if requested_at.elapsed() >= REQUEST_TIMEOUT {
        return Err("The reminder expired while accessing system secure storage.");
    }
    // Telegram can confirm Start while Settings is closed. Its bearer is
    // already usable for reminders even if Keychain still holds a pending item.
    match authenticated_post(NOTIFY_URL, link.token())? {
        StatusCode::OK => {
            if matches!(link, SavedLink::Pending(_)) {
                // The reminder already arrived. Reconciliation can also happen
                // on the next Settings check if a concurrent change holds the lock.
                let _ = update_if_current(&entry, &bytes, &link, RemoteStatus::Linked);
            }
            Ok(())
        }
        StatusCode::TOO_MANY_REQUESTS => {
            Err("A reminder was sent recently. Try again in one minute.")
        }
        StatusCode::UNAUTHORIZED if matches!(link, SavedLink::Pending(_)) => {
            // /notify rejects both an unclaimed Start and an expired link. Only
            // /pair status can tell them apart, including a concurrent redemption.
            let status = remote_status(link.token())?;
            let message = match status {
                RemoteStatus::Pending => {
                    return Err("Open Telegram and press Start to finish linking this computer.")
                }
                RemoteStatus::Linked => "Telegram was just linked. Try the reminder again.",
                RemoteStatus::Gone => "This Telegram link expired. Open Settings to link again.",
            };
            update_if_current(&entry, &bytes, &link, status)?;
            Err(message)
        }
        StatusCode::UNAUTHORIZED => {
            update_if_current(&entry, &bytes, &link, RemoteStatus::Gone)?;
            Err("This Telegram link has been revoked. Open Settings to link again.")
        }
        _ => Err(RELAY_ERROR),
    }
}

fn update_if_current(
    entry: &Entry,
    original: &[u8],
    link: &SavedLink<'_>,
    status: RemoteStatus,
) -> Result<()> {
    if let Ok(_lock) = link_lock() {
        apply_reminder_status(entry, original, link, status)?;
    }
    Ok(())
}

fn apply_reminder_status(
    entry: &Entry,
    original: &[u8],
    link: &SavedLink<'_>,
    status: RemoteStatus,
) -> Result<()> {
    if stored_record(entry)?.as_deref().map(Vec::as_slice) == Some(original) {
        apply_status(entry, link, status)?;
    }
    Ok(())
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

    fn start_fixture() -> serde_json::Value {
        serde_json::json!({
            "device_token": "d".repeat(TOKEN_LENGTH),
            "start_payload": "p".repeat(START_PAYLOAD_LENGTH),
            "expires_in": PAIR_TTL_SECONDS,
        })
    }

    fn mock_entry() -> Entry {
        Entry::new_with_credential(Box::<keyring::mock::MockCredential>::default())
    }

    #[test]
    fn start_and_status_only_use_the_pair_endpoint_and_scoped_credentials() {
        let start = action_request(PairAction::Start).unwrap().build().unwrap();
        let status = action_request(PairAction::Status("test-device-token"))
            .unwrap()
            .build()
            .unwrap();
        for request in [&start, &status] {
            assert_eq!(request.method(), reqwest::Method::POST);
            assert_eq!(request.url().as_str(), PAIR_URL);
            assert_eq!(request.headers()[CONTENT_TYPE], "application/json");
        }
        assert_eq!(
            start.body().unwrap().as_bytes(),
            Some(&br#"{"action":"start"}"#[..])
        );
        assert!(!start.headers().contains_key(reqwest::header::AUTHORIZATION));
        assert_eq!(
            status.body().unwrap().as_bytes(),
            Some(&br#"{"action":"status"}"#[..])
        );
        let auth = &status.headers()[reqwest::header::AUTHORIZATION];
        assert!(auth.is_sensitive());
        assert_eq!(auth.as_bytes(), b"Bearer test-device-token");
    }

    #[test]
    fn only_a_valid_start_payload_reaches_the_trusted_bot_url() {
        let bytes = serde_json::to_vec(&start_fixture()).unwrap();
        let reply = parse_start_reply(&bytes).unwrap();
        assert_eq!(
            reply.url(),
            format!(
                "https://t.me/windows_app_autologin_bot?start={}",
                "p".repeat(32)
            )
        );
        assert!(!reply.url().contains(reply.device_token));

        for (field, value) in [
            (
                "device_token",
                serde_json::json!("d".repeat(TOKEN_LENGTH - 1)),
            ),
            (
                "start_payload",
                serde_json::json!("p".repeat(START_PAYLOAD_LENGTH + 1)),
            ),
            (
                "start_payload",
                serde_json::json!(format!("{}&", "p".repeat(START_PAYLOAD_LENGTH - 1))),
            ),
            ("expires_in", serde_json::json!(0)),
            ("url", serde_json::json!("https://example.invalid/")),
        ] {
            let mut fixture = start_fixture();
            fixture[field] = value;
            assert!(parse_start_reply(&serde_json::to_vec(&fixture).unwrap()).is_err());
        }
        assert!(parse_start_reply(&vec![b' '; MAX_PAIR_REPLY_BYTES + 1]).is_err());
        assert!(serde_json::from_slice::<StatusReply>(br#"{"status":"unknown"}"#).is_err());
        assert!(serde_json::from_slice::<StatusReply>(br#"{"status":"gone"}"#).is_err());
        assert!(parse_pair_reply(&bytes).is_err());
    }

    #[test]
    fn confirmed_pending_records_promote_atomically_and_existing_tokens_stay_linked() {
        let entry = mock_entry();
        let bytes = serde_json::to_vec(&start_fixture()).unwrap();
        entry.set_secret(&bytes).unwrap();
        let saved = stored_record(&entry).unwrap().unwrap();
        let link = SavedLink::parse(&saved).unwrap();
        let pending = apply_status(&entry, &link, RemoteStatus::Pending).unwrap();
        assert!(matches!(pending, LinkState::Pending { .. }));
        assert_eq!(entry.get_secret().unwrap(), bytes);
        assert!(apply_status(&entry, &link, RemoteStatus::Linked).unwrap() == LinkState::Linked);
        assert_eq!(entry.get_secret().unwrap(), link.token().as_bytes());
        assert!(current_state(&entry, false).unwrap() == LinkState::Linked);

        let active = SavedLink::Linked(link.token());
        assert!(apply_status(&entry, &active, RemoteStatus::Pending).is_err());
        assert_eq!(entry.get_secret().unwrap(), link.token().as_bytes());
        assert!(apply_status(&entry, &active, RemoteStatus::Gone).unwrap() == LinkState::Expired);
        assert!(current_state(&entry, false).unwrap() == LinkState::Unlinked);
    }

    #[test]
    fn stale_reminders_and_cancel_actions_leave_the_replacement_link_intact() {
        let entry = mock_entry();
        let first = serde_json::to_vec(&start_fixture()).unwrap();
        let old = SavedLink::parse(&first).unwrap();
        let old_url = parse_start_reply(&first).unwrap().url();
        let mut replacement = start_fixture();
        replacement["start_payload"] = serde_json::json!("q".repeat(START_PAYLOAD_LENGTH));
        replacement["device_token"] = serde_json::json!("e".repeat(TOKEN_LENGTH));
        let second = serde_json::to_vec(&replacement).unwrap();
        entry.set_secret(&second).unwrap();

        apply_reminder_status(&entry, &first, &old, RemoteStatus::Linked).unwrap();
        apply_reminder_status(
            &entry,
            old.token().as_bytes(),
            &SavedLink::Linked(old.token()),
            RemoteStatus::Gone,
        )
        .unwrap();
        assert_eq!(entry.get_secret().unwrap(), second);
        let expected = parse_start_reply(&second).unwrap();
        assert!(
            cancel_saved_pending(&entry, &old_url).unwrap()
                == LinkState::Pending {
                    url: expected.url()
                }
        );
        assert_eq!(entry.get_secret().unwrap(), second);

        let new = SavedLink::parse(&second).unwrap();
        apply_reminder_status(&entry, &second, &new, RemoteStatus::Linked).unwrap();
        assert!(cancel_saved_pending(&entry, &old_url).unwrap() == LinkState::Linked);
        assert_eq!(entry.get_secret().unwrap(), new.token().as_bytes());
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

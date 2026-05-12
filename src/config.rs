#[derive(Debug, Clone)]
pub struct Config {
    pub reconnect_delay_secs: u64,

    pub macos_app_name: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CredentialsConfig {
    pub username: String,
    pub prompt_window_title: Option<String>,
    pub prompt_process_id: Option<i32>,
}

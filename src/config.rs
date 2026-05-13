pub const TARGET_APP_NAME: &str = "Windows App";

#[derive(Debug, Clone)]
pub struct Config {
    pub macos_app_name: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CredentialsConfig {
    pub username: String,
    pub prompt_window_title: Option<String>,
    pub prompt_process_id: Option<i32>,
}

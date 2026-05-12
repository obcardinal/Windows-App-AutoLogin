use crate::config::Config;
#[cfg(target_os = "macos")]
use crate::macos_identity;
#[cfg(target_os = "macos")]
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{debug, info, warn};

pub(crate) struct ReconnectHandler {
    config: Arc<Config>,
}

impl ReconnectHandler {
    pub(crate) fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    pub(crate) fn reconnect_guarded(
        &self,
        guard: impl Fn() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        self.reconnect_sequence(true, &guard)
    }

    pub(crate) fn restart_guarded(
        &self,
        guard: impl Fn() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        self.reconnect_sequence(false, &guard)
    }

    fn reconnect_sequence(
        &self,
        close_dialogs: bool,
        guard: &dyn Fn() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        info!("Starting reconnection sequence...");
        guard()?;

        #[cfg(target_os = "macos")]
        if close_dialogs {
            if let Err(e) = self.close_disconnect_dialogs() {
                warn!("Disconnect dialog close skipped: {}", e);
            }
            guard()?;
        }

        #[cfg(target_os = "macos")]
        self.kill_existing_processes()?;
        guard()?;

        let deadline =
            std::time::Instant::now() + Duration::from_secs(self.config.reconnect_delay_secs);
        while std::time::Instant::now() < deadline {
            guard()?;
            thread::sleep(Duration::from_millis(100));
        }
        guard()?;

        self.open_configured_app()?;

        info!("Reconnection sequence completed");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn click_reconnect_button(&self) -> anyhow::Result<()> {
        let trusted_pids = self.trusted_target_pids()?;
        if trusted_pids.is_empty() {
            anyhow::bail!("No trusted Microsoft Windows App process is running");
        }
        let trusted_pids = macos_identity::applescript_pid_list_literal(&trusted_pids);
        let app_name = Self::applescript_string_literal(&self.config.macos_app_name);
        let script = format!(
            r#"
on processMatches(procRef, expectedName, trustedPIDs)
    tell application "System Events"
        try
            if (name of procRef as string) is not expectedName then return false
            set procPID to unix id of procRef as string
            repeat with trustedPID in trustedPIDs
                if procPID is (trustedPID as string) then return true
            end repeat
            return false
        on error
            return false
        end try
    end tell
end processMatches

on reconnectButtonNameMatches(buttonName)
    ignoring case
        if buttonName contains "Reconnect" then return true
        if buttonName contains "Retry" then return true
        if buttonName contains "Try Again" then return true
        if buttonName contains "Try again" then return true
        if buttonName contains "Повтор" then return true
    end ignoring
    return false
end reconnectButtonNameMatches

on disconnectContextMatches(containerRef, baseText)
    set contextText to baseText
    tell application "System Events"
        tell containerRef
            try
                repeat with t in (every static text)
                    try
                        set contextText to contextText & " " & (name of t as string)
                    end try
                    try
                        set contextText to contextText & " " & (value of t as string)
                    end try
                end repeat
            end try
        end tell
    end tell
    ignoring case
        if contextText contains "Disconnected" then return true
        if contextText contains "Connection lost" then return true
        if contextText contains "Unable to connect" then return true
        if contextText contains "Reconnect" then return true
        if contextText contains "Retry" then return true
        if contextText contains "Отключ" then return true
        if contextText contains "Повтор" then return true
    end ignoring
    return false
end disconnectContextMatches

on clickMatchingReconnectButton(buttonList)
    tell application "System Events"
        repeat with b in buttonList
            try
                set buttonName to name of b as string
                if my reconnectButtonNameMatches(buttonName) then
                    click b
                    return "clicked:" & buttonName
                end if
            end try
        end repeat
    end tell
    return ""
end clickMatchingReconnectButton

tell application "System Events"
    set expectedName to {}
    set trustedPIDs to {}
    set procList to every application process whose name is expectedName
    repeat with procRef in procList
        if my processMatches(procRef, expectedName, trustedPIDs) then
        repeat with w in every window of procRef
            set wName to name of w as string
            try
                if exists sheet 1 of w then
                    set s to sheet 1 of w
                    if my disconnectContextMatches(s, wName) then
                        set clickedButton to my clickMatchingReconnectButton(every button of s)
                        if clickedButton is not "" then return clickedButton
                    end if
                end if
            end try
            try
                if my disconnectContextMatches(w, wName) then
                    set clickedButton to my clickMatchingReconnectButton(every button of w)
                    if clickedButton is not "" then return clickedButton
                end if
            end try
        end repeat
        end if
    end repeat
end tell
"#,
            app_name, trusted_pids
        );
        let output = Self::run_osascript(&script)?;

        if output.status.success() && !String::from_utf8_lossy(&output.stdout).trim().is_empty() {
            info!("Clicked Reconnect button in {} via AppleScript", app_name);
            Ok(())
        } else {
            anyhow::bail!(
                "Reconnect button not found in {}: {}",
                self.config.macos_app_name,
                Self::redacted_stderr(&output.stderr)
            )
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn close_disconnect_dialogs(&self) -> anyhow::Result<()> {
        let trusted_pids = self.trusted_target_pids()?;
        if trusted_pids.is_empty() {
            anyhow::bail!("No trusted Microsoft Windows App process is running");
        }
        let trusted_pids = macos_identity::applescript_pid_list_literal(&trusted_pids);
        let app_name = Self::applescript_string_literal(&self.config.macos_app_name);
        let script = format!(
            r#"
on processMatches(procRef, expectedName, trustedPIDs)
    tell application "System Events"
        try
            if (name of procRef as string) is not expectedName then return false
            set procPID to unix id of procRef as string
            repeat with trustedPID in trustedPIDs
                if procPID is (trustedPID as string) then return true
            end repeat
            return false
        on error
            return false
        end try
    end tell
end processMatches

on disconnectContextMatches(containerRef, baseText)
    set contextText to baseText
    tell application "System Events"
        tell containerRef
            try
                repeat with t in (every static text)
                    try
                        set contextText to contextText & " " & (name of t as string)
                    end try
                    try
                        set contextText to contextText & " " & (value of t as string)
                    end try
                end repeat
            end try
        end tell
    end tell
    ignoring case
        if contextText contains "Disconnected" then return true
        if contextText contains "Connection lost" then return true
        if contextText contains "Unable to connect" then return true
        if contextText contains "Reconnect" then return true
        if contextText contains "Retry" then return true
        if contextText contains "Отключ" then return true
        if contextText contains "Повтор" then return true
    end ignoring
    return false
end disconnectContextMatches

tell application "System Events"
    try
        set expectedName to {}
        set trustedPIDs to {}
        set buttonNames to {{"OK", "Close", "Dismiss"}}
        set procList to every application process whose name is expectedName
        repeat with procRef in procList
            if my processMatches(procRef, expectedName, trustedPIDs) then
            repeat with w in every window of procRef
                set wName to name of w as string
                repeat with buttonName in buttonNames
                    try
                        if exists sheet 1 of w then
                            set s to sheet 1 of w
                            if my disconnectContextMatches(s, wName) then
                                if exists (button (buttonName as string) of s) then
                                    click button (buttonName as string) of s
                                    return "clicked"
                                end if
                            end if
                        end if
                    end try
                    try
                        if my disconnectContextMatches(w, wName) and exists (button (buttonName as string) of w) then
                            click button (buttonName as string) of w
                            return "clicked"
                        end if
                    end try
                end repeat
            end repeat
            end if
        end repeat
    end try
    return "not_found"
end tell
"#,
            app_name, trusted_pids
        );
        let output = Self::run_osascript(&script)?;
        if !output.status.success() {
            anyhow::bail!(
                "Disconnect dialog close failed: {}",
                Self::redacted_stderr(&output.stderr)
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("clicked") {
            info!("Closed disconnect dialog via AppleScript");
        } else {
            info!("No disconnect dialog button found");
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn applescript_string_literal(value: &str) -> String {
        let escaped = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace(['\r', '\n'], " ");
        format!("\"{}\"", escaped)
    }

    #[cfg(target_os = "macos")]
    fn run_osascript(script: &str) -> anyhow::Result<std::process::Output> {
        use std::thread;
        use std::time::{Duration, Instant};

        let mut child = Command::new("/usr/bin/osascript")
            .args(["-e", script])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let started = Instant::now();
        loop {
            if child.try_wait()?.is_some() {
                return Ok(child.wait_with_output()?);
            }

            if started.elapsed() >= Duration::from_secs(5) {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("osascript timed out");
            }

            thread::sleep(Duration::from_millis(25));
        }
    }

    #[cfg(target_os = "macos")]
    fn redacted_stderr(stderr: &[u8]) -> &'static str {
        if stderr.is_empty() {
            "no stderr"
        } else {
            "redacted stderr"
        }
    }

    #[cfg(target_os = "macos")]
    fn run_command_with_timeout(mut command: Command, timeout: Duration) -> anyhow::Result<Output> {
        use std::thread;
        use std::time::Instant;

        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let started = Instant::now();
        loop {
            if child.try_wait()?.is_some() {
                return Ok(child.wait_with_output()?);
            }

            if started.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("command timed out");
            }

            thread::sleep(Duration::from_millis(25));
        }
    }

    #[cfg(target_os = "macos")]
    fn open_configured_app(&self) -> anyhow::Result<()> {
        info!("Opening {}", self.config.macos_app_name);
        let mut command = Command::new("/usr/bin/open");
        if let Some(bundle_path) = macos_identity::trusted_bundle_path(&self.config.macos_app_name)?
        {
            command.arg("-g").arg(bundle_path);
        } else {
            anyhow::bail!("Trusted Microsoft Windows App bundle was not found");
        }
        let output = Self::run_command_with_timeout(command, Duration::from_secs(5))?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to open {}: {}",
                self.config.macos_app_name,
                Self::redacted_stderr(&output.stderr)
            );
        }

        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    fn open_configured_app(&self) -> anyhow::Result<()> {
        debug!(
            "Open configured app stub on unsupported platform: {}",
            self.config.macos_app_name
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn kill_existing_processes(&self) -> anyhow::Result<()> {
        let app_name = &self.config.macos_app_name;
        let pids = self.trusted_target_pids()?;
        if pids.is_empty() {
            debug!("No verified '{}' process to terminate", app_name);
            return Ok(());
        }

        for pid in pids {
            if !self.trusted_target_pids()?.contains(&pid) {
                debug!("Verified target process changed before termination; skipping stale pid");
                continue;
            }
            let mut command = Command::new("/bin/kill");
            command.arg(pid.to_string());
            let output = Self::run_command_with_timeout(command, Duration::from_secs(2))?;
            if output.status.success() {
                info!("Terminated verified target process");
            } else {
                debug!(
                    "Verified target process termination skipped: {}",
                    Self::redacted_stderr(&output.stderr)
                );
            }
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn trusted_target_pids(&self) -> anyhow::Result<Vec<i32>> {
        macos_identity::trusted_process_ids(&self.config.macos_app_name)
    }

    #[cfg(not(target_os = "macos"))]
    pub(crate) fn click_reconnect_button(&self) -> anyhow::Result<()> {
        anyhow::bail!("Reconnect button handling is only supported on macOS")
    }
}

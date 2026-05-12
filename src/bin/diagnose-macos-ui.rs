use std::io::Write;

fn main() {
    let report = windows_app_autologin::diagnose::run().unwrap_or_else(|e| {
        eprintln!("Diagnostic failed: {}", e);
        std::process::exit(1);
    });

    let json = serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
        eprintln!("Failed to serialize report: {}", e);
        std::process::exit(1);
    });

    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(json.as_bytes());
    let _ = stdout.write_all(b"\n");
}

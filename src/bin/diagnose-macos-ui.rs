use std::io::Write;

fn main() {
    let report = windows_app_autologin::diagnose::run().unwrap_or_else(|e| {
        eprintln!("Diagnostic failed: {}", e);
        std::process::exit(1);
    });

    let json = windows_app_autologin::diagnose::diagnostic_report_to_capped_pretty_json(&report)
        .unwrap_or_else(|e| {
            eprintln!("Failed to serialize report: {}", e);
            std::process::exit(1);
        });

    let mut stdout = std::io::stdout().lock();
    if let Err(e) = stdout
        .write_all(json.as_bytes())
        .and_then(|_| stdout.write_all(b"\n"))
    {
        eprintln!("Failed to write diagnostic report: {}", e.kind());
        std::process::exit(1);
    }
}

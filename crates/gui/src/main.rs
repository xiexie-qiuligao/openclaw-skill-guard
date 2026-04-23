use std::path::PathBuf;

use openclaw_skill_guard_gui::{
    load_completed_scan_from_json, run_gui, run_gui_with_state, OpenClawGuardApp, UiTab,
};

fn parse_demo_tab(value: &str) -> Result<UiTab, String> {
    match value {
        "summary" => Ok(UiTab::Summary),
        "findings" => Ok(UiTab::Findings),
        "context" => Ok(UiTab::Context),
        "paths" => Ok(UiTab::Paths),
        "validation" => Ok(UiTab::Validation),
        "audit" => Ok(UiTab::Audit),
        "raw-json" => Ok(UiTab::RawJson),
        other => Err(format!(
            "unsupported demo tab: {other}. expected one of summary, findings, context, paths, validation, audit, raw-json"
        )),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut smoke_test = false;
    let mut demo_report: Option<PathBuf> = None;
    let mut demo_tab = UiTab::Summary;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--smoke-test" => smoke_test = true,
            "--demo-report" => {
                let Some(value) = args.next() else {
                    eprintln!("missing value for --demo-report");
                    std::process::exit(2);
                };
                demo_report = Some(PathBuf::from(value));
            }
            "--tab" => {
                let Some(value) = args.next() else {
                    eprintln!("missing value for --tab");
                    std::process::exit(2);
                };
                match parse_demo_tab(&value) {
                    Ok(tab) => demo_tab = tab,
                    Err(err) => {
                        eprintln!("{err}");
                        std::process::exit(2);
                    }
                }
            }
            _ => {}
        }
    }

    if smoke_test {
        let _ = OpenClawGuardApp::default();
        println!("openclaw-skill-guard-gui smoke test ok");
        return;
    }

    let result = if let Some(path) = demo_report {
        match load_completed_scan_from_json(&path) {
            Ok(scan) => run_gui_with_state(Some(scan), demo_tab),
            Err(err) => Err(err),
        }
    } else {
        run_gui()
    };

    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

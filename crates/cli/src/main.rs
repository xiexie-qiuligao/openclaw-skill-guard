use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use openclaw_skill_guard_core::Verdict;
use openclaw_skill_guard_core::{scan_path_with_options, ValidationExecutionMode};
use openclaw_skill_guard_report::{render_html, render_json, render_markdown, render_sarif};

#[derive(Debug, Parser)]
#[command(name = "openclaw-skill-guard")]
#[command(
    about = "OpenClaw-aware skill verifier CLI",
    long_about = "Scan OpenClaw skills, skill directories, or broader roots and emit a canonical JSON security report. The verifier combines baseline pattern scanning, structured OpenClaw context analysis, attack-path reasoning, runtime-aware refinement, and auditable suppression handling.",
    after_help = "Exit codes: 0=allow, 2=warn, 3=block, 1=runtime or input error."
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Scan a file or directory and emit a security report")]
    Scan {
        #[arg(help = "Path to a SKILL.md file, skill directory, skills root, or workspace")]
        path: PathBuf,
        #[arg(
            long,
            value_enum,
            default_value = "json",
            help = "Output format. JSON remains canonical; SARIF, Markdown, and HTML are derived exports."
        )]
        format: OutputFormat,
        #[arg(
            long,
            help = "Optional JSON suppression file. Suppressed items remain visible in audit output."
        )]
        suppressions: Option<PathBuf>,
        #[arg(
            long,
            help = "Optional runtime manifest in JSON or YAML used for guarded runtime refinement."
        )]
        runtime_manifest: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value = "planned",
            help = "Validation mode. `planned` keeps recommendation-only validation; `guarded` applies safe runtime-backed checks without executing untrusted code."
        )]
        validation_mode: CliValidationMode,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Json,
    Sarif,
    Markdown,
    Html,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliValidationMode {
    Planned,
    Guarded,
}

fn main() {
    let args = Args::parse();
    let exit_code = match run(args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            1
        }
    };
    std::process::exit(exit_code);
}

fn run(args: Args) -> Result<i32, String> {
    match args.command {
        Command::Scan {
            path,
            format,
            suppressions,
            runtime_manifest,
            validation_mode,
        } => {
            let report = scan_path_with_options(
                &path,
                suppressions.as_deref(),
                runtime_manifest.as_deref(),
                match validation_mode {
                    CliValidationMode::Planned => ValidationExecutionMode::Planned,
                    CliValidationMode::Guarded => ValidationExecutionMode::Guarded,
                },
            )
            .map_err(|err| err.to_string())?;
            match format {
                OutputFormat::Json => {
                    let output = render_json(&report).map_err(|err| err.to_string())?;
                    println!("{output}");
                }
                OutputFormat::Sarif => {
                    let output = render_sarif(&report).map_err(|err| err.to_string())?;
                    println!("{output}");
                }
                OutputFormat::Markdown => {
                    let output = render_markdown(&report);
                    println!("{output}");
                }
                OutputFormat::Html => {
                    let output = render_html(&report);
                    println!("{output}");
                }
            }

            let code = match report.verdict {
                Verdict::Allow => 0,
                Verdict::Warn => 2,
                Verdict::Block => 3,
            };

            Ok(code)
        }
    }
}

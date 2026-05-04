use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use openclaw_skill_guard_core::input_resolver::ScanTargetOptions;
use openclaw_skill_guard_core::Verdict;
use openclaw_skill_guard_core::{scan_target_with_options, ValidationExecutionMode};
use openclaw_skill_guard_report::{render_html, render_json, render_markdown, render_sarif};

#[derive(Debug, Parser)]
#[command(name = "agent-skill-guard")]
#[command(
    about = "中文优先的 Agent Skill 安全验证 CLI",
    long_about = "扫描本地 OpenClaw skill、skill 目录、skills 根目录或 HTTPS skill 链接，并输出 canonical JSON、SARIF、Markdown 或 HTML 报告。验证器复用 evidence-driven 主链，不执行远程代码、不安装依赖、不启动 MCP server。",
    after_help = "退出码：0=允许，2=警告，3=阻断，1=运行时或输入错误。"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "扫描本地路径或 HTTPS skill 链接并输出安全报告")]
    Scan {
        #[arg(help = "本地路径或 HTTPS skill 链接")]
        target: String,
        #[arg(
            long,
            value_enum,
            default_value = "json",
            help = "输出格式。JSON 是 canonical report；SARIF、Markdown、HTML 都从同一报告派生。"
        )]
        format: OutputFormat,
        #[arg(
            long,
            help = "可选 suppression JSON 文件；被抑制项仍会保留审计可见性。"
        )]
        suppressions: Option<PathBuf>,
        #[arg(
            long,
            help = "可选运行时 manifest（JSON 或 YAML），用于 guarded runtime refinement。"
        )]
        runtime_manifest: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value = "planned",
            help = "验证模式。planned 只生成验证建议；guarded 只执行安全的本地检查，不执行不可信代码。"
        )]
        validation_mode: CliValidationMode,
        #[arg(long, value_enum, default_value = "zh-cn", help = "人类可读输出语言")]
        lang: CliLanguage,
        #[arg(long, help = "禁止远程 skill 链接输入")]
        no_network: bool,
        #[arg(long, help = "远程 skill 链接缓存目录；默认使用临时目录")]
        remote_cache_dir: Option<PathBuf>,
        #[arg(long, help = "策略配置文件，例如 .openclaw-guard.yml")]
        config: Option<PathBuf>,
        #[arg(long, help = "CI 模式：按策略结果输出稳定退出码")]
        ci: bool,
        #[arg(long, help = "启用通用 Agent / MCP / prompt package 生态解析")]
        agent_ecosystem: bool,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliLanguage {
    ZhCn,
    EnUs,
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
            target,
            format,
            suppressions,
            runtime_manifest,
            validation_mode,
            lang: _lang,
            no_network,
            remote_cache_dir,
            config,
            ci,
            agent_ecosystem,
        } => {
            let report = scan_target_with_options(
                &target,
                ScanTargetOptions {
                    suppression_path: suppressions,
                    runtime_manifest_path: runtime_manifest,
                    validation_mode: match validation_mode {
                        CliValidationMode::Planned => ValidationExecutionMode::Planned,
                        CliValidationMode::Guarded => ValidationExecutionMode::Guarded,
                    },
                    policy_path: config,
                    ci_mode: ci,
                    no_network,
                    remote_cache_dir,
                    agent_ecosystem,
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

            if ci {
                eprintln!(
                    "策略结果：{}",
                    if report.policy_evaluation.blocked {
                        &report.policy_evaluation.reason_zh
                    } else {
                        "通过"
                    }
                );
            }

            let code = if ci && report.policy_evaluation.blocked {
                3
            } else {
                match report.verdict {
                    Verdict::Allow => 0,
                    Verdict::Warn => 2,
                    Verdict::Block => 3,
                }
            };

            Ok(code)
        }
    }
}

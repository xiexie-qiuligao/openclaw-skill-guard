pub fn safe_target_label_zh(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let parts = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    match parts.as_slice() {
        [] => "未命名目标".to_string(),
        [one] => (*one).to_string(),
        _ => parts[parts.len().saturating_sub(2)..].join("/"),
    }
}

pub fn display_text_zh(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return "无可展示内容。".to_string();
    }

    let shared = agent_skill_guard_core::localization::zh_text(trimmed);
    if shared != trimmed {
        return shared;
    }

    let exact = match trimmed {
        "No findings." => Some("未发现需要展示的风险项。"),
        "No attack paths." => Some("未形成达到阈值的攻击路径。"),
        "No external references." => Some("未发现外部引用。"),
        "No dependency findings." => Some("未发现依赖审计问题。"),
        "No supported dependency manifests were discovered." => {
            Some("未发现当前版本支持的依赖清单文件。")
        }
        "No runtime manifest supplied; runtime refinement is based on safe local defaults and unknowns remain explicit." => {
            Some("未提供运行时 manifest；本次只使用安全的本地默认值，未知项会保留为显式假设。")
        }
        "No attack path met the current evidence threshold, but isolated findings may still require review." => {
            Some("没有攻击路径达到当前证据阈值，但孤立发现项仍建议复核。")
        }
        "No offline source identity mismatch signals were detected." => {
            Some("未发现离线来源身份不一致信号。")
        }
        "No OpenClaw config/control-plane risk signals were detected." => {
            Some("未发现 OpenClaw 配置或控制面风险信号。")
        }
        "No companion-document indirect instruction signals were detected." => {
            Some("未发现配套文档中的间接指令风险信号。")
        }
        _ => None,
    };
    if let Some(text) = exact {
        return text.to_string();
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("openclaw skill config may contain a plaintext apikey binding") {
        return "OpenClaw skill 配置可能包含明文 apiKey 绑定。".to_string();
    }
    if lower.contains("inline openclaw_config_secret pattern detected") {
        return "检测到 OpenClaw 配置密钥相关模式。".to_string();
    }
    if lower.contains("remote download piped into shell") {
        return "远程下载内容被直接传入 shell，存在供应链与执行链风险。".to_string();
    }
    if lower.contains("trusted-looking identity narrative conflicts with weak source evidence") {
        return "可信身份叙事与实际来源证据不一致，需要人工确认来源。".to_string();
    }
    if lower.contains("guarded validation collected") {
        return "受保护运行时验证已收集能力与假设检查，并在不执行不可信代码的前提下更新判断。"
            .to_string();
    }
    if lower.contains("execution surface is host") {
        return "影响评估显示该 skill 更接近宿主机执行面；文件系统、凭据、网络或持久化影响需要重点复核。".to_string();
    }
    if lower.contains("runtime validation refined host-vs-sandbox split") {
        return "运行时验证已结合 manifest 权限与环境事实更新宿主机 / 沙箱影响判断。".to_string();
    }
    if lower.contains("threat corpus") {
        return "威胁模式库已参与分析；如有命中，会给出来源与解释。".to_string();
    }
    if lower.contains("sensitive") && lower.contains("corpus") {
        return "敏感数据模式库已参与分析；如有命中，会区分真实风险与示例误报风险。".to_string();
    }
    if lower.contains("dependency") && lower.contains("audit") {
        return "依赖审计已检查依赖清单、版本固定、远程来源与安装链拉取风险。".to_string();
    }
    if lower.contains("api classification") {
        return "API / URL 分类已检查外部服务、源码、原始内容、下载与认证端点。".to_string();
    }
    if lower.contains("source reputation") {
        return "来源信誉摘要基于离线规则、URL 模式与本地种子给出可解释提示。".to_string();
    }
    if lower.contains("config") && lower.contains("control") {
        return "OpenClaw 配置 / 控制面审计已检查 env、apiKey、extraDirs、sandbox 与 unsafe 配置线索。".to_string();
    }
    if lower.contains("capability") {
        return "能力 / 权限视图已汇总声明能力、推断能力、必要能力与不一致信号。".to_string();
    }
    if lower.contains("companion") || lower.contains("indirect instruction") {
        return "配套文档审计已检查 README、docs、examples 中的间接指令和叙事错位风险。"
            .to_string();
    }
    if lower.contains("source identity") || lower.contains("identity mismatch") {
        return "来源身份一致性审计已离线比较名称、主页、仓库、安装来源与官方叙事。".to_string();
    }

    trimmed.to_string()
}

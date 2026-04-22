/// 辅助函数：验证 locale 参数
pub fn validate_locale(locale: &str) -> &str {
    match locale {
        "zh" | "en" => locale,
        _ => "zh", // 默认使用中文
    }
}

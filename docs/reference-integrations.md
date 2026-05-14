# 外部机制吸收与复用边界

Agent Skill Guard 可以学习优秀 skill / agent / MCP 安全扫描器的机制，但默认不把外部产品整包搬进来，也不引入云端判定、在线信誉或危险动态执行。

## 已吸收的机制

| 来源 | 许可证/形态 | 本项目吸收内容 | 是否复制代码 |
| --- | --- | --- | --- |
| Cisco AI Defense skill-scanner | Apache-2.0 | 多引擎分层、best-effort 边界、false-positive filtering、CI/SARIF 口径 | 否，仅机制改写 |
| Snyk Agent Scan / Skill Inspector | Apache-2.0 / 公开资料 | issue taxonomy、真实生态 benchmark、MCP / skill / prompt package 风险分类、toxic flow 思路 | 否，仅机制改写 |
| MCPShield | MIT / 公开资料 | hidden Unicode、tool poisoning、schema injection、credential harvesting、command/data exfiltration 风险面 | 否，仅机制改写 |
| MCP Scanner / MCP 安全公开资料 | 公开资料 | tool shadowing、cross-tool escalation、rug-pull/hash baseline 风险面 | 否，仅机制改写 |

## 复用准入规则

- 只允许 MIT、Apache-2.0、BSD 等兼容许可证代码进入仓库。
- 如果未来复制外部代码，必须保留来源、许可证和 NOTICE 记录，并添加测试。
- GPL、闭源、未知许可证、云 API 绑定、在线信誉平台、live MCP server 执行器默认不进入主线。
- 外部规则只能进入 corpus / matcher / benchmark / taxonomy / report 解释层，不替换 Rust verifier 主链。

## 当前落地范围

- MCP 静态分析新增 tool shadowing 与 schema field poisoning issue code。
- Hidden instruction 检测扩展到变体选择符、异常空白、金融操作、系统持久化、第三方内容暴露。
- Benchmark matrix 用于校准正常安装、MCP 高风险、语义高影响和误报保护样本。
- 产品仍保持本地、离线、中文优先、可解释；不执行远程代码，不启动 MCP server，不调用云端 LLM。

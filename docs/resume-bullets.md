# 简历写法（PoCVerify 2.0）

> 数字请按实际运行结果填写；下面的测试数量（188）是仓库当前的真实值。

## 项目条目

**PoCVerify 2.0：PoC 全生命周期工具链（lint → gate → run → report）｜独立开发**

- 在原有 YAML 动态验证器前增加静态门禁：基于 PyYAML 节点树实现 YAML 路径 → 行号定位，设计 6 类规则（元数据契约、身份/CVE 一致性、危险协议、破坏性 payload、弱匹配、跨文件重复指纹），输出精确到 `file:line` 的 finding。
- 高风险模板默认拒绝执行，需显式 `--allow-unsafe` 放行；支持 glob 豁免且强制填写 reason，未命中豁免会被报告，`--strict-waivers` 下直接失败。
- 兼容原生与 Nuclei 两套方言（`http:`/`raw:`/`payloads:`/协议块，旧版 `match_*` 字段仍可加载），共享同一套解析模型，lint 与 runner 不重复解析 YAML。
- 输出 SARIF 2.1.0 接入 GitHub Code Scanning（含 suppression），统一 Markdown 证据报告；188 个 pytest 用例、本地 mock 靶场，CI 离线可跑，Linux/Windows 双平台矩阵。

## 面试时讲三个问题

1. **为什么先静态、后动态**
   不把陌生人写的模板直接跑在扫描机上。静态筛掉危险协议、破坏性 payload、重复模板和弱匹配，只把“值得跑”的交给运行器；运行器对未通过门禁的模板默认拒绝，而不是提示后继续。

2. **为什么不用 `nuclei -validate`**
   `-validate` 回答“模板能不能加载”；本项目回答“该不该合并、该不该运行”。两者不冲突，前者是语法检查，后者是质量与安全门禁。

3. **最难的地方**
   YAML 行号映射（`yaml.compose` 节点树 + 缺失字段回退到父节点）、跨文件指纹归一化（让 `/admin` 与 `{{BaseURL}}/admin` 判为同一端点）、以及误报控制：每条规则都配“好模板不能报”的反例，这比多写规则更能体现工程判断。

## 两个项目怎么并排讲

- **PoCVerify**：一条 PoC 从“写出来”到“敢跑”的完整链路，重点是信任边界与工程化。
- 原有的批量验证能力现在是链路的后半段，不再是“一个 requests 循环”。

一句话总结：

> PoCVerify 解决“PoC 跑不跑得通”，也解决“PoC 值不值得跑、安不安全、是不是重复造轮子”。

## 发布前检查

- 把 `github.com/xiangfuhua/poc-verify` 设为公开，确认 README 的 demo 图能正常显示。
- 仓库 topics 建议：`security`、`poc`、`nuclei`、`static-analysis`、`sarif`、`devsecops`。
- 打 tag `v2.0.0`，Release notes 直接引用 `CHANGELOG.md`。
- 简历里的电话、邮箱、求职岗位仍是占位符，投递前替换。

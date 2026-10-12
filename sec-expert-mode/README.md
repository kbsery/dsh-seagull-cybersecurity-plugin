# 网安专家模式 · sec-expert-mode

DSH 的网络安全作业插件（Host 编排工具 + Client 状态条）与其校验套件。

## 三个文件

| 文件 | 作用 |
| --- | --- |
| `plugin/index.js` | Host 半边：注册 4 个 `sec_` 工具、注入作业面提示词节、挂非破坏性守卫 |
| `plugin/client.js` | Client 半边：composer 下方的舰队状态条（走 `conversation.composer.dock` 槽位） |
| `plugin/cordis.patch.yml` | bundle 的 loader patch：一行 insert，把 Host 半边挂到 host 平面 |

## 四个工具

| 工具 | 阶段 | 职责 |
| --- | --- | --- |
| `sec_recon_plan` | 一 · 测绘 | 生成侦察 Agent 作业面。**不分配攻击 Agent**——分工必须来自事实 |
| `sec_recon_fanout` | 二 · 扇出 | 按侦察交回的 `surfaces[]` 生成攻击 Agent 编制，只为可达面派人 |
| `sec_http_probe` | 取证 | 原始请求/响应采集；`pair: true` 提供抖动对照组 |
| `sec_payload_forge` | 变形 | parser-diff 所需的编码/同形/承载变体，含 JWT 拆解 |

前两个是**编排**，后两个是**实战**。没有后两个，本模式只能规划不能取证。

## 安装

已装进 `desktop` profile（`~/.dsh/profiles/desktop`）：

```jsonc
// package.json
"dependencies": { "dsh-sec-expert-mode": "link:C:/Users/杨科斌/Desktop/sec-expert-mode/plugin" },
"dsh": { "profile": { "bundles": ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-web-app", "dsh-sec-expert-mode"] } }
```

**必须重启 dsh 才生效。** bundle 的 patch 行只在 Host 启动时随 profile 层组合；
运行中热装不会 reconcile（`readProfilePatches` 优先用启动快照里的 `patches`），
所以 `install_bundle` 返回 `applied` 也不代表这行进了 loader 树。

重启后自检：工具目录里应出现 4 个 `sec_` 工具。

## 校验

```powershell
# 1. 插件契约（125 项）：注册形状、参数校验、guard、真实 HTTP 探测、载荷变形
node verify.mjs

# 2. 真实 cordis 装配（21 项）：真注册表 + 真提示词装配
copy boot-test.mjs $env:USERPROFILE\deepseek-harness\boot-test.mjs
cd $env:USERPROFILE\deepseek-harness; node boot-test.mjs; del boot-test.mjs

# 3. 技能加载（27 个）：逐字复刻 dsh-skill-filesystem 的 frontmatter 解析
node verify-skills.mjs
```

`boot-test.mjs` 需要放在 `deepseek-harness` 目录下运行——那里才有
`@deepseek-ai/dsh-tools` 与 `dsh-system-prompt` 的实体。

## 本次修正的缺陷

1. **`presentCall` 读不存在的嵌套字段**（`sec_recon_fanout`）。
   注册表传入的是**原始 args**，代码却按归一化后的形状取值，导致卡片永远
   退化成通用渲染。已改为在 `presentCall` 内部自行归一化。
2. **`surfaces[].type` 未在入口校验**。未知类别会漏到 `buildFanout` 才被拒，
   报错面向开发者而非模型。已提前到 `validateFanoutArgs`。
3. **`report` 技能的 frontmatter 解析失败**，被 loader **静默忽略**。
   原因是未加引号的 `description` 里含 ASCII 冒号（`EN: `），YAML 解析成嵌套映射。
   已整串加引号 —— 27 个技能现已全部可加载。

## 边界

本模式只做**证明型**验证：证明漏洞存在即停止。不拖库、不批量导出、不破坏性写入、
不持久化、不横向移动。`destructiveGuard` 在任何 `sec_` 工具执行前拦截越界参数。

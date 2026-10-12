/**
 * 网安专家模式 (Security Expert Mode) — Host 半边。
 *
 * 本模式的核心是「高爆发并行 + 单点深度 + 情报交叉 + 验证型证据」四件事，
 * 它们分别落在三个平面：
 *
 *   1. AGENT 平面（多 Agent 扇出、攻击特化人格、情报检索纪律）
 *      → 由 preset `security-expert` 的 agent.cordis.yml 组合，不在本文件。
 *
 *   2. HOST 平面（本文件）
 *      → 注册 `sec_recon_plan` 编排工具：把「一次目标」摊成
 *        「一个思考 Agent + N 个专精攻击 Agent」的作业计划与并行扇出指令。
 *      → 注入攻击作业面提示词节：把「只证明存在、不拖库、不破坏」写进
 *        每一轮模型步的系统提示词，而不是靠会话里的口头约定。
 *
 *   3. CLIENT 平面（client.js）
 *      → composer 下方的舰队状态条，把「当前处于网安专家模式」变成页面事实。
 *
 * ── 零外部依赖（刻意的，且经过实测） ────────────────────────────────────
 * 本包以 `link:` 形式装进 profile，模块解析从本包的**物理路径**起算
 * （loader 的 baseUrl 是 profile 目录，但插件模块自身的 import 由 Node 按
 * 自身位置解析）。本包位于 Desktop，向上找不到 `.dsh/profiles/node_modules`
 * 或部署根的 `node_modules` 里的任何 `@deepseek-ai/*`。
 *
 * 实测结论（项目内两处都用 require.resolve 验证过）：
 *   - `@deepseek-ai/schemastery`  → 不可达
 *   - `@deepseek-ai/dsh-tools`    → 不可达
 * 现有同级插件（dsh-super-dev-mode、dsh-purge）同样零外部依赖，只 import
 * `node:` 内置与相对路径——这不是巧合，是 `link:` 安装的必然约束。
 *
 * 因此配置校验与参数校验全部手写，不依赖 schemastery 与 defineTool。
 * 参数校验是必须的：裸对象 `ctx.tools.register({...})` 得到的 definition
 * 会绕过 defineTool 的整层包装（parameters/output.schema 不被编译、args
 * 不被校验、presentCall 不在非法参数下退避）。本包因此在 buildPlan 里
 * 自行做严格校验并显式抛错，用同等的严格度补齐这一层。
 *
 * ── 边界纪律（本模式的硬约束） ──────────────────────────────────────────
 * 本模式只做**证明型**验证：证明漏洞存在即停止。
 * 不实现批量导出（拖库）、不实现破坏性载荷、不实现持久化落地。
 * 这三条通过 `sec_recon_plan` 返回的 constraints 与 `sec_` 前缀守卫共同表达。
 *
 * 命名导出契约遵循 shipped 工具包的形状：`name` / `inject` / `apply`。
 * 刻意**不**导出 `Config`——见 normalizeConfig 上方的说明：cordis 会把
 * `Config` 导出当 Standard Schema 解析，普通函数会让 boot 崩掉。
 * `inject` 是硬依赖——不声明，Cordis 不会把服务注入本 ctx。
 */

export const name = 'sec-expert-mode';

/** 硬依赖：工具注册表与提示词注册表。 */
export const inject = ['tools', 'systemPrompt'];

/**
 * 漏洞类别候选库 —— 注意是「候选」，不是「必修」。
 *
 * 早期版本把这 10 条当成固定编制：不管目标是什么，一律派这 10 个 Agent。
 * 那是个结构错误——它等于让编排者替目标猜攻击面。打 Spring Boot 后台和打
 * 一个 Node SSR 前台，真实攻击面完全不同，预先钉死分工必然产生两类浪费：
 * 派出打不着的 Agent（比如目标根本没有反序列化入口），同时漏掉目标特有的
 * 面（比如某个自研的签名算法、某条只有知道业务才想得到的越权路径）。
 *
 * 现在它是侦察 Agent 的判断依据与回填时的校验表：侦察结果里出现的
 * surface 类型必须落在这个库里，而最终派谁由侦察结果决定。
 */
const VULN_LANES = [
  'authn',      // 认证与会话：JWT、OAuth、SAML、MFA、会话固定、密码重置
  'authz',      // 权限：水平越权 IDOR、垂直越权、BOLA/BFLA、租户隔离
  'injection',  // 注入：SQL/NoSQL/命令/模板/表达式/LDAP/XPath
  'xss',        // 客户端注入：反射/存储/DOM、CSP 绕过、mXSS
  'ssrf',       // 服务端请求伪造：内网探测、云元数据、gopher、DNS 外带
  'file',       // 文件：任意上传、任意读取、路径穿越、归档解压
  'deserial',   // 反序列化与对象注入：Java/PHP/.NET/Python/Node
  'logic',      // 业务逻辑：竞态、状态机绕过、价格/数量篡改、限额绕过
  'infra',      // 基础设施：默认凭证、暴露面板、配置错误、依赖 CVE
  'client',     // 客户端逆向：隐藏接口、硬编码密钥、签名算法、小程序/APK
];

/**
 * 侦察 Agent 必须回答的问题 —— 第二阶段分组的唯一依据。
 *
 * 每一条都对应一个「决定派谁」的判断。清单刻意不写成「请做信息收集」，
 * 因为那样模型会给你一段泛泛的资产罗列，回填时无从下手。这里要求的是
 * 可执行的结构：每个面都要带上「怎么进去」和「够不够得着高危」。
 */
const RECON_QUESTIONS = [
  {
    id: 'stack',
    ask: '技术栈与精确版本：语言/框架/中间件/数据库/云厂商，及各组件可判定到的最细版本号。',
    why: '版本是 CVE 匹配的唯一钥匙。只报「用了 Nginx」毫无价值，「nginx/1.18.0 + Spring Boot 2.3.4」才能定位到具体洞。',
  },
  {
    id: 'surface',
    ask: '可达面清单：子域、端口、暴露服务、API 基路径、前端路由、静态资源目录、管理面板、调试端点。',
    why: '决定攻击 Agent 的数量与分工键；哪些实际上不去，就不该为它派人。',
  },
  {
    id: 'entry',
    ask: '每个可交互入口：HTTP 方法、参数名、鉴权要求（匿名/登录/特定角色）、返回体形状、是否接受文件或 URL。',
    why: '入口决定可打的漏洞类型。接受 URL 的参数优先怀疑 SSRF；接受文件的上传点优先怀疑任意上传与解析绕过。',
  },
  {
    id: 'auth',
    ask: '身份体系：登录方式、令牌形态（JWT/Session/OAuth/OIDC）、令牌校验位置、角色模型、注册与找回密码流程。',
    why: '认证与权限是 SRC 高危的主要来源，且必须先摸清令牌形态才能谈绕过。',
  },
  {
    id: 'data',
    ask: '数据流特征：哪些接口按 ID 取对象、哪些返回他人数据、请求体里有哪些看起来是服务端信任的字段（价格、角色、额度、状态）。',
    why: '越权与逻辑漏洞的入口全在这里，而它们通常不在扫描器覆盖范围内。',
  },
  {
    id: 'build',
    ask: '构建与供应链线索：前端产物中的 sourcemap、硬编码密钥、内部域名、SDK 版本、第三方组件清单、错误页暴露的堆栈。',
    why: '既能直接产出高危（硬编码凭证），也能反向确认技术栈版本。',
  },
  {
    id: 'defense',
    ask: '防护态势：WAF 指纹与拦截特征、CSP 策略、限流与验证码、响应头暴露的服务信息、错误处理是否泄露细节。',
    why: '决定攻击 Agent 该走直接注入还是编码绕过；也避免在防护面前做无用尝试。',
  },
  {
    id: 'hot',
    ask: '疑似近期热点：组件版本落在最近公开的严重漏洞区间内的可能性，以及该行业/该框架近半年的公开高危事件线索。',
    why: '0day 与 n-day 的切入点。新版组件、自研协议、少见技术组合是挖未知漏洞的主要方向。',
  },
];

/** 情报源分层 —— 每个攻击 Agent 必须交叉比对的最低层数。 */
const INTEL_SOURCES = [
  { id: 'osint', label: '开源情报', detail: 'GitHub 泄露、搜索引擎 dork、供应链公开信息、文档与招聘泄露的技术栈线索' },
  { id: 'cve', label: 'CVE/NVD', detail: 'NVD、CVE.org、GitHub Advisory、厂商安全公告；按组件与版本精确匹配' },
  { id: 'cwe', label: 'CWE 分类', detail: 'CWE 根因归类与变体清单，用于推导同一根因的其它入口' },
  { id: 'writeup', label: '漏洞报告与赏金 Writeup', detail: 'HackerOne Hacktivity、Bugcrowd、PortSwigger Research、CTF 与会议议题' },
  { id: 'advisory', label: '厂商与生态公告', detail: '框架/中间件/云服务公告、补丁 diff、release note 的安全条目' },
  { id: 'recent', label: '最新漏洞与在野情报', detail: '近 90 天的 NVD 新增、GitHub Advisory 新条目、CISA KEV 在野利用清单、安全研究者的新公开手法、组件 changelog 里的安全修复' },
];

/**
 * 0day 与高危的探索方向 —— 附在每个攻击 Agent 的作业面里。
 *
 * 「尝试挖 0day」如果只写成一句口号，模型会退化成「去搜一下有没有已知洞」。
 * 这四条把它落成可执行动作：把范围从「已公开记录」推到「未被记录的行为差异」。
 * 提醒一句实话：真 0day 稀缺，本清单的作用是提高命中率与不放过候选，
 * 而不是保证产出——把它当成「必须走到这一步」，而非「必须交出 0day」。
 */
const ZERO_DAY_VECTORS = [
  {
    id: 'version-gap',
    ask: '版本差与补丁 diff：拉取相邻版本的安全修复提交，反推该修复针对的具体缺陷，判断本目标是否在受影响区间，或是否存在未完全修复的变体。',
    why: '这是最稳定的一类 0day 来源——补丁修了 A，但没修同一根因的 B 路径。',
  },
  {
    id: 'logic-abuse',
    ask: '业务逻辑的组合滥用：把多个「单独看无害」的合法操作串起来，构造出设计者未预期的状态。含竞态、状态机跳跃、数值边界、顺序依赖。',
    why: '逻辑漏洞几乎不会被扫描器发现，且常构成高危，因为它们直接触达资产或权限。',
  },
  {
    id: 'parser-diff',
    ask: '解析器不一致：同一份输入在网关/框架/业务代码/数据库之间被解析出不同结果（编码、截断、大小写、类型转换、Unicode 归一）。',
    why: '解析差异是绕过一切前置校验的根因，也是近年多个高危 RCE 的同一模式。',
  },
  {
    id: 'self-made',
    ask: '自研协议与私有接口：识别目标特有的协议、签名算法、序列化格式、内部 SDK，分析其设计缺陷而非套用通用 payload。',
    why: '自研部分没有公开记录，是唯一真正「不查已知也能打」的地方，也是最可能出现未公开漏洞的区域。',
  },
];


/**
 * 配置默认值与归一化。
 *
 * 手写而非 schemastery：见文件头的「零外部依赖」说明。这里的职责只是把
 * loader 传来的原始 config 补齐成完整可用的设置对象，并对越界值做钳制。
 */
const CONFIG_DEFAULTS = {
  promptSection: true,
  reconTool: true,
  probeTool: true,
  maxParallelAgents: 8,
  evidenceRequired: true,
  destructiveGuard: true,
};

/**
 * 把原始 config 归一成完整设置；布尔取真值，上限钳到 [1, 32]。
 *
 * 注意：这里**不能**命名为 `Config` 并导出——cordis 把插件的 `Config` 导出
 * 当作 Standard Schema 处理（resolveConfig 直接调 `Config["~standard"].validate`），
 * 普通函数没有 `["~standard"]`，会抛
 * `Cannot read properties of undefined (reading 'validate')` 把整个 boot 打崩。
 * 所以本函数只做内部归一化，不导出；cordis 拿到 raw config 后原样交给 apply。
 */
function normalizeConfig(raw) {
  const input = raw && typeof raw === 'object' ? raw : {};
  const pickBool = (key) => (typeof input[key] === 'boolean' ? input[key] : CONFIG_DEFAULTS[key]);
  const rawLimit = Number(input.maxParallelAgents);
  const limit = Number.isFinite(rawLimit) && rawLimit >= 1
    ? Math.min(Math.floor(rawLimit), 32)
    : CONFIG_DEFAULTS.maxParallelAgents;
  return {
    promptSection: pickBool('promptSection'),
    reconTool: pickBool('reconTool'),
    probeTool: pickBool('probeTool'),
    evidenceRequired: pickBool('evidenceRequired'),
    destructiveGuard: pickBool('destructiveGuard'),
    maxParallelAgents: limit,
  };
}

/** 把用户给的自由文本目标归一成稳定的目标描述。 */
function normalizeTarget(raw) {
  const text = String(raw ?? '').trim();
  if (!text) return { scope: 'unspecified', base: '' };
  return { scope: 'operator-provided', base: text };
}

/**
 * 参数严格校验 —— 补上 defineTool 缺失的那一层。
 *
 * shipped 工具走 `defineTool(...)`，它会把 parameters 编译成 JSON Schema 并在
 * 每次 execute / presentCall / isConcurrencySafe 前校验 args，违规抛
 * `ToolArgsError`。本包因为解析不到 `@deepseek-ai/dsh-tools` 而无法使用它，
 * 因此在这里以同等严格度自行校验：缺必填、类型错、枚举错一律抛错，
 * 绝不静默降级。
 *
 * 这不是过度防御。编排工具的返回值会被用来决定「派几个 Agent、各打什么」，
 * 调用者以为锁定了某条分工、实际拿到另一套，比调用直接失败有害得多。
 *
 * @param args - 模型传进来的原始参数。
 * @returns 归一后的 { target, lanes, notes }；`lanes` 为 undefined 表示省略。
 * @throws {Error} 参数非法时抛出，消息面向模型可读。
 */
function validateArgs(args) {
  const input = args && typeof args === 'object' && !Array.isArray(args) ? args : {};

  if (!Object.hasOwn(input, 'target') || input.target === undefined || input.target === null) {
    throw new Error('缺少必填参数 target：请给出目标描述（域名、URL、接口、二进制标识或资产范围）。');
  }
  if (typeof input.target !== 'string') {
    throw new Error(`参数 target 必须是字符串，收到 ${Array.isArray(input.target) ? 'array' : typeof input.target}。`);
  }
  if (!input.target.trim()) {
    throw new Error('参数 target 不能是空字符串。');
  }

  let lanes;
  if (input.lanes !== undefined && input.lanes !== null) {
    if (!Array.isArray(input.lanes)) {
      throw new Error(`参数 lanes 必须是字符串数组，收到 ${typeof input.lanes}。`);
    }
    const badType = input.lanes.filter((l) => typeof l !== 'string');
    if (badType.length > 0) {
      throw new Error(`参数 lanes 的元素必须是字符串，收到 ${badType.map((b) => typeof b).join('、')}。`);
    }
    // 枚举校验放在这里而不是 buildPlan：validateArgs 是唯一的入口校验点，
    // 未知类别必须在这里就被拒绝，不能漏到计划生成阶段被静默过滤。
    const unknown = input.lanes.filter((l) => !VULN_LANES.includes(l));
    if (unknown.length > 0) {
      throw new Error(
        `未知的攻击类别：${[...new Set(unknown)].map((u) => JSON.stringify(u)).join('、')}；` +
        `可用类别为 ${VULN_LANES.join('、')}。`,
      );
    }
    // 去重，保持分工表与派出的 Agent 数一致（同名 lane 只会派一个 Agent）。
    lanes = [...new Set(input.lanes)];
  }

  let notes;
  if (input.notes !== undefined && input.notes !== null) {
    if (typeof input.notes !== 'string') {
      throw new Error(`参数 notes 必须是字符串，收到 ${typeof input.notes}。`);
    }
    notes = input.notes;
  }

  return { target: input.target, lanes, notes };
}

/**
 * 第二阶段参数校验 —— 与 validateArgs 同等严格。
 *
 * `surfaces` 的形状直接决定派出几个 Agent 和它们各打什么，所以元素级的
 * 类型检查是必须的：一个 `type` 拼错会让分工表与候选库脱节，
 * 一个 `entry` 缺失会让 Agent 拿到空靶子。
 */
function validateFanoutArgs(args) {
  const input = args && typeof args === 'object' && !Array.isArray(args) ? args : {};

  if (typeof input.target !== 'string' || !input.target.trim()) {
    throw new Error('缺少必填参数 target：请给出与侦察阶段一致的目标描述。');
  }

  if (!Array.isArray(input.surfaces)) {
    throw new Error(
      `参数 surfaces 必须是数组（侦察 Agent 交回的攻面清单），收到 ${Array.isArray(input.surfaces) ? 'array' : typeof input.surfaces}。`,
    );
  }
  if (input.surfaces.length === 0) {
    throw new Error('surfaces 不能为空数组：第二阶段的分工必须来自实际侦察结果。');
  }

  const surfaces = input.surfaces.map((s, i) => {
    if (!s || typeof s !== 'object' || Array.isArray(s)) {
      throw new Error(`surfaces[${i}] 必须是对象（至少含 type 与 entry），收到 ${s === null ? 'null' : typeof s}。`);
    }
    if (typeof s.type !== 'string' || !s.type.trim()) {
      throw new Error(`surfaces[${i}].type 必须是非空字符串。`);
    }
    if (typeof s.entry !== 'string' || !s.entry.trim()) {
      throw new Error(`surfaces[${i}].entry 必须是非空字符串——攻击 Agent 需要一个具体入口，不能是空靶子。`);
    }
    return {
      type: s.type.trim(),
      entry: s.entry.trim(),
      auth: typeof s.auth === 'string' ? s.auth : undefined,
      reachable: typeof s.reachable === 'string' ? s.reachable : undefined,
      severity: typeof s.severity === 'string' ? s.severity : undefined,
      priority: Number.isFinite(s.priority) ? s.priority : undefined,
      evidence: typeof s.evidence === 'string' ? s.evidence : undefined,
    };
  });

  let maxAgents;
  if (input.maxAgents !== undefined && input.maxAgents !== null) {
    if (!Number.isFinite(input.maxAgents) || input.maxAgents < 1) {
      throw new Error(`参数 maxAgents 必须是 >= 1 的数字，收到 ${JSON.stringify(input.maxAgents)}。`);
    }
    maxAgents = input.maxAgents;
  }

  // 枚举校验必须发生在归一化之后、返回之前：validateArgs 是唯一入口校验点，
  // 未知类别不能漏到 buildFanout 才被拒（那条路径的报错面向开发者，不是模型）。
  const unknown = surfaces
    .map((s, i) => ({ i, t: s.type }))
    .filter(({ t }) => !VULN_LANES.includes(t));
  if (unknown.length > 0) {
    throw new Error(
      `surfaces 里存在未知类型：${unknown.map(({ i, t }) => `[${i}] ${JSON.stringify(t)}`).join('、')}；` +
      `可用类型为 ${VULN_LANES.join('、')}。`,
    );
  }

  let notes;
  if (input.notes !== undefined && input.notes !== null) {
    if (typeof input.notes !== 'string') {
      throw new Error(`参数 notes 必须是字符串，收到 ${typeof input.notes}。`);
    }
    notes = input.notes;
  }

  return { target: input.target, surfaces, maxAgents, notes };
}

/**
 * 生成第一阶段计划：只派侦察 Agent。
 *
 * 与早期版本的根本区别：这里**不预先分配漏洞类别**。
 * 早期版本直接返回 10 个攻击 Agent 的分工表，等于在不知道目标长什么样的
 * 情况下替它决定打哪 10 个点。改法的依据很直接——你打一个站之前不可能知道
 * 它是 Spring 后台还是 Node SSR，预先钉死分工必然既派错人又漏掉目标特有的面。
 *
 * 现在第一阶段的产出只有一个侦察 Agent 的作业面：它探明技术栈、可达面、
 * 入口、身份体系、数据流、供应链、防护态势、热点线索，然后由
 * `sec_recon_fanout` 把这份结果翻译成第二阶段的子 Agent 编制。
 *
 * `lanes` 参数的含义随之改变：不再是「派哪些攻击 Agent」，而是
 * 「侦察时重点看哪些方向」。两者不是同一件事——前者是结论，后者是关注点。
 */
function buildPlan(input, limits) {
  const target = normalizeTarget(input.target);

  // 侦察关注点：省略则全看。这是提示，不是编制。
  const focus = Array.isArray(input.lanes) && input.lanes.length > 0
    ? input.lanes
    : VULN_LANES.slice();

  const scout = {
    role: '侦察 Agent · 攻击面测绘',
    stage: 'recon',
    objective: [
      '探明目标真实存在哪些攻击面，而不是套用通用清单。产出必须是可执行的结构，不是资产罗列。',
      '每个面都要回答「怎么进去」与「够不够得着高危」——够不着的面不写进结论，避免后续派人去打空气。',
      '对每一项标注确定性：已证实 / 强推断 / 待验证。三者必须分开，不能混写成「发现」。',
    ],
    questions: RECON_QUESTIONS.map((q) => ({ ...q })),
    focus,
    deliverables: [
      'tech_stack[]：组件、精确版本、判定依据（响应头/报错页/静态产物/指纹）',
      'surfaces[]：类型（必须是 VULN_LANES 之一）、入口点、鉴权要求、可达性、可能严重度上限、优先级',
      'entries[]：方法、路径、参数名、期望返回、可操控的输入类型',
      'auth_model：令牌形态、校验位置、角色模型、注册与找回流程',
      'data_flows[]：按 ID 取对象的接口、疑似服务端信任的字段',
      'supply_chain[]：sourcemap、硬编码密钥、内部域名、第三方组件、堆栈泄露',
      'defenses[]：WAF 指纹、CSP、限流、错误处理特征',
      'hot_leads[]：落在近期严重漏洞区间的组件、该技术栈近半年公开高危事件',
    ],
    forbidden: [
      '把「技术栈是 Java」这类无法定位到 CVE 的粗粒度结论当作版本结论',
      '把推断写成已证实',
      '在还没有入口清单的情况下就给出攻击建议',
    ],
  };

  return {
    mode: 'security-expert',
    stage: 'recon',
    target,
    notes: String(input.notes ?? ''),
    doctrine: [
      '先测绘，后打击：不知道目标有什么之前，不分配攻击 Agent。',
      '分工由事实生成：第二阶段的子 Agent 编制来自侦察结果，不来自预设清单。',
      '单点纵深：每个攻击 Agent 只负责一条链，不跨链、不抢活。',
      '情报交叉：每个攻击 Agent 都必须完成六层检索（含近 90 天最新记录）。',
      '0day 探索：每条链都要走到「版本差 / 逻辑组合 / 解析差异 / 自研协议」四个方向，不把存在性证明停在已知 CVE。',
      '证据优先：没有原始请求/响应的发现等于没有发现。',
      '证明即止：只证明存在，不拖库、不改数据、不落地、不留后门。',
      '门槛纪律：只收 high 与 critical；medium、low、info 一律不提交。',
    ],
    scout,
    intelSources: INTEL_SOURCES,
    zeroDayVectors: ZERO_DAY_VECTORS,
    lanesAvailable: VULN_LANES,
    constraints: buildConstraints(limits),
    limits: {
      maxParallelAgents: limits.maxParallelAgents,
      scoutAgents: 1,
      attackerAgents: 0,
      truncated: false,
    },
    nextStep: '把侦察 Agent 的结果回填给 sec_recon_fanout，由它生成第二阶段的攻击子 Agent 编制。',
    note: '第一阶段只派 1 个侦察 Agent。它探明的攻面决定第二阶段派谁——本阶段固定不派攻击 Agent，因此不存在截断。',
  };
}

/** 硬约束集合 —— 两个阶段共用，保证口径一致。 */
function buildConstraints(limits) {
  return {
    proofOnly: true,
    noDataExfiltration: true,
    noDestructivePayload: true,
    noPersistence: true,
    minimalNoise: true,
    evidenceRequired: limits.evidenceRequired,
    severityAccepted: ['high', 'critical'],
    severityRejected: ['medium', 'low', 'info'],
  };
}

/**
 * 第二阶段：按侦察结果生成攻击子 Agent 编制。
 *
 * 这是本次改动的核心。输入是侦察 Agent 交回的 `surfaces[]`，输出是
 * 「派几个 Agent、每个打什么」。关键规则：
 *
 *   1. 只为**真实存在且在可达范围内**的面派人。侦察结果里没出现的类别不派。
 *   2. 同一类别有多个独立入口时按入口拆分，因为「同一个类别的两个入口」
 *      通常需要两套完全不同的手法——把它们塞给一个 Agent 就是让它浅覆盖。
 *   3. 优先级排序后按上限截断，并明确报告丢了哪些，不静默丢弃。
 *   4. 0day 方向不是可选项：每个子 Agent 都要走那四条，因为它们正是
 *      「已知 CVE 之外」的探索路径。
 *
 * @param input - { target, surfaces[], notes?, maxAgents? }
 * @param limits - 归一后的部署设置。
 */
function buildFanout(input, limits) {
  const target = normalizeTarget(input.target);
  const surfaces = Array.isArray(input.surfaces) ? input.surfaces : [];

  if (surfaces.length === 0) {
    throw new Error(
      'surfaces 是空的：第二阶段的分工必须来自侦察结果。请先把侦察 Agent 交回的攻面清单填进来；' +
      '若侦察确实没发现可用面，那就说明当前目标在可达范围内没有高危切入点，而不是随便派几个 Agent 去打。',
    );
  }

  // 校验每个面的类型，避免拼错类别导致分工表与预设口径脱节。
  const badType = surfaces
    .map((s, i) => ({ i, t: s && typeof s === 'object' ? s.type : undefined }))
    .filter(({ t }) => !VULN_LANES.includes(t));
  if (badType.length > 0) {
    throw new Error(
      `surfaces 里存在未知类型：${badType.map(({ i, t }) => `[${i}] ${JSON.stringify(t)}`).join('、')}；` +
      `可用类型为 ${VULN_LANES.join('、')}。`,
    );
  }

  const cap = Number.isFinite(input.maxAgents) && input.maxAgents >= 1
    ? Math.min(Math.floor(input.maxAgents), limits.maxParallelAgents)
    : limits.maxParallelAgents;

  // 优先级：显式 priority 优先，其次按严重度上限，最后保持侦察给出的顺序。
  const sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const ranked = surfaces.map((s, order) => ({
    order,
    ...s,
    entry: String(s.entry ?? '').trim() || '(未标注入口)',
    priority: Number.isFinite(s.priority) ? Math.floor(s.priority) : (sevRank[s.severity] ?? 9),
  })).sort((a, b) => (a.priority - b.priority) || (a.order - b.order));

  const selected = ranked.slice(0, cap);
  const dropped = ranked.slice(cap);

  const attackers = selected.map((s, idx) => ({
    agentId: `atk-${String(idx + 1).padStart(2, '0')}-${s.type}`,
    lane: s.type,
    entry: s.entry,
    fromRecon: true,
    role: `攻击 Agent · ${s.type} @ ${s.entry}`,
    targetSurface: {
      type: s.type,
      entry: s.entry,
      auth: s.auth ?? 'unknown',
      reachable: s.reachable ?? 'unverified',
      severityCeiling: s.severity ?? s.severityCeiling ?? 'unknown',
      evidence: s.evidence ?? '',
    },
    objective: [
      `只打 ${s.type} 在 ${s.entry} 这一个点，打到能出具可复现证据为止。`,
      '这是侦察结果指认的真实入口，不是通用清单里的一条；若现场与侦察不符，以现场为准并说明差异。',
      '先建立该点的最小可验证假设，再逐条证伪或证实；证伪后换同类别下的其它入口，而不是换方向。',
      '拿不到证据就明确报「未证实」，不把「看起来像」写成发现。',
    ],
    intelRequired: INTEL_SOURCES.map((src) => ({
      id: src.id,
      label: src.label,
      detail: src.detail,
      mustFind: `找出与本目标技术栈/组件版本/${s.type} 相关的全部 ${src.label} 记录，并给出相似点比对` +
        (src.id === 'recent' ? '；特别标出近 90 天内新增、且与本组件版本区间重叠的条目' : ''),
    })),
    zeroDay: ZERO_DAY_VECTORS.map((v) => ({ ...v })),
    evidenceContract: [
      '最小 PoC：完整原始请求（方法、路径、全部相关头、body）与对应的原始响应',
      '若为盲注/外带类，给出可回连证明与时间/内容差异，附上对照组的原始记录',
      '影响面陈述必须区分「已证实」与「推断」，逐条标注依据',
      '映射到 CWE 根因，并列出由此推导出的同一根因的其它入口',
      '若声称 0day：必须给出「所属组件与版本 → 相关已知修复不存在或未覆盖 → 可复现的异常行为」完整链条，缺一环不算',
    ],
    stopCondition: '证明漏洞存在即停止。不做利用后动作，不读业务数据，不做横向移动。',
    severityFloor: '仅当可达性与影响面共同支撑 high 或 critical 时才提交；medium 及以下不进入结论集。',
  }));

  const coveredTypes = [...new Set(attackers.map((a) => a.lane))];

  return {
    mode: 'security-expert',
    stage: 'fanout',
    target,
    notes: String(input.notes ?? ''),
    doctrine: [
      '编制来自事实：本批 Agent 由侦察结果生成，不是预设清单。',
      '并行爆发：全部攻击 Agent 在同一轮派出，不串行等待。',
      '单点纵深：每个 Agent 只负责一个入口上的一类问题，不跨链、不抢活。',
      '情报交叉：六层检索，含近 90 天最新记录。',
      '0day 探索：四条方向逐条走到，不把结论停在已知 CVE。',
      '证据优先：没有原始请求/响应的发现等于没有发现。',
      '证明即止：只证明存在，不拖库、不改数据、不落地、不留后门。',
      '门槛纪律：只收 high 与 critical。',
    ],
    derivedFrom: {
      surfacesReceived: surfaces.length,
      surfacesDispatched: attackers.length,
      surfacesDropped: dropped.length,
    },
    attackers,
    coverage: {
      typesCovered: coveredTypes,
      typesNotPresent: VULN_LANES.filter((l) => !coveredTypes.includes(l)),
    },
    intelSources: INTEL_SOURCES,
    zeroDayVectors: ZERO_DAY_VECTORS,
    phases: [
      { title: '扇出', detail: `同一轮派出 ${attackers.length} 个攻击 Agent，全部 background 并行，各自一个入口。` },
      { title: '情报交叉', detail: `每个 Agent 完成 ${INTEL_SOURCES.length} 层检索（含近 90 天最新），产出相似点比对表。` },
      { title: '0day 探索', detail: `每个 Agent 逐条走 ${ZERO_DAY_VECTORS.length} 个未公开方向：版本差、逻辑组合、解析差异、自研协议。` },
      { title: '验证', detail: '对每条已证实的点做最小 PoC，采集原始请求/响应作为证据。' },
      { title: '定级与收敛', detail: '按可达性 × 影响面定级，只保留 high/critical，输出可直接提交的条目。' },
    ],
    constraints: buildConstraints(limits),
    limits: {
      maxParallelAgents: limits.maxParallelAgents,
      scoutAgents: 0,
      attackerAgents: attackers.length,
      truncated: dropped.length > 0,
    },
    note: dropped.length > 0
      ? `侦察返回 ${surfaces.length} 个面，按优先级取前 ${attackers.length} 个；` +
        `剩余 ${dropped.length} 个（${dropped.map((d) => `${d.type}@${d.entry}`).slice(0, 6).join('、')}${dropped.length > 6 ? '…' : ''}）` +
        '下一轮再派，或提高 maxAgents。'
      : `${surfaces.length} 个面全部排入本轮，未丢弃任何入口。`,
  };
}


/**
 * 把计划渲染成给人看也顺眼的文本摘要。
 *
 * 按 `stage` 分支渲染：第一阶段只有侦察 Agent，第二阶段只有攻击 Agent。
 * 早期版本无条件读 `plan.attackers` 与 `plan.thinker`，两阶段化之后
 * 第一阶段调用会直接崩在 `plan.attackers.length` 上。
 */
function renderPlan(plan) {
  const lines = [];
  lines.push(`# 网安专家模式 · ${plan.stage === 'fanout' ? '攻击编排' : '侦察计划'}`);
  lines.push('');
  lines.push(`目标：${plan.target.base || '(未指定)'}`);
  if (plan.notes) lines.push(`备注：${plan.notes}`);

  if (plan.stage === 'fanout') {
    lines.push(`编制来源：侦察结果（收到 ${plan.derivedFrom.surfacesReceived} 个面，派出 ${plan.derivedFrom.surfacesDispatched} 个 Agent）`);
  } else {
    lines.push('本阶段：1 个侦察 Agent 测绘攻击面，不派攻击 Agent');
  }
  lines.push('');

  lines.push('## 信念');
  for (const d of plan.doctrine) lines.push(`- ${d}`);
  lines.push('');

  if (plan.stage !== 'fanout') {
    const sc = plan.scout;
    lines.push('## 侦察 Agent · 攻击面测绘');
    for (const o of sc.objective) lines.push(`- ${o}`);
    lines.push('');
    lines.push('### 必须回答的问题');
    for (const q of sc.questions) {
      lines.push(`- **${q.id}**：${q.ask}`);
      lines.push(`  - 为什么问：${q.why}`);
    }
    lines.push('');
    lines.push('### 关注方向');
    lines.push(`- ${sc.focus.join('、')}`);
    lines.push('');
    lines.push('### 交付物');
    for (const d of sc.deliverables) lines.push(`- ${d}`);
    lines.push('');
    lines.push('### 禁止');
    for (const f of sc.forbidden) lines.push(`- ${f}`);
    lines.push('');
    lines.push('## 下一步');
    lines.push(`- ${plan.nextStep}`);
  } else {
    lines.push('## 攻击 Agent 分工（由侦察结果生成）');
    for (const a of plan.attackers) {
      lines.push(`### ${a.agentId} · ${a.lane}`);
      lines.push(`- 目标入口：${a.entry}`);
      lines.push(`- 侦察判定：鉴权=${a.targetSurface.auth} · 可达性=${a.targetSurface.reachable} · 严重度上限=${a.targetSurface.severityCeiling}`);
      for (const o of a.objective) lines.push(`- ${o}`);
      lines.push('- 0day 方向：');
      for (const v of a.zeroDay) lines.push(`  - ${v.ask}`);
      lines.push(`- 停止条件：${a.stopCondition}`);
      lines.push(`- 定级门槛：${a.severityFloor}`);
    }
    lines.push('');
    lines.push('## 覆盖情况');
    lines.push(`- 已覆盖类型：${plan.coverage.typesCovered.join('、') || '（无）'}`);
    lines.push(`- 侦察未发现、因此未派人的类型：${plan.coverage.typesNotPresent.join('、') || '（无）'}`);
  }

  lines.push('');
  lines.push('## 情报交叉要求（每名攻击 Agent 必经）');
  for (const s of plan.intelSources) lines.push(`- ${s.label}：${s.detail}`);

  lines.push('');
  lines.push('## 0day 探索方向（每名攻击 Agent 必走）');
  for (const v of plan.zeroDayVectors) {
    lines.push(`- **${v.id}**：${v.ask}`);
    lines.push(`  - 为什么有效：${v.why}`);
  }

  if (plan.stage === 'fanout') {
    lines.push('');
    lines.push('## 证据契约');
    for (const e of plan.attackers[0].evidenceContract) lines.push(`- ${e}`);

    lines.push('');
    lines.push('## 阶段');
    for (const p of plan.phases) lines.push(`- ${p.title}：${p.detail}`);
  }

  lines.push('');
  lines.push('## 硬约束');
  for (const [k, v] of Object.entries(plan.constraints)) {
    lines.push(`- ${k}：${JSON.stringify(v)}`);
  }

  lines.push('');
  lines.push('## 上限');
  lines.push(`- 单轮 Agent 上限：${plan.limits.maxParallelAgents}`);
  lines.push(`- 本轮：侦察 Agent ${plan.limits.scoutAgents} 个 · 攻击 Agent ${plan.limits.attackerAgents} 个`);
  lines.push(`- ${plan.note}`);
  return lines.join('\n');
}

/**
 * 非破坏性守卫。
 *
 * 本模式的设计目标之一是「拿到高/严重档的承认」，而能拿承认的 PoC 从来不需要
 * 真的搬数据。因此守卫拦的不是「攻击」，而是「超出证明需要的动作」：
 * 批量导出、破坏性写入、持久化落地。
 */
const BANNED_ACTIONS = /\b(drop\s+table|truncate\s+table|delete\s+from|rm\s+-rf|mkfs|shutdown|reboot|ransom|webshell|backdoor|schtasks)\b|拖库|全量导出|加密勒索|留后门/i;

function createDestructiveGuard(enabled) {
  return (execution) => {
    if (!enabled) return undefined;
    const toolName = String(execution?.name ?? '');
    if (!toolName.startsWith('sec_')) return undefined;
    let raw;
    try {
      raw = JSON.stringify(execution?.arguments ?? {});
    } catch {
      return undefined;
    }
    if (BANNED_ACTIONS.test(raw)) {
      return '网安专家模式的非破坏性约束拒绝该参数：本模式只证明漏洞存在，不做数据导出、破坏性写入或持久化落地。请把 PoC 收敛到最小证明。';
    }
    return undefined;
  };
}

/**
 * 把一个绝对 URL 归一成可安全探测的目标，同时挡住本模式不该走的协议。
 *
 * 刻意**不**限制内网地址：SSRF 与内网横向是本模式的正当作业内容，
 * 而且目标本身就是操作员指定的授权资产。这里拦的是「协议」与「畸形 URL」，
 * 不是「目标范围」——范围由操作员在 sec_recon_plan 的 target 里声明。
 *
 * @param raw - 模型给的目标字符串。
 * @returns { url } 或抛错。
 */
function normalizeProbeUrl(raw) {
  if (typeof raw !== 'string' || !raw.trim()) {
    throw new Error('参数 url 必须是非空字符串。');
  }
  let parsed;
  try {
    parsed = new URL(raw.trim());
  } catch {
    throw new Error(`参数 url 不是合法 URL：${JSON.stringify(raw)}。需要形如 http://host/path 的绝对地址。`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`只支持 http / https，收到 ${parsed.protocol}。`);
  }
  return parsed;
}

/** 逐个读响应，边读边截断，避免把整个响应体读进内存。 */
async function readCapped(response, cap) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: false });
  let text = '';
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      text += decoder.decode(value, { stream: true });
      if (text.length >= cap) {
        truncated = true;
        break;
      }
    }
  } finally {
    // 提前跳出时显式取消，不让底层连接悬着。
    try { await reader.cancel(); } catch { /* 已关闭 */ }
  }
  text += decoder.decode();
  return truncated ? text.slice(0, cap) : text;
}

/**
 * 发一次请求并采集原始记录（状态、头、体、耗时）。
 *
 * redirect 固定为 manual：自动跟随会掩盖 30x 上的跳转问题，而开放重定向、
 * OAuth 跳转劫持、SSRF 的跳转绕过恰恰都在那一跳上。
 */
async function probeOnce(target, options) {
  const { headers, body, method, timeoutMs, maxBody, signal } = options;
  const started = Date.now();
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener('abort', onAbort, { once: true });
  }
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(target, {
      method,
      headers,
      body: method === 'GET' || method === 'HEAD' ? undefined : body,
      redirect: 'manual',
      signal: controller.signal,
    });
    const text = await readCapped(response, maxBody);
    return {
      status: response.status,
      statusText: response.statusText,
      headers: Object.fromEntries(response.headers.entries()),
      length: text.length,
      body: text,
      elapsedMs: Date.now() - started,
    };
  } catch (error) {
    return {
      status: 0,
      statusText: '',
      headers: {},
      length: 0,
      body: '',
      elapsedMs: Date.now() - started,
      error: error?.name === 'AbortError'
        ? (signal?.aborted ? '调用方取消' : `超时（${timeoutMs}ms）`)
        : String(error?.message ?? error),
    };
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

/**
 * 盲注/时间盲注/外带类漏洞的判定辅助：把同一请求跑两遍，比较耗时与内容差异。
 *
 * 这是「对照组」的自动化。没有对照组的时间差不能作为证据——
 * 网络抖动与服务端真实行为无法区分，而 SRC 审核恰恰会拿这一点驳回。
 * 本函数只做测量与对比，不对结果下结论；结论由攻击 Agent 依据原始记录给出。
 */
async function probePair(target, options) {
  const first = await probeOnce(target, options);
  const second = await probeOnce(target, options);
  return [first, second];
}

/** 攻击作业面提示词节 —— 每一轮模型步都会重新注入。 */
const SEC_PROMPT_SECTION = `You are operating in SECURITY EXPERT MODE (网安专家模式).

Mission: find and prove high-severity or critical vulnerabilities — including previously
unpublished (0day-class) issues and RCE — through recon-driven parallel multi-agent hunting,
then submit only findings that survive SRC-grade scrutiny.

Two-stage workflow. Do not skip stage one, and do not pre-assign attack categories.
- Stage 1 — RECON. Call sec_recon_plan, then dispatch ONE recon agent. It maps what actually
  exists: exact component versions, reachable surface, per-entry auth requirements, identity
  model, data flows, supply-chain clues, defenses, and recent-hot leads. It assigns no
  attackers. Versions must be precise enough to match a CVE — "uses Nginx" is not a version.
- Stage 2 — FANOUT. Feed the recon result into sec_recon_fanout. It derives the attack-agent
  roster FROM those surfaces. Dispatch every returned attacker in ONE message, concurrently,
  as background subagents. Never serialize what can overlap.

Roster discipline: an agent is dispatched only for a surface that recon proved exists and is
reachable. A category recon did not find is a category with no agent — do not pad the roster
back to a fixed list, and do not silently drop a surface either; report what was left out.

Attack agents: each owns exactly ONE entry on ONE category and drives it to reproducible
evidence. Do not let a single agent cover several lanes shallowly.

Intel cross-reference is mandatory, six layers: OSINT, CVE/NVD, CWE classification, public
bounty/CTF writeups, vendor advisories, and RECENT (last 90 days — new NVD entries, new GitHub
Advisories, CISA KEV additions, fresh public techniques, and security fixes in changelogs).
Report the similar points found in each layer, not just a link.

0day exploration is mandatory, four vectors per agent:
- version-gap: diff adjacent releases' security fixes, infer the defect each patch targets,
  then test for the un-fixed sibling path or an incomplete fix.
- logic-abuse: chain individually-harmless legitimate operations into an unintended state
  (race, state-machine skip, numeric boundary, ordering dependency).
- parser-diff: one input parsed differently across gateway/framework/app/database
  (encoding, truncation, case, coercion, Unicode normalization).
- self-made: target-specific protocols, signing schemes, private serialization, internal SDKs —
  analyze their design rather than replaying a generic payload.
Claiming 0day requires the full chain: component+version → the relevant known fix is absent or
incomplete → a reproducible anomalous behavior. A missing link means it is not a 0day claim.

Evidence or it did not happen. A finding without the raw request and raw response (or an
equivalent deterministic proof for blind classes) is a hypothesis, not a finding.
Use sec_http_probe to produce that raw exchange: it sends one fully-controlled request and
returns the raw response (status, headers, body) so the exact bytes are in the record.
Do not paraphrase a finding from memory — re-run it through the probe and paste the output.

For blind, time-based, and out-of-band classes use sec_http_probe with pair: true. It replays
the SAME request twice and reports the jitter baseline (delta.elapsedMs, sameStatus, sameBody).
A timing difference without that control group is not evidence — server load and network jitter
are indistinguishable from a real signal, and SRC triage rejects exactly that. Report baseline
and payload timing side by side, and never claim a blind finding on a single measurement.

Prove existence and STOP. No data exfiltration, no bulk export, no destructive writes, no
persistence, no lateral movement. A minimal proof is the whole deliverable.

Severity discipline: submit only high and critical. Medium, low, and informational findings are
not results — they are noise, and they dilute the report.

Keep noise minimal and changes reversible. Record exact steps so any finding can be replayed.`;

/**
 * @param ctx - the plugin context; `tools` and `systemPrompt` are injected.
 * @param config - the deployment's explicit mode policy.
 */
export function apply(ctx, config) {
  const settings = normalizeConfig(config ?? {});

  if (settings.reconTool) {
    ctx.tools.register({
      name: 'sec_recon_plan',
      description: [
        '网安专家模式 · 第一阶段：攻击面测绘。',
        '派 1 个侦察 Agent 探明目标真实存在哪些攻击面——技术栈与精确版本、可达面、',
        '每个入口的鉴权要求、身份体系、数据流特征、供应链线索、防护态势、近期热点。',
        '它不分配攻击 Agent：分工必须来自事实，不能来自预设清单。',
        '拿到侦察结果后，用 sec_recon_fanout 生成第二阶段的攻击子 Agent 编制。',
        '本模式只做证明型验证：不拖库、不破坏、不落地。',
      ].join(''),
      parameters: {
        type: 'object',
        required: ['target'],
        properties: {
          target: {
            type: 'string',
            description: '目标描述：域名、URL、接口、二进制标识或资产范围。',
          },
          lanes: {
            type: 'array',
            description: [
              '侦察时重点关注的方向（不是要派的攻击 Agent——分工由侦察结果决定）。',
              '省略 = 全方向都看；含未知值会被拒绝（不静默丢弃）。',
            ].join(''),
            items: {
              type: 'string',
              enum: VULN_LANES,
            },
          },
          notes: {
            type: 'string',
            description: '操作员补充的约束、已知信息或排除项。',
          },
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: false,
          required: ['plan', 'markdown'],
          properties: {
            plan: {
              type: 'object',
              additionalProperties: true,
            },
            markdown: {
              type: 'string',
            },
          },
        },
        render: (_args, value) => [{
          type: 'text',
          text: typeof value?.markdown === 'string' ? value.markdown : JSON.stringify(value, null, 2),
        }],
      },
      execute(args) {
        // validateArgs 已处理非法输入并抛错；buildPlan 只处理合法参数。
        const safe = validateArgs(args);
        const plan = buildPlan(safe, {
          maxParallelAgents: settings.maxParallelAgents,
          evidenceRequired: settings.evidenceRequired,
        });
        return Promise.resolve({ plan, markdown: renderPlan(plan) });
      },
      isConcurrencySafe: () => true,
      presentCall: (args) => {
        // 与 defineTool 的行为对齐：参数非法时不渲染自定义卡片，
        // 退回通用渲染，避免用一个合法形状去描述一次非法调用。
        try {
          const safe = validateArgs(args);
          return {
            card: 'generic',
            title: `sec_recon_plan · ${safe.target.slice(0, 60)}`,
            kind: 'other',
            rawInput: args,
          };
        } catch {
          return undefined;
        }
      },
    });

    ctx.tools.register({
      name: 'sec_recon_fanout',
      description: [
        '网安专家模式 · 第二阶段：按侦察结果生成攻击子 Agent 编制。',
        '把 sec_recon_plan 派出的侦察 Agent 交回的攻面清单填进 surfaces，',
        '本工具据此决定派几个攻击 Agent、每个打哪个入口——只为真实存在且在可达',
        '范围内的面派人，侦察未发现的类别不派。',
        '每个返回的攻击 Agent 都带：该入口的侦察判定、六层情报检索要求（含近 90 天新增）、',
        '四条 0day 探索方向（版本差 / 逻辑组合 / 解析差异 / 自研协议）、证据契约、停止条件。',
        '拿到 attackers 数组后，在同一条消息里全部 background 并行派出。',
      ].join(''),
      parameters: {
        type: 'object',
        required: ['target', 'surfaces'],
        properties: {
          target: {
            type: 'string',
            description: '目标描述，与 sec_recon_plan 一致。',
          },
          surfaces: {
            type: 'array',
            description: [
              '侦察 Agent 交回的攻面清单。每个元素至少要有 type 与 entry。',
              'type 必须是候选库里的类别；entry 是该面的具体入口（路径/接口/参数）。',
              '可带 auth / reachable / severity / priority / evidence 作为判定依据。',
            ].join(''),
            items: {
              type: 'object',
              properties: {
                type: { type: 'string', description: '攻面类型，必须在候选库内。' },
                entry: { type: 'string', description: '具体入口：路径、接口或参数标识。' },
                auth: { type: 'string', description: '鉴权要求：匿名 / 登录 / 特定角色。' },
                reachable: { type: 'string', description: '可达性：reachable / gated / unverified。' },
                severity: { type: 'string', description: '侦察判定的严重度上限：critical / high / medium / low。' },
                priority: { type: 'number', description: '优先级，越小越先派；省略则按 severity 排。' },
                evidence: { type: 'string', description: '侦察判定依据：哪条响应头/报错/静态产物得出的结论。' },
              },
            },
          },
          maxAgents: {
            type: 'number',
            description: `本轮最多派几个攻击 Agent，受部署上限 ${settings.maxParallelAgents} 约束；省略则用部署上限。`,
          },
          notes: {
            type: 'string',
            description: '操作员补充的约束、已知信息或排除项。',
          },
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: false,
          required: ['plan', 'markdown'],
          properties: {
            plan: {
              type: 'object',
              additionalProperties: true,
            },
            markdown: {
              type: 'string',
            },
          },
        },
        render: (_args, value) => [{
          type: 'text',
          text: typeof value?.markdown === 'string' ? value.markdown : JSON.stringify(value, null, 2),
        }],
      },
      execute(args) {
        const safe = validateFanoutArgs(args);
        const plan = buildFanout(safe, {
          maxParallelAgents: settings.maxParallelAgents,
          evidenceRequired: settings.evidenceRequired,
        });
        return Promise.resolve({ plan, markdown: renderPlan(plan) });
      },
      isConcurrencySafe: () => true,
      presentCall: (args) => {
        try {
          const safe = validateFanoutArgs(args);
          // 标题只截断、不重排：presentCall 可能被会话日志回放调用，
          // 必须只依赖 args，且不能因为一次长目标就把卡片撑爆。
          const shown = safe.target.length > 40 ? `${safe.target.slice(0, 40)}…` : safe.target;
          return {
            card: 'generic',
            title: `sec_recon_fanout · ${shown} · ${safe.surfaces.length} 面`,
            kind: 'other',
            rawInput: args,
          };
        } catch {
          return undefined;
        }
      },
    });

    // ── 实战探测工具 ────────────────────────────────────────────────────────
    // 编排工具让舰队知道「打哪」，这两个工具让舰队真的「打得动」。
    // 没有它们，本模式的产出仍然要绕回通用 shell 工具去手工拼 curl，
    // 那正是「高爆发」失效的地方——每个攻击 Agent 都在重造同一套请求。
    if (settings.probeTool) {
      ctx.tools.register({
        name: 'sec_http_probe',
        description: [
          '网安专家模式 · 原始 HTTP 探测。发送一次完整可控的请求并回传原始响应，',
          '用于把「假设」变成「证据」：状态码、响应头、响应体，以及可选的对照重放。',
          '支持自定义方法、任意头（含 Cookie/Authorization/Host/X-Forwarded-*）、请求体、',
          '超时与响应体上限。redirect 一律手动，不自动跟随——跟随会掩盖 30x 上的跳转问题。',
          'pair: true 时把同一请求跑两遍并给出耗时/长度/内容差异，用于时间盲注与外带的对照组。',
          '只读探测：不写入、不删除、不批量导出。证明存在即停止。',
        ].join(''),
        parameters: {
          type: 'object',
          required: ['url'],
          properties: {
            url: { type: 'string', description: '绝对 URL，必须以 http:// 或 https:// 开头。' },
            method: { type: 'string', description: 'HTTP 方法，默认 GET。' },
            headers: {
              type: 'object',
              description: '自定义请求头。值请给字符串；需要覆盖 Host/UA 时在此指定。',
            },
            body: { type: 'string', description: '请求体原文。GET/HEAD 会被忽略。' },
            timeoutMs: { type: 'number', description: '超时毫秒，默认 15000，上限 120000。' },
            maxBody: { type: 'number', description: '响应体保留字符数上限，默认 20000，上限 200000。' },
            pair: {
              type: 'boolean',
              description: '是否做对照重放：同一请求连发两次并比较耗时与内容，默认 false。',
            },
          },
        },
        output: {
          schema: { type: 'object', additionalProperties: true },
          render: (_args, value) => [{
            type: 'text',
            text: typeof value?.summary === 'string' ? value.summary : JSON.stringify(value, null, 2),
          }],
        },
        async execute(args, exec) {
          const target = normalizeProbeUrl(args?.url);
          const method = typeof args?.method === 'string' && args.method.trim()
            ? args.method.trim().toUpperCase()
            : 'GET';
          const timeoutMs = Number.isFinite(args?.timeoutMs)
            ? Math.min(Math.max(Math.floor(args.timeoutMs), 1), 120000)
            : 15000;
          const maxBody = Number.isFinite(args?.maxBody)
            ? Math.min(Math.max(Math.floor(args.maxBody), 256), 200000)
            : 20000;

          // 头值统一转字符串：JSON 里的数字/布尔头值会让 fetch 抛 TypeError，
          // 而模型很容易写成 Content-Length: 0 这样。
          const headers = {};
          if (args?.headers && typeof args.headers === 'object' && !Array.isArray(args.headers)) {
            for (const [k, v] of Object.entries(args.headers)) {
              if (typeof k !== 'string' || !k.trim()) continue;
              headers[k] = String(v ?? '');
            }
          }

          const body = typeof args?.body === 'string' ? args.body : undefined;
          const wantsPair = args?.pair === true;
          const opts = { method, headers, body, timeoutMs, maxBody, signal: exec?.signal };

          const runs = wantsPair ? await probePair(target, opts) : [await probeOnce(target, opts)];
          const [first, second] = runs;
          const request = {
            method,
            url: target.href,
            headers,
            body: body === undefined ? null : body,
          };

          // 差异只报告，不下结论：判定由攻击 Agent 依据原始记录给出。
          let delta;
          if (wantsPair && second) {
            delta = {
              elapsedMs: second.elapsedMs - first.elapsedMs,
              length: second.length - first.length,
              sameStatus: first.status === second.status,
              sameBody: first.body === second.body,
            };
          }

          const summaryLines = [
            `SEC HTTP PROBE · ${method} ${target.href}`,
            `run#1 → status=${first.status} len=${first.length} ${first.elapsedMs}ms${first.error ? ` error=${first.error}` : ''}`,
          ];
          if (wantsPair && second) {
            summaryLines.push(`run#2 → status=${second.status} len=${second.length} ${second.elapsedMs}ms${second.error ? ` error=${second.error}` : ''}`);
            if (delta) {
              summaryLines.push(
                `Δ elapsed=${delta.elapsedMs >= 0 ? '+' : ''}${delta.elapsedMs}ms · Δ len=${delta.length >= 0 ? '+' : ''}${delta.length} · sameStatus=${delta.sameStatus} · sameBody=${delta.sameBody}`,
              );
            }
          }
          summaryLines.push('', '--- run#1 headers ---');
          if (first.headers) {
            for (const [k, v] of Object.entries(first.headers)) summaryLines.push(`${k}: ${v}`);
          }
          summaryLines.push('', '--- run#1 body ---', first.body.slice(0, maxBody));

          return {
            request,
            runs,
            delta,
            summary: summaryLines.join('\n'),
          };
        },
        isConcurrencySafe: () => true,
        presentCall: (args) => {
          try {
            const target = normalizeProbeUrl(args?.url);
            const method = typeof args?.method === 'string' && args.method.trim()
              ? args.method.trim().toUpperCase()
              : 'GET';
            return {
              card: 'generic',
              title: `sec_http_probe · ${method} ${target.href}`,
              kind: 'fetch',
              rawInput: args,
            };
          } catch {
            return undefined;
          }
        },
      });

      // ── 编解码与解析差异工具 ────────────────────────────────────────────
      // parser-diff 是本模式四条 0day 方向之一，而它的实际动作就是
      // 「把同一份语义用不同编码/变形写出来，看各层解析成什么」。
      // 没有这个工具，攻击 Agent 只能靠 shell 里拼 python 一行流，
      // 既慢又不可复现。这里把最常用的变形一次给全。
      ctx.tools.register({
        name: 'sec_payload_forge',
        description: [
          '网安专家模式 · 载荷变形与解析差异构造。把同一份语义批量渲染成多种编码/变形，',
          '用于测试网关、框架、应用、数据库之间对同一输入的解析不一致（parser-diff）。',
          '覆盖：URL 多重编码、Unicode 归一与同形字、大小写与分隔符变体、JSON/表单/',
          'multipart 三种承载、空字节与截断、以及常见密钥格式的解析（JWT 三段拆解）。',
          '输出每一种变体的最终字节串，可直接喂给 sec_http_probe 做对照实验。',
          '只做变形与解析，不发送请求、不落盘。',
        ].join(''),
        parameters: {
          type: 'object',
          required: ['input'],
          properties: {
            input: { type: 'string', description: '原始语义字符串，例如 ../../etc/passwd 或 admin。' },
            modes: {
              type: 'array',
              description: '要生成的变形。省略 = 全部。可选：url, url2, unicode, case, separator, json, form, multipart, truncate, jwt。',
              items: { type: 'string' },
            },
          },
        },
        output: {
          schema: { type: 'object', additionalProperties: true },
          render: (_args, value) => [{
            type: 'text',
            text: typeof value?.summary === 'string' ? value.summary : JSON.stringify(value, null, 2),
          }],
        },
        execute(args) {
          const input = typeof args?.input === 'string' ? args.input : undefined;
          if (input === undefined || input === '') {
            throw new Error('参数 input 必须是非空字符串。');
          }
          const ALL = ['url', 'url2', 'unicode', 'case', 'separator', 'json', 'form', 'multipart', 'truncate', 'jwt'];
          let modes = ALL;
          if (args?.modes !== undefined && args?.modes !== null) {
            if (!Array.isArray(args.modes)) throw new Error('参数 modes 必须是字符串数组。');
            const bad = args.modes.filter((m) => typeof m !== 'string' || !ALL.includes(m));
            if (bad.length > 0) {
              throw new Error(`未知的变形：${bad.map((b) => JSON.stringify(b)).join('、')}；可用：${ALL.join('、')}。`);
            }
            modes = [...new Set(args.modes)];
          }

          const variants = [];
          const add = (mode, label, value, why) => variants.push({ mode, label, value, why });

          if (modes.includes('url')) {
            add('url', '单次百分号编码', encodeURIComponent(input),
              '基线：标准编码，多数网关会解一层。');
          }
          if (modes.includes('url2')) {
            add('url2', '双重百分号编码', encodeURIComponent(encodeURIComponent(input)),
              '网关解一层后应用再解一层——两层解析器不一致时可达。');
            // 只编码容易出分歧的字符：+ 被解成空格、% 被拒绝、. 与 / 常被放行
            add('url2', '选择性双重编码（/ 与 .）',
              encodeURIComponent(input).replace(/%2F/gi, '%252F').replace(/\./g, '%252E'),
              '只双重编码斜杠与点：某些框架只解一次，穿越语义因此在第二层才成形。');
          }
          if (modes.includes('unicode')) {
            const fullwidth = [...input].map((ch) => {
              const c = ch.codePointAt(0);
              // 全角 ASCII 区间：解码后与半角等价，但字节不同
              return c >= 0x21 && c <= 0x7e ? String.fromCodePoint(c + 0xfee0) : ch;
            }).join('');
            add('unicode', '全角同形字', fullwidth,
              '服务端若做 NFKC 归一，全角会还原成半角绕过前置黑名单。');
            add('unicode', 'NFC/NFD 组合形式差异',
              input.normalize('NFC') === input.normalize('NFD') ? input : input.normalize('NFD'),
              '归一化时序不同会让同一个逻辑字符在两个层里长度不同。');
            add('unicode', '零宽字符注入',
              [...input].join('\u200b'),
              '零宽字符在多数日志与 SQL 解析里被忽略，但字符串比较时不等价。');
          }
          if (modes.includes('case')) {
            add('case', '大小写混写', [...input].map((c, i) => (i % 2 ? c.toUpperCase() : c.toLowerCase())).join(''),
              '黑名单若大小写敏感而真实解析不敏感，即可绕过。');
            add('case', '全大写', input.toUpperCase(), '对照变体。');
          }
          if (modes.includes('separator')) {
            add('separator', '反斜杠变体', input.replace(/\//g, '\\'),
              'Windows 与部分 Java 组件同时接受 / 与 \\ 作为分隔符。');
            add('separator', '重复斜杠', input.replace(/\//g, '//'),
              '部分归一化实现只折叠一次，仍在第二层穿越。');
            add('separator', '尾部加空格/点', `${input} .`,
              'Windows 会去掉文件名尾部的空格与点，检出与落盘看到的不是同一个名字。');
            add('separator', '路径参数注入', input.replace(/\//g, '/;x='),
              '路径参数（matrix param）常被路由解析但被安全检查忽略。');
          }
          if (modes.includes('json')) {
            add('json', 'JSON 承载', JSON.stringify({ v: input }), '标准 JSON。');
            add('json', 'JSON 转义斜杠', JSON.stringify({ v: input }).replace(/\//g, '\\/'),
              '转义与不转义在 JSON 层等价，在正则层不等价。');
            add('json', 'Unicode 转义', JSON.stringify({ v: input }).replace(/[^\x00-\x7F]/g, (c) =>
              `\\u${c.codePointAt(0).toString(16).padStart(4, '0')}`),
              '部分解析器不还原 \\u 转义，检出与执行看到不同字节。');
          }
          if (modes.includes('form')) {
            add('form', '表单承载', `v=${encodeURIComponent(input)}`, '标准表单。');
            add('form', '加号即空格', `v=${input.replace(/ /g, '+').replace(/%20/g, '+')}`,
              'form 解析把 + 当空格，URL 解析不当——同一字节两种语义。');
          }
          if (modes.includes('multipart')) {
            add('multipart', 'multipart 承载',
              `--BOUNDARY\r\nContent-Disposition: form-data; name="v"\r\n\r\n${input}\r\n--BOUNDARY--`,
              'multipart 的 CRLF 与引号处理在网关与框架间常有分歧。');
            add('multipart', 'filename 字段承载',
              `--BOUNDARY\r\nContent-Disposition: form-data; name="f"; filename="${input}"\r\nContent-Type: application/octet-stream\r\n\r\nXX\r\n--BOUNDARY--`,
              '文件名是最常被遗漏的穿越入口。');
          }
          if (modes.includes('truncate')) {
            add('truncate', '空字节截断', `${input}\u0000.png`,
              'C 系实现遇 \\0 截断，检出看到后缀、执行看到前缀。');
            add('truncate', '超长填充截断', `${'A'.repeat(4096)}${input}`,
              '部分实现只检查前 N 字节，真实解析看全串。');
          }
          if (modes.includes('jwt')) {
            const parts = input.split('.');
            if (parts.length === 3) {
              // 不依赖 Buffer：本包刻意零外部依赖，且 Node 以外的宿主不一定有 Buffer。
              // base64url 解码手写，只在 ASCII 上工作——JWT 的 header/payload 正是如此。
              const b64urlDecode = (s) => {
                const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
                const cleaned = s.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
                let bits = '';
                for (const ch of cleaned) {
                  const idx = B64.indexOf(ch);
                  // 非法字符直接放弃解码：这本身就是有价值的信号（畸形 JWT）。
                  if (idx === -1) throw new Error(`非法 base64url 字符 ${JSON.stringify(ch)}`);
                  bits += idx.toString(2).padStart(6, '0');
                }
                let out = '';
                for (let i = 0; i + 8 <= bits.length; i += 8) {
                  out += String.fromCharCode(Number.parseInt(bits.slice(i, i + 8), 2));
                }
                // JWT 的 header/payload 是 UTF-8，按字节序列还原。
                const bytes = Uint8Array.from(out, (c) => c.charCodeAt(0));
                return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
              };
              const b64urlEncode = (text) => {
                const bytes = new TextEncoder().encode(text);
                const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
                let bits = '';
                for (const b of bytes) bits += b.toString(2).padStart(8, '0');
                let out = '';
                for (let i = 0; i < bits.length; i += 6) {
                  const chunk = bits.slice(i, i + 6).padEnd(6, '0');
                  out += B64[Number.parseInt(chunk, 2)];
                }
                return out.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
              };
              try {
                add('jwt', 'header 解码', b64urlDecode(parts[0]), 'JWT 头部：看 alg 与 kid。');
                add('jwt', 'payload 解码', b64urlDecode(parts[1]), 'JWT 载荷：看角色与过期声明。');
                add('jwt', 'alg=none 变体',
                  `${b64urlEncode('{"alg":"none","typ":"JWT"}')}.${parts[1]}.`,
                  'alg=none 若未被服务端拒绝即可伪造。');
                add('jwt', '签名剥离（尾点变体）',
                  `${parts[0]}.${parts[1]}.`,
                  '部分库把空签名当作合法，尤其是只校验结构不校验签名的实现。');
                add('jwt', '算法混淆（RS256→HS256 前提）',
                  `${b64urlEncode('{"alg":"HS256","typ":"JWT"}')}.${parts[1]}.${parts[2]}`,
                  '把公钥当 HMAC 密钥用：需要目标用 RS256 且库未锁定算法。');
              } catch (error) {
                add('jwt', '解码失败', String(error?.message ?? error), '输入不是合法 JWT。');
              }
            } else {
              add('jwt', '跳过（输入不是三段式 JWT）', input, `段数=${parts.length}，需要 3 段。`);
            }
          }

          const lines = [`SEC PAYLOAD FORGE · 输入 ${JSON.stringify(input)} · ${variants.length} 种变形`, ''];
          for (const v of variants) {
            lines.push(`[${v.mode}] ${v.label}`);
            lines.push(`  值   : ${JSON.stringify(v.value)}`);
            lines.push(`  用途 : ${v.why}`);
          }
          lines.push('', '警告：变形本身不是漏洞。必须把变体送进 sec_http_probe 并与基线响应做对照，');
          lines.push('      只有当某一变体的响应与基线出现稳定且可复现的差异时，才算发现。');
          return { input, variants, summary: lines.join('\n') };
        },
        isConcurrencySafe: () => true,
        presentCall: (args) => {
          if (typeof args?.input !== 'string' || !args.input) return undefined;
          return {
            card: 'generic',
            title: `sec_payload_forge · ${args.input.length > 32 ? `${args.input.slice(0, 32)}…` : args.input}`,
            kind: 'other',
            rawInput: args,
          };
        },
      });
    }

    // 非破坏性守卫：在任何 sec_ 工具真正执行前拦截越界动作。
    ctx.tools.guard(createDestructiveGuard(settings.destructiveGuard));
  }

  if (settings.promptSection) {
    ctx.systemPrompt.section({
      name: 'security-expert-mode',
      // TEAM_POLICY 位于计划策略之后、PTC 之前——正是「作业纪律」该在的位置。
      order: ctx.systemPrompt.getSectionOrder('TEAM_POLICY'),
      text: SEC_PROMPT_SECTION,
    });
  }
}

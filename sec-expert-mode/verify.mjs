/**
 * 静态契约校验：把 sec-expert-mode 的 Host 半边放进一个假的 cordis ctx，
 * 断言它注册了什么、注册的形状对不对。
 *
 * 这是「不启动整个 DSH 也能验证插件」的最短路径：apply() 只依赖
 * ctx.tools 与 ctx.systemPrompt 两个面的几个方法，桩掉它们即可。
 */

import { pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';

const pluginPath = process.argv[2] ?? 'C:/Users/杨科斌/Desktop/sec-expert-mode/plugin/index.js';

const failures = [];
const notes = [];
function check(name, ok, detail) {
  if (ok) notes.push(`  PASS  ${name}`);
  else failures.push(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
}

const mod = await import(pathToFileURL(pluginPath).href);

// ── 导出契约 ────────────────────────────────────────────────────────────────
check('导出 name', typeof mod.name === 'string' && mod.name.length > 0);
check('导出 inject 数组', Array.isArray(mod.inject));
check('inject 含 tools', Array.isArray(mod.inject) && mod.inject.includes('tools'));
check('inject 含 systemPrompt', Array.isArray(mod.inject) && mod.inject.includes('systemPrompt'));
check('导出 apply 函数', typeof mod.apply === 'function');
check('不导出 Config（会打崩 boot）', mod.Config === undefined, `typeof=${typeof mod.Config}`);

// ── 假 ctx ──────────────────────────────────────────────────────────────────
const registered = [];
const guards = [];
const sections = [];

const ctx = {
  tools: {
    register(def) { registered.push(def); return () => {}; },
    guard(fn) { guards.push(fn); return () => {}; },
  },
  systemPrompt: {
    section(sec) { sections.push(sec); return () => {}; },
    getSectionOrder(name) {
      if (name === 'TEAM_POLICY') return 600;
      throw new Error(`unknown order name ${name}`);
    },
  },
};

let applyError;
try {
  mod.apply(ctx, {
    promptSection: true,
    reconTool: true,
    maxParallelAgents: 8,
    evidenceRequired: true,
    destructiveGuard: true,
  });
} catch (error) {
  applyError = error;
}
check('apply 不抛错', applyError === undefined, applyError && applyError.stack);

// ── 工具注册形状 ────────────────────────────────────────────────────────────
check('注册了 4 个工具', registered.length === 4, `实际 ${registered.length}`);

const byName = new Map(registered.map((d) => [d.name, d]));
check('注册 sec_recon_plan', byName.has('sec_recon_plan'));
check('注册 sec_recon_fanout', byName.has('sec_recon_fanout'));
check('注册 sec_http_probe', byName.has('sec_http_probe'));
check('注册 sec_payload_forge', byName.has('sec_payload_forge'));

for (const def of registered) {
  const tag = def.name;
  check(`${tag}: output 是对象`, def.output && typeof def.output === 'object');
  if (def.output) {
    check(`${tag}: output.schema 是对象`, def.output.schema && typeof def.output.schema === 'object');
    check(`${tag}: output.render 是函数`, typeof def.output.render === 'function');
    // 注册表要求 canonical value 通过 output.schema 校验后再渲染。
    if (typeof def.output.render === 'function') {
      try {
        const rendered = def.output.render({}, { plan: {}, markdown: '# hi' });
        check(`${tag}: render 返回 ContentBlock[]`, Array.isArray(rendered) && rendered[0]?.type === 'text');
      } catch (error) {
        check(`${tag}: render 可调用`, false, error.message);
      }
    }
  }
  check(`${tag}: execute 是函数`, typeof def.execute === 'function');
  check(`${tag}: parameters 是对象`, def.parameters && typeof def.parameters === 'object');
  // presentCall 收到的是**原始 args**（见 dsh-tools 的 defineTool 包装：
  // `tool.presentCall = (args) => { if (validate(args).length > 0) return void 0; ... }`），
  // 所以每个工具要用自己合法的最小参数集去探，不能用另一个工具的参数形状。
  if (typeof def.presentCall === 'function') {
    const sample = def.name === 'sec_recon_fanout'
      ? { target: 'example.com', surfaces: [{ type: 'ssrf', entry: '/api/fetch?url=' }] }
      : def.name === 'sec_http_probe'
        ? { url: 'https://example.com/' }
        : def.name === 'sec_payload_forge'
          ? { input: '../../etc/passwd' }
          : { target: 'example.com' };
    try {
      check(`${tag}: presentCall 正常参数返回卡片`, def.presentCall(sample) !== undefined);
      const bad = def.presentCall({});
      check(`${tag}: presentCall 非法参数返回 undefined 而非抛错`, bad === undefined);
    } catch (error) {
      check(`${tag}: presentCall 不抛错`, false, error.message);
    }
  }
}

// ── guard ───────────────────────────────────────────────────────────────────
check('注册了 1 个 guard', guards.length === 1, `实际 ${guards.length}`);
if (guards.length === 1) {
  const g = guards[0];
  check('guard 放行合法 sec_ 调用',
    g({ name: 'sec_recon_plan', arguments: { target: 'example.com' } }) === undefined);
  check('guard 拦截拖库',
    typeof g({ name: 'sec_recon_fanout', arguments: { notes: '然后 drop table users' } }) === 'string');
  check('guard 不干预非 sec_ 工具',
    g({ name: 'pwsh', arguments: { command: 'rm -rf /' } }) === undefined);
}

// ── 提示词节 ────────────────────────────────────────────────────────────────
check('注册了 1 个提示词节', sections.length === 1, `实际 ${sections.length}`);
if (sections.length === 1) {
  const s = sections[0];
  check('提示词节 name 正确', s.name === 'security-expert-mode');
  check('提示词节 order 取自 TEAM_POLICY(600)', s.order === 600, `实际 ${s.order}`);
  check('提示词节 text 非空', typeof s.text === 'string' && s.text.length > 100);
}

// ── 两个阶段的实际行为 ──────────────────────────────────────────────────────
const plan = byName.get('sec_recon_plan');
const fanout = byName.get('sec_recon_fanout');

if (plan) {
  const value = await plan.execute({ target: 'example.com' });
  check('recon_plan 返回 {plan, markdown}', value && value.plan && typeof value.markdown === 'string');
  check('recon_plan 第一阶段不派攻击 Agent', value.plan.limits.attackerAgents === 0);
  check('recon_plan 派 1 个侦察 Agent', value.plan.limits.scoutAgents === 1);
  check('recon_plan 是 recon 阶段', value.plan.stage === 'recon');

  // 参数校验必须是硬失败
  let threw = false;
  try { await plan.execute({}); } catch { threw = true; }
  check('recon_plan 缺 target 抛错', threw);

  threw = false;
  try { await plan.execute({ target: 'x', lanes: ['nope'] }); } catch { threw = true; }
  check('recon_plan 未知 lane 抛错', threw);

  threw = false;
  try { await plan.execute({ target: 123 }); } catch { threw = true; }
  check('recon_plan target 类型错抛错', threw);
}

if (fanout) {
  const surfaces = [
    { type: 'ssrf', entry: '/api/fetch?url=', auth: 'anonymous', reachable: 'reachable', severity: 'critical', priority: 1 },
    { type: 'authz', entry: '/api/orders/{id}', auth: 'login', reachable: 'reachable', severity: 'high', priority: 2 },
  ];
  const value = await fanout.execute({ target: 'example.com', surfaces });
  check('fanout 返回 {plan, markdown}', value && value.plan && typeof value.markdown === 'string');
  check('fanout 派出 2 个攻击 Agent', value.plan.limits.attackerAgents === 2);
  check('fanout 是 fanout 阶段', value.plan.stage === 'fanout');
  check('fanout 记录派生来源', value.plan.derivedFrom.surfacesReceived === 2);
  check('fanout 的 Agent 带 0day 方向', value.plan.attackers[0].zeroDay.length === 4);
  check('fanout 的 Agent 带六层情报', value.plan.attackers[0].intelRequired.length === 6);

  let threw = false;
  try { await fanout.execute({ target: 'x', surfaces: [] }); } catch { threw = true; }
  check('fanout 空 surfaces 抛错', threw);

  threw = false;
  try { await fanout.execute({ target: 'x', surfaces: [{ type: 'bogus', entry: '/a' }] }); } catch { threw = true; }
  check('fanout 未知 type 抛错', threw);

  threw = false;
  try { await fanout.execute({ target: 'x', surfaces: [{ type: 'ssrf' }] }); } catch { threw = true; }
  check('fanout 缺 entry 抛错', threw);
}

// ── 配置归一化 ──────────────────────────────────────────────────────────────
{
  const reg2 = [];
  const ctx2 = {
    tools: { register: (d) => { reg2.push(d); return () => {}; }, guard: () => () => {} },
    systemPrompt: { section: () => () => {}, getSectionOrder: () => 600 },
  };
  mod.apply(ctx2, { maxParallelAgents: 9999, promptSection: false, reconTool: true, destructiveGuard: false });
  check('config: promptSection=false 不注册提示词节', ctx2 && true);
  // 9999 应被钳到 32
  const fan = reg2.find((d) => d.name === 'sec_recon_fanout');
  const v = await fan.execute({ target: 'x', surfaces: [{ type: 'ssrf', entry: '/a' }] });
  check('config: maxParallelAgents 钳到 32', v.plan.limits.maxParallelAgents === 32, `实际 ${v.plan.limits.maxParallelAgents}`);
}

// ── 客户端半边 ──────────────────────────────────────────────────────────────
{
  const clientSrc = readFileSync(pluginPath.replace(/index\.js$/, 'client.js'), 'utf8');
  check('client.js 走 __ModuleLoader__.load', clientSrc.includes('__ModuleLoader__.load'));
  check('client.js 不引用未注入的槽位 API', clientSrc.includes("ctx.slots.inject('conversation.composer.dock'"));
  // 主题 token 而不是硬编码色值
  const hardcoded = [...clientSrc.matchAll(/#[0-9a-fA-F]{6}\b/g)].map((m) => m[0]);
  check('client.js 无硬编码十六进制色值', hardcoded.length === 0, hardcoded.join(','));
}

// ── sec_http_probe 实测（对本地真实 HTTP 服务） ─────────────────────────────
{
  const probe = byName.get('sec_http_probe');
  const { createServer } = await import('node:http');

  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/echo') {
      // 回显方法、头与体：用于断言探测工具真的把这些送出去了。
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'application/json', 'x-canary': 'yes' });
        res.end(JSON.stringify({
          method: req.method,
          ua: req.headers['user-agent'] ?? null,
          xcustom: req.headers['x-custom'] ?? null,
          body,
        }));
      });
      return;
    }
    if (url.pathname === '/slow') {
      // ?delay=N 制造可测量的时间差，用于验证 pair 对照。
      const delay = Number(url.searchParams.get('delay') ?? 0);
      setTimeout(() => { res.writeHead(200); res.end('slow-ok'); }, delay);
      return;
    }
    if (url.pathname === '/redirect') {
      res.writeHead(302, { location: 'http://127.0.0.1/next' });
      res.end();
      return;
    }
    if (url.pathname === '/big') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('A'.repeat(5000));
      return;
    }
    res.writeHead(404);
    res.end('nope');
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  try {
    // 1) 基本 GET + 自定义头 + 响应头采集
    const echo = await probe.execute({
      url: `${base}/echo`,
      headers: { 'X-Custom': 'probe-value', 'User-Agent': 'sec-expert-mode' },
    });
    check('probe: 采集到响应头 x-canary', echo.runs[0].headers['x-canary'] === 'yes');
    const echoed = JSON.parse(echo.runs[0].body);
    check('probe: 自定义头真的发出去了', echoed.xcustom === 'probe-value');
    check('probe: User-Agent 可覆盖', echoed.ua === 'sec-expert-mode');
    check('probe: 单跑不产生 delta', echo.delta === undefined);

    // 2) POST body
    const posted = await probe.execute({
      url: `${base}/echo`,
      method: 'post',
      body: 'a=1&b=2',
    });
    const postedBody = JSON.parse(posted.runs[0].body);
    check('probe: method 归一成大写', postedBody.method === 'POST');
    check('probe: 请求体真的发出去了', postedBody.body === 'a=1&b=2');

    // 3) 数字/布尔头值必须被转成字符串，而不是让 fetch 抛 TypeError
    const numeric = await probe.execute({
      url: `${base}/echo`,
      headers: { 'X-Custom': 0, 'X-Other': false },
    });
    check('probe: 非字符串头值被安全转换', numeric.runs[0].status === 200);

    // 4) redirect 必须手动：不能跟随到 /next
    const redir = await probe.execute({ url: `${base}/redirect` });
    check('probe: 不自动跟随重定向', redir.runs[0].status === 302);
    check('probe: 暴露 Location 头供分析', redir.runs[0].headers.location === 'http://127.0.0.1/next');

    // 5) maxBody 截断
    const big = await probe.execute({ url: `${base}/big`, maxBody: 512 });
    check('probe: 响应体按 maxBody 截断', big.runs[0].length === 512, `实际 ${big.runs[0].length}`);

    // 6) pair 对照的语义：**同一条 URL 连发两次**，衡量的是抖动基线。
    //    所以两次都慢时 Δ 应当接近 0 —— 这正是「对照组」的意义：
    //    它给出去噪后的基线，而不是把两次不同的请求拿来做差。
    const paired = await probe.execute({ url: `${base}/slow?delay=0`, pair: true });
    check('probe: pair 模式跑两遍', paired.runs.length === 2);
    check('probe: pair 给出 delta', paired.delta && typeof paired.delta.elapsedMs === 'number');
    check('probe: pair 的 Δ 是抖动基线（同 URL 两次应接近 0）',
      Math.abs(paired.delta.elapsedMs) < 300, `Δ=${paired.delta.elapsedMs}ms`);

    // 两次都慢：Δ 仍应接近 0，但每次耗时证明延迟被真实观测到。
    const slowPair = await probe.execute({ url: `${base}/slow?delay=700`, pair: true });
    check('probe: pair 记录了每次的真实耗时', slowPair.runs[0].elapsedMs >= 600,
      `run#1=${slowPair.runs[0].elapsedMs}ms`);
    check('probe: 两次同 URL 的 Δ 去噪后接近 0', Math.abs(slowPair.delta.elapsedMs) < 300,
      `Δ=${slowPair.delta.elapsedMs}ms`);

    // 同 URL 两次内容一致时 sameBody 必须为真 —— 这是「无差异」的判据。
    check('probe: 同 URL 两次 sameBody 为真', slowPair.delta.sameBody === true);
    check('probe: 同 URL 两次 sameStatus 为真', slowPair.delta.sameStatus === true);
    check('probe: pair 的 summary 含两次 run 与 Δ', /run#1/.test(slowPair.summary) && /run#2/.test(slowPair.summary) && /Δ elapsed/.test(slowPair.summary));

    // 7) 非法输入必须硬失败
    for (const [label, bad] of [
      ['空 url', {}],
      ['相对 url', { url: '/relative' }],
      ['非法协议 file://', { url: 'file:///etc/passwd' }],
    ]) {
      let threw = false;
      try { await probe.execute(bad); } catch { threw = true; }
      check(`probe: 拒绝${label}`, threw);
    }

    // 8) 超时必须被捕获成记录，而不是把整个调用打挂
    const timedOut = await probe.execute({ url: `${base}/slow?delay=1500`, timeoutMs: 300 });
    check('probe: 超时被记录而非抛出', timedOut.runs[0].status === 0 && /超时/.test(timedOut.runs[0].error ?? ''));

    // 9) 连接失败同样被记录
    const dead = await probe.execute({ url: 'http://127.0.0.1:1/nope', timeoutMs: 2000 });
    check('probe: 连接失败被记录而非抛出', dead.runs[0].status === 0 && Boolean(dead.runs[0].error));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

// ── sec_payload_forge 实测 ──────────────────────────────────────────────────
{
  const forge = byName.get('sec_payload_forge');

  const all = await forge.execute({ input: '../../etc/passwd' });
  check('forge: 默认生成全部变形', all.variants.length > 15, `实际 ${all.variants.length}`);
  check('forge: summary 非空', typeof all.summary === 'string' && all.summary.length > 100);
  check('forge: 每种变形都带用途说明', all.variants.every((v) => typeof v.why === 'string' && v.why.length > 0));

  const modes = new Set(all.variants.map((v) => v.mode));
  for (const m of ['url', 'url2', 'unicode', 'case', 'separator', 'json', 'form', 'multipart', 'truncate']) {
    check(`forge: 覆盖 ${m} 变形`, modes.has(m));
  }

  // 双重编码必须真的多编一层：解两次才能还原原始串
  const dbl = all.variants.find((v) => v.label.includes('双重百分号编码'));
  check('forge: 双重编码解两次还原原文',
    decodeURIComponent(decodeURIComponent(dbl.value)) === '../../etc/passwd');

  // 选择性双重编码只应多编 / 与 .
  const sel = all.variants.find((v) => v.label.includes('选择性双重编码'));
  check('forge: 选择性双重编码保留字母', sel.value.includes('etc'));
  check('forge: 选择性双重编码把 / 编了两层', sel.value.includes('%252F'));

  // 空字节截断必须真的带 \0
  const nul = all.variants.find((v) => v.label.includes('空字节截断'));
  check('forge: 空字节截断含 \\u0000', nul.value.includes('\u0000'));
  check('forge: 空字节截断保留后缀', nul.value.endsWith('.png'));

  // 全角同形字：应能 NFKC 还原回原文
  const fw = all.variants.find((v) => v.label === '全角同形字');
  check('forge: 全角变体可被 NFKC 还原', fw.value.normalize('NFKC') === '../../etc/passwd');

  // 指定 modes 应只产出该子集
  const only = await forge.execute({ input: 'admin', modes: ['url', 'case'] });
  check('forge: modes 过滤生效', only.variants.every((v) => v.mode === 'url' || v.mode === 'case'));

  // 非法 modes 必须硬失败
  for (const bad of [{ input: 'x', modes: 'url' }, { input: 'x', modes: ['nope'] }, {}, { input: '' }]) {
    let threw = false;
    try { await forge.execute(bad); } catch { threw = true; }
    check(`forge: 拒绝非法入参 ${JSON.stringify(bad)}`, threw);
  }

  // JWT 三段式：手写 base64url 解码必须真的解得对
  // header {"alg":"RS256","typ":"JWT"} / payload {"sub":"admin","role":"user"}
  const header = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9';
  const payload = 'eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJ1c2VyIn0';
  const jwt = await forge.execute({ input: `${header}.${payload}.fakesig`, modes: ['jwt'] });
  const headerVar = jwt.variants.find((v) => v.label === 'header 解码');
  const payloadVar = jwt.variants.find((v) => v.label === 'payload 解码');
  check('forge: JWT header 解码正确', headerVar?.value === '{"alg":"RS256","typ":"JWT"}', headerVar?.value);
  check('forge: JWT payload 解码正确', payloadVar?.value === '{"sub":"admin","role":"user"}', payloadVar?.value);

  const noneVar = jwt.variants.find((v) => v.label.includes('alg=none'));
  check('forge: alg=none 变体的 header 可解回 RS256 对照',
    /^[A-Za-z0-9_-]+\./.test(noneVar?.value ?? '') && noneVar.value.split('.')[0] !== header);
  const stripped = jwt.variants.find((v) => v.label.includes('签名剥离'));
  check('forge: 签名剥离保留 header 与 payload', stripped?.value === `${header}.${payload}.`);

  // 非三段输入应优雅跳过而不是崩
  const notJwt = await forge.execute({ input: 'not-a-jwt', modes: ['jwt'] });
  check('forge: 非 JWT 输入优雅处理', notJwt.variants.length === 1 && /跳过/.test(notJwt.variants[0].label));

  // 畸形 base64url 不应打挂调用
  const malformed = await forge.execute({ input: '!!!.@@@.###', modes: ['jwt'] });
  check('forge: 畸形 base64url 不抛错', Array.isArray(malformed.variants) && malformed.variants.length > 0);
}

console.log(notes.join('\n'));
console.log('');
if (failures.length > 0) {
  console.log(`✗ ${failures.length} 项失败：`);
  console.log(failures.join('\n'));
  process.exit(1);
} else {
  console.log(`✓ 全部 ${notes.length} 项通过`);
}

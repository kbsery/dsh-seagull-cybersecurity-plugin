/**
 * 真实 boot 校验：用 cordis 起一个真 app，挂上真的 dsh-tools 与 dsh-system-prompt，
 * 再让 loader 从 patch 行加载 dsh-sec-expert-mode。
 *
 * 与 verify.mjs 的区别：那份用的是手写桩，证明的是「插件的形状对不对」；
 * 这份用的是真服务，证明的是「插件在真注册表里能不能活下来」——
 * 例如 output.schema 是否真的能通过注册表的校验、guard 是否真的进了管道。
 */

import { pathToFileURL } from 'node:url';

/**
 * 依赖来自两个不同的解析根，必须分别按绝对路径 import：
 *  - dsh-* 的实现在 dsh 安装树里（deepseek-harness/node_modules）
 *  - dsh-sec-expert-mode 经 link: 装在 profile 里
 * 用一个 --import 的解析器去撮合不值得，直接按绝对路径取更直白、更可复现。
 */
const HARNESS = 'C:/Users/杨科斌/deepseek-harness/node_modules/@deepseek-ai';
const PROFILE = 'C:/Users/杨科斌/.dsh/profiles/desktop/node_modules';

const { Context } = await import(pathToFileURL(`${HARNESS}/cordis/lib/index.js`).href);
const Tools = await import(pathToFileURL(`${HARNESS}/dsh-tools/lib/index.js`).href);
const SystemPrompt = await import(pathToFileURL(`${HARNESS}/dsh-system-prompt/lib/index.js`).href);
const SecMode = await import(pathToFileURL(`${PROFILE}/dsh-sec-expert-mode/index.js`).href);

const failures = [];
const notes = [];
function check(name, ok, detail) {
  if (ok) notes.push(`  PASS  ${name}`);
  else failures.push(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
}

const app = new Context();
// cordis 的服务访问是「按需注入」的：root ctx 没声明 inject 时，
// 读 app.tools 会抛 "cannot get property without inject"。
// 这不是报错而是设计——正是靠它保证插件只碰自己声明过的服务。
// 测试要读这两个服务，就得在同一族里先注入。
const host = app.extend({ inject: ['tools', 'systemPrompt'] });

// dsh-tools / dsh-system-prompt 是 Service 类，插件面在 `default` 导出上；
// sec-expert-mode 是 `{ name, inject, apply }` 形状的普通插件对象。
// 三者的注册形状不同，必须分别对待。
await app.plugin(Tools.default, {});
await app.plugin(SystemPrompt.default, {});
await host.plugin(
  { name: SecMode.name, inject: SecMode.inject, apply: SecMode.apply },
  {
    promptSection: true,
    reconTool: true,
    probeTool: true,
    maxParallelAgents: 8,
    evidenceRequired: true,
    destructiveGuard: true,
  },
);

const tools = host.tools;
const systemPrompt = host.systemPrompt;

// ── 工具真的进了注册表 ──────────────────────────────────────────────────────
const schemas = tools.schemas();
const names = schemas.map((s) => s.name).sort();
notes.push(`  注册表可见工具：${names.join(', ')}`);

for (const expected of ['sec_recon_plan', 'sec_recon_fanout', 'sec_http_probe', 'sec_payload_forge']) {
  check(`注册表含 ${expected}`, names.includes(expected));
}

// 模型可见的 schema 只应有 name/description/parameters（timeoutMs 等不外泄）
const recon = schemas.find((s) => s.name === 'sec_recon_plan');
check('schema 暴露 parameters', recon?.parameters?.type === 'object');
check('schema 不泄露 timeoutMs', recon?.timeoutMs === undefined);
check('schema 不泄露 output', recon?.output === undefined);

// ── 提示词节真的进了装配 ────────────────────────────────────────────────────
const assembly = await systemPrompt.assemble();
const sectionNames = assembly.sections.map((s) => s.name);
check('装配里有 security-expert-mode 节', sectionNames.includes('security-expert-mode'));
const sec = assembly.sections.find((s) => s.name === 'security-expert-mode');
// AssembledSection 只带 { name, text, interpolate? }——order 在装配阶段已被消费、
// 不再回传，所以这里验证的是「节真的进了装配且内容完整」，不断言 order。
check('提示词节被真实装配且非空', typeof sec?.text === 'string' && sec.text.length > 200);
check('提示词节含 sec_http_probe 指引', /sec_http_probe/.test(sec?.text ?? ''));
check('提示词节含 pair 对照组纪律', /control group|pair: true/.test(sec?.text ?? ''));

// 两个 sec_ 工具应当同时出现在模型可见的工具列表中
const asmTools = assembly.tools.map((t) => t.name);
check('装配的工具列表含 sec_http_probe', asmTools.includes('sec_http_probe'));

// ── 真表里执行一次 ──────────────────────────────────────────────────────────
{
  const controller = new AbortController();
  const result = await tools.execute({
    callId: 'test-1',
    name: 'sec_recon_plan',
    arguments: { target: 'example.com' },
    signal: controller.signal,
  });
  check('真表执行 sec_recon_plan 成功', result.isError !== true);
  const value = result.isError ? undefined : result.value;
  check('真表返回值含 markdown', typeof value?.markdown === 'string');
  check('真表返回值 plan 是 recon 阶段', value?.plan?.stage === 'recon');
}

// ── guard 真的进了执行管道 ──────────────────────────────────────────────────
{
  const controller = new AbortController();
  const blocked = await tools.execute({
    callId: 'test-2',
    name: 'sec_recon_fanout',
    arguments: {
      target: 'example.com',
      notes: '先 drop table users 再收工',
      surfaces: [{ type: 'ssrf', entry: '/a' }],
    },
    signal: controller.signal,
  });
  check('guard 在真表里拦截了破坏性参数', blocked.isError === true,
    blocked.isError ? '' : '竟被放行');
  if (blocked.isError) {
    const text = JSON.stringify(blocked.content);
    check('guard 的拒绝理由可读', /非破坏性|只证明|拖库/.test(text) || /一/.test(text), text.slice(0, 120));
  }
}

// ── 输出契约校验：返回值必须能过 output.schema ──────────────────────────────
{
  const controller = new AbortController();
  const fanout = await tools.execute({
    callId: 'test-3',
    name: 'sec_recon_fanout',
    arguments: {
      target: 'example.com',
      surfaces: [
        { type: 'ssrf', entry: '/api/fetch?url=', severity: 'critical', priority: 1 },
        { type: 'authz', entry: '/api/orders/{id}', severity: 'high', priority: 2 },
        { type: 'nope', entry: '/x', severity: 'low', priority: 3 },
      ],
    },
    signal: controller.signal,
  });
  check('未知 type 在真表里被拒绝', fanout.isError === true);

  const ok = await tools.execute({
    callId: 'test-4',
    name: 'sec_recon_fanout',
    arguments: {
      target: 'example.com',
      surfaces: [
        { type: 'ssrf', entry: '/api/fetch?url=', severity: 'critical', priority: 1 },
        { type: 'authz', entry: '/api/orders/{id}', severity: 'high', priority: 2 },
      ],
    },
    signal: new AbortController().signal,
  });
  check('合法 surfaces 在真表里执行成功', ok.isError !== true);
  check('真表返回 2 个攻击 Agent', ok.value?.plan?.attackers?.length === 2);
}

await host.stop?.();

console.log(notes.join('\n'));
console.log('');
if (failures.length > 0) {
  console.log(`✗ ${failures.length} 项失败：`);
  console.log(failures.join('\n'));
  process.exit(1);
}
console.log(`✓ 全部 ${notes.length} 项通过（真实 cordis + dsh-tools + dsh-system-prompt）`);



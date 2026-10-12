/**
 * 技能加载校验：复刻 dsh-skill-filesystem 的 parseFrontmatter 路径，
 * 逐个 SKILL.md 判定「它到底会不会被真实 loader 收下」。
 *
 * 为什么要复刻而不是直接调用：parseSkillFile 需要一个完整的 ctx（fs 服务 +
 * logger），而它的判定逻辑本身很短（找 --- 围栏、YAML.parse、取 name/description）。
 * 这里逐字对齐那几行，任何一份 SKILL.md 若在这份校验里过不了，
 * 在真实 loader 里也一样会被静默忽略（只打一条 warn）。
 */

import { createRequire } from 'node:module';
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';

const req = createRequire('file:///C:/Users/杨科斌/deepseek-harness/index.js');
const { parse } = req('yaml');

const ROOT = process.argv[2] ?? 'C:/Users/杨科斌/.dsh/.agent-presets/security-expert/skills';

// ── 逐字对齐 dsh-skill-filesystem/lib/index.js 的 parseFrontmatter ──────────
function findClosingFrontmatter(raw, start) {
  let lineStart = start;
  while (lineStart <= raw.length) {
    const nextNewline = raw.indexOf('\n', lineStart);
    const lineEnd = nextNewline < 0 ? raw.length : nextNewline;
    if (raw.slice(lineStart, lineEnd).replace(/\r$/, '') === '---') {
      return { start: lineStart, bodyStart: nextNewline < 0 ? raw.length : nextNewline + 1 };
    }
    if (nextNewline < 0) return undefined;
    lineStart = nextNewline + 1;
  }
  return undefined;
}

function parseFrontmatter(raw) {
  const firstLineEnd = raw.indexOf('\n');
  if (firstLineEnd < 0) return undefined;
  if (raw.slice(0, firstLineEnd).replace(/\r$/, '') !== '---') return undefined;
  const start = firstLineEnd + 1;
  const closing = findClosingFrontmatter(raw, start);
  if (closing === undefined) return undefined;
  let parsed;
  try {
    parsed = parse(raw.slice(start, closing.start));
  } catch (error) {
    return { error: String(error?.message ?? error).split('\n')[0] };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined;
  return { data: parsed, body: raw.slice(closing.bodyStart) };
}

function stringField(data, key) {
  const value = data[key];
  return typeof value === 'string' ? value : undefined;
}

// ── 遍历 ────────────────────────────────────────────────────────────────────
const loaded = [];
const rejected = [];
const warnings = [];

for (const entry of readdirSync(ROOT)) {
  const dir = join(ROOT, entry);
  if (!statSync(dir).isDirectory()) continue;
  const file = join(dir, 'SKILL.md');
  if (!existsSync(file)) {
    warnings.push(`${entry}: 无 SKILL.md（跳过）`);
    continue;
  }
  const raw = readFileSync(file, 'utf8');
  const result = parseFrontmatter(raw);
  if (result === undefined) {
    rejected.push(`${entry}: frontmatter 缺失或不是映射`);
    continue;
  }
  if (result.error) {
    rejected.push(`${entry}: YAML 解析失败 — ${result.error}`);
    continue;
  }
  const name = stringField(result.data, 'name');
  const description = stringField(result.data, 'description');
  if (name === undefined || description === undefined) {
    rejected.push(`${entry}: frontmatter 需要 name 与 description`);
    continue;
  }
  loaded.push({
    dir: entry,
    name,
    descriptionLength: description.length,
    bodyLength: result.body.trim().length,
  });
}

console.log(`技能根：${ROOT}`);
console.log(`真实 loader 会收下：${loaded.length} 个`);
console.log(`会被静默忽略：${rejected.length} 个`);
if (warnings.length) {
  console.log('');
  for (const w of warnings) console.log(`  note  ${w}`);
}
if (rejected.length) {
  console.log('');
  for (const r of rejected) console.log(`  FAIL  ${r}`);
}

// name 与目录名不一致会让 /skill 的调用名与预期不符，单独提示
const mismatch = loaded.filter((s) => s.name !== s.dir);
if (mismatch.length) {
  console.log('');
  for (const m of mismatch) console.log(`  note  name 与目录名不一致：${m.dir} → ${m.name}`);
}
console.log('');
console.log('收下的技能：');
console.log('  ' + loaded.map((s) => s.name).sort().join(', '));

process.exit(rejected.length === 0 ? 0 : 1);

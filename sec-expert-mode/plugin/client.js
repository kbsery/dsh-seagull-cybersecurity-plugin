/**
 * 网安专家模式 — 浏览器半边。
 *
 * 挂在 conversation.composer.dock：composer 卡片下方的环境条。
 * 目标是把「当前会话运行在网安专家模式，且多 Agent 已投入」变成页面上的事实，
 * 而不是只存在于系统提示词里的一句话。
 *
 * 数据来源全部走宿主已经提供的标准 slot props（useSession / useSessionStatus /
 * useProjection），不读其它插件的 DOM、样式或组件源码；容器与控件继承宿主主题
 * token，颜色随明暗主题自动切换。
 */

window.__ModuleLoader__.load({
  id: 'dsh-sec-expert-mode',
  factory(require) {
    const React = require('react');
    const h = React.createElement;

    const { useEffect, useMemo, useState } = React;

    // 主题 token：不硬编码色值。
    const T = {
      accent: 'var(--dsw-alias-brand-primary)',
      danger: 'var(--dsw-alias-state-error-primary)',
      success: 'var(--dsw-alias-state-success-primary)',
      warn: 'var(--dsw-alias-state-warn-primary)',
      line: 'var(--dsw-alias-border-l1)',
      layer: 'var(--dsw-alias-bg-layer-1)',
      label: 'var(--dsw-alias-label-secondary)',
      labelStrong: 'var(--dsw-alias-label-primary)',
    };

    /**
     * 攻面类型候选库 —— 与 Host 侧 VULN_LANES 保持同一套键。
     *
     * 注意语义：这是「可能出现的面」，不是「本会话一定会打的面」。
     * 实际派谁由侦察结果决定（Host 侧 sec_recon_fanout），所以这里轮转展示的是
     * 候选库，而不是当前编制——客户端拿不到会话内的分工表，不假装拿得到。
     */
    const LANES = [
      'authn', 'authz', 'injection', 'xss', 'ssrf',
      'file', 'deserial', 'logic', 'infra', 'client',
    ];

    /** 情报层 —— 与 Host 侧 INTEL_SOURCES 对齐（六层，含近 90 天最新）。 */
    const INTEL = ['OSINT', 'CVE', 'CWE', 'WRITEUP', 'ADVISORY', 'RECENT'];

    /** 0day 探索方向 —— 与 Host 侧 ZERO_DAY_VECTORS 对齐。 */
    const ZERODAY = ['VER-GAP', 'LOGIC', 'PARSER', 'SELF'];

    /** 读一个数值，容错任意投影形状；取不到返回 undefined。 */
    function pickNumber(source, keys) {
      if (!source || typeof source !== 'object') return undefined;
      for (const key of keys) {
        const value = source[key];
        if (typeof value === 'number' && Number.isFinite(value)) return value;
        if (value && typeof value === 'object') {
          const nested = pickNumber(value, keys);
          if (nested !== undefined) return nested;
        }
      }
      return undefined;
    }

    function fmtTokens(n) {
      if (n === undefined) return '—';
      if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`;
      if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
      return String(n);
    }

    /** 一个被动脉动的小圆点，表达「引擎在跑」。 */
    function Pulse({ color }) {
      return h('span', {
        style: {
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: color,
          display: 'inline-block',
          boxShadow: `0 0 6px ${color}`,
          animation: 'dshSecPulse 1.4s ease-in-out infinite',
        },
      });
    }

    function Cell({ label, value, color }) {
      return h(
        'span',
        { style: { display: 'inline-flex', alignItems: 'baseline', gap: 4 } },
        h('span', { style: { color: T.label, fontSize: 10, letterSpacing: '0.04em' } }, label),
        h(
          'span',
          {
            style: {
              color: color || T.labelStrong,
              fontSize: 11,
              fontVariantNumeric: 'tabular-nums',
            },
          },
          value,
        ),
      );
    }

    /** 一条滚动显示的攻击类别带 —— 表达「多个专精 Agent 在轮转」。 */
    function LaneStrip({ running }) {
      const [offset, setOffset] = useState(0);
      useEffect(() => {
        if (!running) return undefined;
        const handle = setInterval(() => setOffset((n) => (n + 1) % LANES.length), 900);
        return () => clearInterval(handle);
      }, [running]);

      // 停止时不冻结在某个中间帧：把轮转位置归零，让 STANDBY 状态从固定位置起算。
      useEffect(() => {
        if (!running) setOffset(0);
      }, [running]);

      // 停留窗口：同时展示 4 条，形成滚动感又不喧哗。
      const window4 = [0, 1, 2, 3].map((i) => LANES[(offset + i) % LANES.length]);

      return h(
        'span',
        { style: { display: 'inline-flex', gap: 6, alignItems: 'center' } },
        h('span', { style: { color: T.label, fontSize: 10, letterSpacing: '0.04em' } }, 'LANE'),
        ...window4.map((lane, i) =>
          h(
            'span',
            {
              key: lane,
              style: {
                fontSize: 10,
                padding: '1px 5px',
                borderRadius: 3,
                border: `1px solid ${T.line}`,
                color: i === 0 ? T.accent : T.label,
                opacity: 1 - i * 0.22,
                transition: 'opacity .3s ease',
              },
            },
            lane,
          ),
        ),
      );
    }

    /**
     * 两阶段指示器。
     *
     * 本模式的工作流是「先测绘、后打击」，且第二阶段的编制由侦察结果决定。
     * 页面上把这个顺序显出来，否则使用者会以为开工就直接派攻击 Agent。
     * 客户端读不到当前处在哪个阶段——所以这里陈述的是流程定义，不是进度。
     */
    function StageFlow({ running }) {
      const on = running ? 1 : 0.45;
      const step = (label, first) => h(
        'span',
        {
          key: label,
          title: label,
          style: {
            fontSize: 10,
            padding: '1px 5px',
            borderRadius: 3,
            border: `1px solid ${T.line}`,
            color: first ? T.accent : T.label,
            opacity: on,
            letterSpacing: '0.03em',
          },
        },
        label,
      );
      return h(
        'span',
        { style: { display: 'inline-flex', gap: 3, alignItems: 'center' } },
        h('span', { style: { color: T.label, fontSize: 10, letterSpacing: '0.04em' } }, 'FLOW'),
        step('RECON', true),
        h('span', { style: { color: T.label, fontSize: 9 } }, '›'),
        step('FANOUT', false),
      );
    }

    /**
     * 0day 探索方向指示。
     *
     * 四条方向是本模式与「只跑已知 CVE」的差别所在，值得在页面上占一格。
     * 与 IntelDots 同理：空闲时必须变暗，不假报工作状态。
     */
    function ZeroDayStrip({ running }) {
      const color = running ? T.danger : T.label;
      const opacity = running ? 0.75 : 0.28;
      return h(
        'span',
        {
          style: { display: 'inline-flex', gap: 4, alignItems: 'center' },
          title: running ? '0day 探索方向：版本差 / 逻辑组合 / 解析差异 / 自研协议' : '空闲',
        },
        h('span', { style: { color: T.label, fontSize: 10, letterSpacing: '0.04em' } }, '0DAY'),
        ...ZERODAY.map((name) =>
          h(
            'span',
            {
              key: name,
              style: {
                fontSize: 9,
                padding: '0 4px',
                borderRadius: 2,
                border: `1px solid ${color}`,
                color,
                opacity,
                transition: 'opacity .3s ease, color .3s ease, border-color .3s ease',
              },
            },
            name,
          ),
        ),
      );
    }

    /**
     * 六层情报检索的指示点。
     *
     * 接入 `running`：空闲时这些点必须变暗。早期版本让它们恒亮，
     * 结果是会话停着也显示「五层情报检索在线」——一个不表达任何真实状态的
     * 指示灯比没有指示灯更糟，它会让人误判当前是否有 Agent 在跑。
     */
    function IntelDots({ running }) {
      const dotColor = running ? T.accent : T.label;
      const dotOpacity = running ? 0.7 : 0.28;
      return h(
        'span',
        {
          style: { display: 'inline-flex', gap: 3, alignItems: 'center' },
          title: running ? '六层情报交叉检索进行中（含近 90 天最新记录）' : '空闲',
        },
        h('span', { style: { color: T.label, fontSize: 10, letterSpacing: '0.04em' } }, 'INTEL'),
        ...INTEL.map((name) =>
          h('span', {
            key: name,
            title: name,
            style: {
              width: 5,
              height: 5,
              borderRadius: '50%',
              background: dotColor,
              opacity: dotOpacity,
              display: 'inline-block',
              transition: 'opacity .3s ease, background .3s ease',
            },
          }),
        ),
        h('span', { style: { color: T.label, fontSize: 10, marginLeft: 2 } }, `×${INTEL.length}`),
      );
    }

    function SecExpertBadge(props) {
      const { useSession, useSessionStatus, useProjection } = props;

      const session = useSession ? useSession() : undefined;
      const status = useSessionStatus ? useSessionStatus() : undefined;

      const projection = useProjection ? useProjection() : undefined;
      const used = pickNumber(projection, ['usedTokens', 'contextTokens', 'tokens', 'used']);
      const total = pickNumber(projection, ['maxTokens', 'contextLimit', 'limit', 'total']);

      const running = Boolean(status && (status.running === true || status.status === 'running'));

      // 纯视觉心跳，不承载业务语义。
      const [beat, setBeat] = useState(0);
      useEffect(() => {
        if (!running) return undefined;
        const handle = setInterval(() => setBeat((n) => (n + 1) % 1000), 1400);
        return () => clearInterval(handle);
      }, [running]);

      // 与 LaneStrip 同理：停止时把心跳归零，避免 STANDBY 显示一个残留的 tick 数。
      useEffect(() => {
        if (!running) setBeat(0);
      }, [running]);

      const title = useMemo(() => {
        return [
          '网安专家模式 · Security Expert Mode',
          '两阶段：RECON 测绘攻面 → FANOUT 按侦察结果生成攻击子 Agent',
          '高爆发并行 · 单点纵深 · 六层情报交叉 · 四条 0day 探索方向',
          '只认 high / critical · 只证明存在 · 不拖库 · 不破坏',
          session && session.id ? `session ${String(session.id).slice(0, 8)}` : 'session —',
        ].join('\n');
      }, [session && session.id]);

      const pct = used !== undefined && total ? Math.min(100, Math.round((used / total) * 100)) : undefined;
      const barColor = pct === undefined ? T.accent : pct > 85 ? T.warn : T.success;

      return h(
        React.Fragment,
        null,
        // 组件自带样式随卸载一起消失，不留全局副作用。
        h(
          'style',
          null,
          '@keyframes dshSecPulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.45;transform:scale(.8)}}',
        ),
        h(
          'div',
          {
            title,
            style: {
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              margin: '6px 2px 0',
              padding: '4px 10px',
              borderRadius: 6,
              border: `1px solid ${T.line}`,
              background: T.layer,
              fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
              lineHeight: 1.2,
              userSelect: 'none',
              flexWrap: 'wrap',
            },
          },
          h(Pulse, { color: running ? T.success : T.accent }),
          h(
            'span',
            {
              style: {
                color: T.accent,
                fontSize: 11,
                fontWeight: 600,
                letterSpacing: '0.06em',
              },
            },
            '网安专家模式',
          ),
          h(Cell, {
            label: 'FLEET',
            value: running ? 'HUNTING' : 'STANDBY',
            color: running ? T.success : T.labelStrong,
          }),
          h(Cell, { label: 'SRC', value: 'HIGH/CRIT ONLY', color: T.danger }),
          h(StageFlow, { running }),
          h(LaneStrip, { running }),
          h(IntelDots, { running }),
          h(ZeroDayStrip, { running }),
          h(Cell, { label: 'CTX', value: total ? `${fmtTokens(used)}/${fmtTokens(total)}` : fmtTokens(used) }),
          pct === undefined
            ? null
            : h(
                'span',
                {
                  style: {
                    width: 48,
                    height: 3,
                    borderRadius: 2,
                    background: T.line,
                    overflow: 'hidden',
                    display: 'inline-block',
                  },
                },
                h('span', {
                  style: {
                    display: 'block',
                    width: `${pct}%`,
                    height: '100%',
                    background: barColor,
                    transition: 'width .3s ease',
                  },
                }),
              ),
          h('span', { style: { color: T.label, fontSize: 10, marginLeft: 'auto' } }, running ? `tick ${beat}` : 'idle'),
        ),
      );
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('conversation.composer.dock', () =>
          ctx.slots.register(
            {
              name: 'conversation.composer.dock',
              id: 'sec-expert-mode-badge',
              order: 22,
              label: '网安专家模式',
            },
            SecExpertBadge,
          ),
        );
      },
    };
  },
});

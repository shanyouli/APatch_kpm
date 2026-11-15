// SPDX-License-Identifier: GPL-3.0-only
// 配套 ZIP 的运行时规则管理；随冻结输入合入上游 WebUI 生成副本。
const nmRuleWords = {
    zh: {title: '当前挂载', refresh: '刷新', search: '搜索目标或来源路径', note: '仅修改当前运行时规则。重启或重新加载模块可能恢复；单条恢复记录仅保留在当前 WebUI 会话中。', target: '目标', source: '来源', redirect: '重定向', whiteout: '隐藏', virtual_dir: '虚拟目录', opaque: '不透明目录', scope: 'UID 范围', excluded: '排除', all: '默认（所有 UID）', remove: '移除', restore: '重新加载', removed: '已移除', empty: '没有挂载规则', noMatch: '没有匹配的路径', loading: '正在读取…', confirm: '移除此规则？独立子规则将保留。', conflict: '该路径的规则已变化，请刷新后操作。', failed: '操作失败'},
    en: {title: 'Current mounts', refresh: 'Refresh', search: 'Search target or source path', note: 'Changes affect runtime rules only. Rebooting or reloading a module may restore them. Individual restore records last for this WebUI session.', target: 'Target', source: 'Source', redirect: 'Redirection', whiteout: 'Whiteout', virtual_dir: 'Virtual directory', opaque: 'Opaque directory', scope: 'UID scope', excluded: 'Excluded', all: 'Default (all UIDs)', remove: 'Remove', restore: 'Reload', removed: 'Removed', empty: 'No mount rules', noMatch: 'No matching paths', loading: 'Loading…', confirm: 'Remove this rule? Independent child rules will remain.', conflict: 'The rule at this path has changed. Refresh before continuing.', failed: 'Operation failed'}
};
const nmMountState = {active: [], removed: new Map(), busy: false, valid: false, generation: 0, panel: null};
function nmRuleText(key) {
    return nmRuleWords[document.documentElement.lang?.startsWith('zh') ? 'zh' : 'en'][key];
}
function nmRulePath(path) {
    if (typeof path !== 'string' || !path.startsWith('/') || path.includes('\0'))
        throw new Error('Invalid rule path');
    return path;
}
function nmRuleScope(rule) {
    const number = key => {
        const n = rule[key] === undefined ? 0 : rule[key];
        if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error('Invalid UID scope');
        return n;
    };
    const scope = ['uid', 'uid_end', 'deny_start', 'deny_end'].map(number);
    const [start, end, denyStart, denyEnd] = scope;
    if (end < start || ((denyStart || denyEnd) && (!denyStart || denyEnd < denyStart || denyStart < start || denyEnd > (start || end ? end : 0xffffffff))))
        throw new Error('Invalid UID scope');
    return scope;
}
function nmRuleKey(rule) { return JSON.stringify([nmRulePath(rule.virtual), ...nmRuleScope(rule)]); }
function nmRuleKind(rule) {
    return rule.whiteout ? 'whiteout' : rule.virtual_dir ? 'virtual_dir' : rule.opaque ? 'opaque' : 'redirect';
}
function nmRuleSame(a, b) {
    return nmRuleKey(a) === nmRuleKey(b) && nmRuleKind(a) === nmRuleKind(b) && (a.real || '') === (b.real || '');
}
function nmRuleScopeLabel(rule) {
    const [start, end, denyStart, denyEnd] = nmRuleScope(rule);
    return `${nmRuleText('scope')}: ${start || end ? `${start}–${end}` : nmRuleText('all')}` +
        (denyStart ? `; ${nmRuleText('excluded')}: ${denyStart}–${denyEnd}` : '');
}
function nmShellQuote(value) { return "'" + value.replace(/'/g, "'\\''") + "'"; }
function nmRuleCommand(rule, adding) {
    const scope = nmRuleScope(rule);
    const args = [NM_BIN, 'rule', adding ? 'add' : 'del'];
    if (scope[0] || scope[1]) args.push('--uid-range', `${scope[0]}-${scope[1]}`);
    if (scope[2]) args.push('--uid-excluded', `${scope[2]}-${scope[3]}`);
    if (adding) {
        const flag = {whiteout: '--whiteout', virtual_dir: '--virtual-dir', opaque: '--opaque'}[nmRuleKind(rule)];
        if (flag) args.push(flag);
    }
    args.push(nmRulePath(rule.virtual));
    if (adding && !rule.whiteout && !rule.virtual_dir) args.push(nmRulePath(rule.real));
    return args.map(nmShellQuote).join(' ');
}
async function nmRuleExec(command) {
    const result = await exec(`( ${command} ); nm_status=$?; printf '\\nnm_path_status=%s\\n' "$nm_status" >&2`);
    const match = (result.stderr || '').match(/(?:^|\n)nm_path_status=(\d+)\s*$/);
    if (result.errno !== 0 || !match || Number(match[1]) !== 0)
        throw new Error((result.stderr || '').replace(/\n?nm_path_status=\d+\s*$/, '').trim() || nmRuleText('failed'));
    return result.stdout;
}
async function nmReadRules() {
    const rules = parseRuleList(await nmRuleExec(`${nmShellQuote(NM_BIN)} rule list --json`));
    if (!Array.isArray(rules)) throw new Error('Invalid rule list');
    for (const rule of rules) {
        nmRuleKey(rule);
        if (!rule.whiteout && !rule.virtual_dir) nmRulePath(rule.real);
    }
    return rules;
}
function nmRuleNode(tag, text, className = '') {
    const node = document.createElement(tag);
    node.textContent = text;
    node.className = className;
    return node;
}
function nmMountPanel() {
    if (nmMountState.panel) return nmMountState.panel;
    const modules = document.getElementById('modules-list');
    if (!modules) return null;
    const panel = document.createElement('details');
    panel.className = 'card';
    panel.style.cssText = 'margin-bottom:16px;min-width:0';
    const summary = nmRuleNode('summary', nmRuleText('title'));
    panel.append(summary);
    const note = nmRuleNode('p', nmRuleText('note'));
    const search = document.createElement('input');
    search.type = 'search';
    search.placeholder = nmRuleText('search');
    search.setAttribute('aria-label', nmRuleText('search'));
    search.style.cssText = 'width:100%;box-sizing:border-box;margin:8px 0;padding:12px;border-radius:12px;background:transparent;color:inherit;border:1px solid currentColor';
    search.oninput = nmRenderRules;
    const refresh = nmRuleNode('button', nmRuleText('refresh'), 'custom-tonal-btn');
    refresh.onclick = () => nmRefreshRules();
    const message = nmRuleNode('p', '');
    message.setAttribute('role', 'status');
    const rows = document.createElement('div');
    panel.append(note, search, refresh, message, rows);
    modules.before(panel);
    nmMountState.panel = {summary, search, refresh, message, rows};
    return nmMountState.panel;
}
function nmRenderRules() {
    const panel = nmMountPanel();
    if (!panel) return;
    panel.refresh.disabled = nmMountState.busy;
    panel.summary.textContent = `${nmRuleText('title')} (${nmMountState.active.length})`;
    panel.rows.replaceChildren();
    if (!nmMountState.valid) return;
    const entries = nmMountState.active.map(rule => ({rule, removed: false}));
    for (const rule of nmMountState.removed.values()) entries.push({rule, removed: true});
    const term = panel.search.value.toLowerCase();
    let count = 0;
    for (const {rule, removed} of entries) {
        if (!`${rule.virtual}\n${rule.real || ''}`.toLowerCase().includes(term)) continue;
        count++;
        const row = document.createElement('div');
        row.style.cssText = 'padding:12px 0;border-bottom:1px solid currentColor;overflow-wrap:anywhere;white-space:pre-wrap';
        row.append(nmRuleNode('strong', `${nmRuleText(nmRuleKind(rule))}${removed ? ` · ${nmRuleText('removed')}` : ''}`));
        row.append(nmRuleNode('p', `${nmRuleText('target')}: ${rule.virtual}`));
        if (rule.real) row.append(nmRuleNode('p', `${nmRuleText('source')}: ${rule.real}`));
        row.append(nmRuleNode('p', nmRuleScopeLabel(rule)));
        const button = nmRuleNode('button', nmRuleText(removed ? 'restore' : 'remove'), 'custom-tonal-btn');
        button.disabled = nmMountState.busy;
        button.onclick = () => nmChangeRule(rule, removed);
        row.append(button);
        panel.rows.append(row);
    }
    if (!count) panel.rows.append(nmRuleNode('p', nmRuleText(entries.length ? 'noMatch' : 'empty')));
}
async function nmRefreshRules() {
    const panel = nmMountPanel();
    if (!panel) return;
    const generation = ++nmMountState.generation;
    panel.message.textContent = nmRuleText('loading');
    try {
        const rules = await nmReadRules();
        if (generation !== nmMountState.generation) return;
        nmMountState.active = rules;
        nmMountState.valid = true;
        for (const rule of rules) {
            const key = nmRuleKey(rule), saved = nmMountState.removed.get(key);
            if (saved && nmRuleSame(saved, rule)) nmMountState.removed.delete(key);
        }
        panel.message.textContent = '';
        nmRenderRules();
    } catch (error) {
        if (generation !== nmMountState.generation) return;
        nmMountState.valid = false;
        panel.message.textContent = `${nmRuleText('failed')}: ${error.message}`;
        panel.rows.replaceChildren();
    }
}
async function nmChangeRule(rule, adding) {
    if (nmMountState.busy) return;
    if (!adding && !window.confirm(`${nmRuleText('confirm')}\n${rule.virtual}\n${nmRuleScopeLabel(rule)}`)) return;
    nmMountState.busy = true;
    ++nmMountState.generation;
    nmRenderRules();
    try {
        const rules = await nmReadRules();
        const current = rules.find(item => nmRuleKey(item) === nmRuleKey(rule));
        if ((!adding && (!current || !nmRuleSame(current, rule))) || (adding && current))
            throw new Error(nmRuleText('conflict'));
        await nmRuleExec(nmRuleCommand(rule, adding));
        if (adding) nmMountState.removed.delete(nmRuleKey(rule));
        else nmMountState.removed.set(nmRuleKey(rule), {...rule});
        await nmRefreshRules();
        await loadModules();
        await loadHome();
    } catch (error) {
        showToast(`${nmRuleText('failed')}: ${error.message}`);
        await nmRefreshRules();
    } finally {
        nmMountState.busy = false;
        const panel = nmMountPanel();
        if (panel) {
            panel.refresh.disabled = false;
            if (!panel.message.textContent) nmRenderRules();
        }
    }
}

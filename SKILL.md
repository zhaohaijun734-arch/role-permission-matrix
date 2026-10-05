---
name: role-permission-matrix
description: 给自建业务系统（ERP/工单/审批台）加一套「角色 → 权限点」的权限体系与多人审批流，含前后端一致的前端显隐、并发双批防护、角色变更即时生效、账号管理页、首次登录强制改密。当用户说「给所有人开账号和权限」「谁能看什么」「按岗位授权」「多人审批谁先批谁生效」「越权」「403 无权限」，或要给已有系统补权限门时使用。
agent_created: true
---

# 角色 / 权限矩阵 · 给自建业务系统加权限

适用：已经跑起来、但没有权限控制（或只有零散 `if (role === 'admin')`）的内部系统。
一句话目标：**权限点矩阵 + 按角色定的审批 + 前端只负责藏、后端负责拦**。

## 先摸清现状（别急着写）

```bash
# 有没有定义了但从没调用的权限中间件？
grep -rn "requireRole\|requirePerm\|hasPerm" routes/ | head
# 路由到底挂了哪些中间件
grep -rn "router.use\|router.get\|router.post" routes/*.js | grep -v node_modules
```

**高频发现**：项目里已经有个 `requireRole()` 定义了但**全项目从未调用** ——
意味着除了个别硬编码判断外零权限控制。这比重新设计更值得先说清楚。

顺带核对一条：**记忆/文档里写的审批人和代码里的可能不一致**，以代码为准并让用户定夺。

## 三层模型（务必分开，别揉在一起）

| 层 | 存哪 | 判什么 |
|---|---|---|
| 录入权 | 权限点矩阵 | 这个人**能不能录**这类单据 |
| 审批权 | 独立的审批规则表 | 这个人**能不能批**这类单据 |
| 数据可见性 | 登录即可 | 能不能**看到**列表 |

> **能录 ≠ 能批**。销售助理能录采购订单和销售订单，但不该批任何一张。
> 把审批权塞进权限点矩阵是常见错误，后面会越来越绕。

## 后端实现

### 1. 矩阵放一个文件，路由里只放权限点

```js
// db.js
const ROLES = {
  admin:             { label: '管理员',   desc: '全部权限' },
  sales:             { label: '销售执行', desc: '报价单/销售订单/出库单 录入' },
  sales_approver:    { label: '销售审批', desc: '报价单/销售订单 审批' },
  purchase:          { label: '采购执行', desc: '采购订单/检验单/入库单 录入' },
  purchase_approver: { label: '采购审批', desc: '采购订单/入库单 审批' },
  inspector:         { label: '进货检验', desc: '检验单/入库单 录入' },
  viewer:            { label: '只读',     desc: '仅查看' },
};

const PERMS = {
  view: '查看', export: '导出 PDF', quote: '报价单录入', so: '销售订单录入',
  outbound: '出库单录入', po: '采购订单录入', insp: '检验单录入',
  inbound: '入库单录入', master: '基础资料维护', user: '账号管理',
};

const PERM_MATRIX = {
  admin:             Object.keys(PERMS),          // 或用 hasPerm 里的全通短路
  sales:             ['view','export','quote','so','outbound','master'],
  sales_approver:    ['view','export'],
  purchase:          ['view','export','po','insp','inbound','master'],
  purchase_approver: ['view','export'],
  inspector:         ['view','export','insp','inbound'],
  viewer:            ['view'],
};

function hasPerm(role, perm) {
  if (role === 'admin') return true;               // admin 短路，不用列全
  return (PERM_MATRIX[role] || []).includes(perm);
}
```

**权限点必须是业务动作，不是技术动作**。写 `'quote'` 而不是 `'POST /api/sales/quotes'`，
否则路由一改就全废。

### 2. 中间件

```js
// routes/mw.js
const { db, hasPerm, PERMS } = require('../db');

function requirePerm(...perms) {          // 多选一，满足任一即可
  return (req, res, next) => {
    const u = req.session && req.session.user;
    if (!u) return res.status(401).json({ error: '未登录' });
    if (perms.some(p => hasPerm(u.role, p))) return next();
    const names = perms.map(p => PERMS[p] || p).join(' / ');
    return res.status(403).json({ error: `你的岗位没有「${names}」权限` });
  };
}
const requireAdmin = (req, res, next) => { /* role === 'admin' */ };
```

挂法：查询接口只挂 `auth`，写入接口挂 `requirePerm`。

```js
router.post('/quotes',        requirePerm('quote'),    handler);
router.post('/quotes/:id/to-order', requirePerm('so'), handler);
router.post('/outbound',      requirePerm('outbound'), handler);
```

### 3. 审批按角色，支持多人

```js
const APPROVAL_RULES = {
  quote:          { roles: ['sales_approver', 'admin'], cc: [],        label: '报价单' },
  sales_order:    { roles: ['sales_approver', 'admin'], cc: [],        label: '销售订单' },
  purchase_order: { roles: ['purchase_approver'],       cc: ['admin'], label: '采购订单' },
  outbound:       { roles: [],                          cc: [],        label: '出库单' },  // 登记即放行
  inbound:        { roles: ['purchase_approver'],       cc: ['admin'], label: '入库单' },
};

function canApprove(role, type) {
  if (role === 'admin') return true;
  const r = APPROVAL_RULES[type];
  return !!(r && (r.roles || []).includes(role));
}
function needsApproval(type) {
  const r = APPROVAL_RULES[type];
  return !!(r && (r.roles || []).length);
}
/** 角色数组展开成具体人（含通知所需的联系方式） */
function approversOf(type) {
  const r = APPROVAL_RULES[type];
  if (!r || !(r.roles || []).length) return [];
  const ph = r.roles.map(() => '?').join(',');
  return db.prepare(
    `SELECT username, name, role FROM users WHERE role IN (${ph}) AND active = 1 ORDER BY id`
  ).all(...r.roles);
}
/** 抄送：展开后剔除已在审批人名单里的，避免同一人收两条 */
function ccsOf(type) {
  const r = APPROVAL_RULES[type];
  if (!r || !(r.cc || []).length) return [];
  const ph = r.cc.map(() => '?').join(',');
  const set = new Set(approversOf(type).map(u => u.username));
  return db.prepare(
    `SELECT username, name, role FROM users WHERE role IN (${ph}) AND active = 1 ORDER BY id`
  ).all(...r.cc).filter(u => !set.has(u.username));
}
```

**「谁先批谁生效」必须靠条件更新实现**，读-判-写挡不住并发：

```js
const r = db.prepare(
  `UPDATE ${table} SET status=?, approver=?, approve_time=? WHERE id=? AND status='待审批'`
).run(pass ? '已批准' : '已驳回', me.name, now(), id);

if (r.changes === 0) {
  const cur = db.prepare(`SELECT status, approver FROM ${table} WHERE id=?`).get(id);
  return res.status(409).json({
    error: `该单据刚被 ${cur?.approver || '他人'} 处理为「${cur?.status || '未知'}」`,
  });
}
```

### 4. 角色变更即时生效（容易漏）

session 里存着 `role`，管理员改了角色后对方**还拿着旧角色继续用**。
在 `auth` 里每次回库核对：

```js
function auth(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ error: '未登录' });
  const u = db.prepare('SELECT id,username,name,role,active FROM users WHERE id=?')
    .get(req.session.user.id);
  if (!u || !u.active) {
    req.session.destroy(() => {});
    return res.status(401).json({ error: '账号已停用，请联系管理员' });
  }
  req.session.user = { id: u.id, username: u.username, name: u.name, role: u.role };
  next();
}
```

`/api/auth/me` 也要走同一套（它通常不走 `auth` 中间件），
并把前端要用的东西一次给全：

```js
function profileOf(user) {
  return {
    ...user,
    role_label: (ROLES[user.role] || {}).label || user.role,
    perms: Object.keys(PERMS).filter(p => hasPerm(user.role, p)),
    is_admin: user.role === 'admin',
  };
}
```

## 前端：只负责藏，不负责拦

```js
let ME = null;
const can = p => !!(ME && (ME.perms || []).includes(p));
const isAdmin = () => !!(ME && ME.is_admin);

// 导航项两种标注
// <a class="nav-item" data-p="users" data-admin="1">账号与权限</a>
// <a class="nav-item" data-p="quotes" data-perm="quote">报价单</a>
function applyPerm() {
  document.querySelectorAll('.nav-item').forEach(a => {
    if (a.dataset.perm && !can(a.dataset.perm)) { a.hidden = true; return; }
    if (a.dataset.admin === '1' && !isAdmin()) { a.hidden = true; return; }
    a.hidden = false;
  });
  // 整组都被藏起来的，组标题也藏掉
  document.querySelectorAll('.nav-group').forEach(g => {
    let n = g.nextElementSibling, any = false;
    while (n && !n.classList.contains('nav-group')) {
      if (n.classList.contains('nav-item') && !n.hidden) any = true;
      n = n.nextElementSibling;
    }
    g.hidden = !any;
  });
}
```

列表页的按钮同步包一层：

```js
`${can('export') ? `<button onclick="exportPdf(...)">导出 PDF</button>` : ''}`
```

**碰过的坑**：前端按管理员隐藏了某页，后端接口却只挂了 `auth` ——
「藏起来但还能调」就是漏洞。**每个 `data-admin` 的页面，对应路由必须挂 `requireAdmin`。**

## 首次登录强制改密

初始密码统一时，`users` 加一列 `pwd_changed INTEGER NOT NULL DEFAULT 0`：

- 登录返回 `must_change: !u.pwd_changed`，前端弹窗挡住
- 改密成功后写 `pwd_changed = 1`
- **后端不阻断请求**（只在返回里带标记），否则用户改密失败就彻底进不来了
- 新密码校验：至少 6 位 + 不许还是初始密码

## 账号管理页（给管理员一个可视化入口）

后端 `routes/users.js`（`router.use(auth); router.use(requireAdmin)`）：

| 端点 | 作用 |
|---|---|
| `GET /api/users` | 列表 + 角色中文名 + 权限点 + 该人能批哪些单据 |
| `GET /api/users/roles` | 角色清单 + 每个角色的权限点 + 当前审批规则（给前端下拉用） |
| `POST /api/users` | 新建（账号名归一化 + 校验） |
| `PATCH /api/users/:id` | 改姓名 / 角色 / 启停 |
| `POST /api/users/:id/reset` | 重置为初始密码 |
| `POST /api/users/:id/bind` | 绑外部账号（企微 userid 等） |

**必须有的护栏**：不许把最后一个启用的管理员降级或停用，否则没人能管系统了。

```js
const adminCount = db.prepare(
  "SELECT COUNT(*) c FROM users WHERE role='admin' AND active=1").get().c;
if (lostAdmin && adminCount <= 1) {
  return res.status(400).json({ error: '系统里至少要留一个启用状态的管理员' });
}
```

前端页面同时把「岗位 → 权限」矩阵和「当前审批规则」渲染出来，
让老板一眼看到谁批什么 —— 比文档靠谱。

## 测试（不写这些就别上线）

**关键：测试脚本一律不得重置真人的密码。** 员工一旦自己改过初始密码，
用 `123456` 的测试就会失败；此时应**标记「已自行改密」并跳过**，并支持环境变量覆盖：

```python
def pwd_of(u):
    return os.environ.get("ERP_PWD_" + u.upper(), "123456")

def need(*users):          # 依赖的账号不可用就整体跳过，不误报失败
    miss = [u for u in users if u not in S]
    if miss:
        skip("本节", "账号不可用（多半是自己改过密码）：" + "、".join(miss))
        return False
    return True
```

断言要覆盖（矩阵的每一格都该有一条）：

| 类型 | 例 |
|---|---|
| 正向 | 销售执行能建报价单（200） |
| 反向 | 采购执行建报价单被拒（403，且错误信息里有中文岗位名） |
| 审批正向 | 销售审批能批报价单 |
| 审批反向 | 采购审批批报价单被拒 |
| 并发 | 甲批成功后，乙再批拿 **409** 且提示甲的姓名 |
| 护栏 | 最后一个管理员降级 → 400 |
| 越权接口 | 非管理员访问账号管理 / 系统设置接口 → 403 |
| 即时生效 | 改角色/停用后，对方不重登就生效 / 掉线 |

### 前端也要测，而且不用浏览器

`node --check` **查不出模板字符串里的变量名错误**（`${x.labell}` 照样过语法检查，一到页面就白屏）。
写个几十行的 DOM 桩就能把前端真跑起来：

```js
const mainEl = el('main');       // 常驻，页面内容都写到这里
const ctx = {
  document: {
    querySelector: () => el(), getElementById: id => (id === 'main' ? mainEl : el()),
    querySelectorAll: () => [], createElement: t => el(t),
    body: el('body'), addEventListener() {},
  },
  location: { hash: '', reload() {} }, window: { open() {} },
  alert: m => alerts.push(m), confirm: () => false, prompt: () => null,
  console, setTimeout, clearTimeout, setInterval, clearInterval,
  fetch: null, URLSearchParams, JSON, Math, Date, Number, String, Object, Array,
};
ctx.fetch = async (url, opt = {}) => {          // 补上登录 Cookie
  opt.headers = { ...opt.headers, Cookie: cookie };
  return fetch(/^https?:/.test(url) ? url : BASE + url, opt);
};
const sandbox = vm.createContext(ctx);
vm.runInContext(fs.readFileSync('public/app.js', 'utf8'), sandbox, { filename: 'app.js' });
sandbox.ME = me.user;                            // 顶掉未登录时的 null

for (const p of PAGES) {                         // 逐个页面函数跑一遍，抓 throw
  mainEl.innerHTML = '';
  await sandbox[p].call(sandbox);
  if (mainEl.innerHTML.includes('加载中…')) throw new Error(p + ' 没渲染出来');
}
```

按钮显隐的判定要分清「硬断言」和「数据依赖」：

- **无权限 → 界面绝不能出现该按钮**：这条必须硬断言（真安全属性）
- **有权限 → 按钮是否出现**：取决于当前有没有数据（空列表没有行内按钮），
  只提示、不算失败，否则库里没数据时全是假红

## 上线清单

1. 备份服务器代码 + 数据库（`cp -a` 到 `backups/pre-xxx-<时间戳>/`）
2. rsync **逐个目标目录**传（根目录模块和 `routes/` 同名文件极易串）
3. 新增列用 `ensureColumn()`（`ALTER TABLE ADD COLUMN`），**不用重传 db**
4. 重启后确认：老账号还在、新账号建出来了、绑定有没有更新成功
5. 跑全套测试（正向 + 反向 + 前端渲染）
6. 清理测试数据（业务单据归零、日志清空、临时账号删除）
7. **前端静态资源加版本号**（`app.js?v=YYYYMMDDx`），每次改完 +1

## 常见错误

| 症状 | 原因 |
|---|---|
| 权限改了不生效 | session 里存着旧 role，`auth` 没回库核对 |
| 两个人同时批都成功 | 用了「读-判-写」而不是条件 `UPDATE … WHERE status='待审批'` |
| 改了角色对方还能乱操作 | 前端藏了按钮但后端路由没挂 `requirePerm` |
| 找回密码进不去 | 强制改密做成了「后端阻断」而不是「前端提示」 |
| 把最后一个管理员降级了 | 没做「至少留一个启用的管理员」护栏 |
| 测试全红但其实没问题 | 有人自己改过密码 / 库里没数据；测试要用 `need()` 优雅跳过 |

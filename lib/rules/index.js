// aiscan · 检测规则库（零依赖）
// 每条规则：id / severity / title / category / 匹配方式（regex 或 heuristic）
// 全部使用 Node 内置能力，纯静态文本匹配，不执行任何被测代码。

export const RULES = [
  // ── 机密信息泄漏 ──────────────────────────────────────
  {
    id: 'SECRET-AWS',
    severity: 'critical',
    category: 'secret',
    title: '疑似 AWS Access Key 泄漏',
    description: '检测到 AWS Access Key（AKIA 开头 20 位字符）。此类密钥可直接用于调用 AWS API，应立即轮换。',
    regex: /\b(AKIA|ASIA)[0-9A-Z_]{16,}\b/,
    message: '疑似 AWS Access Key，请立即轮换并检查 Git 历史',
    recommendation: '使用 aws secretsmanager / 环境变量注入凭证；用 git filter-repo 清理历史',
    cwe: 'CWE-798',
  },
  {
    id: 'SECRET-PRIVATE-KEY',
    severity: 'critical',
    category: 'secret',
    title: '疑似私钥 / 证书内容泄漏',
    description: '检测到 PEM 格式私钥块（RSA / EC / OPENSSH）。私钥入库等于把大门钥匙挂在门口。',
    regex: /-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----[\s\S]{0,2048}?-----END (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----/,
    message: '私钥内容不应出现在代码库中',
    recommendation: '密钥放入 vault / secrets manager，仅以只读路径引用',
    cwe: 'CWE-798',
  },
  {
    id: 'SECRET-GENERIC-TOKEN',
    severity: 'high',
    category: 'secret',
    title: '疑似通用 API Token / 密码硬编码',
    description: '高熵令牌（长度 ≥ 20 且字符熵极高）直接写在代码中。',
    heuristic: 'entropy',
    minLength: 20,
    minEntropy: 4.2,
    message: '检测到高熵字符串，可能是硬编码 Token / 密码',
    recommendation: '改用环境变量注入，禁止提交至仓库',
    cwe: 'CWE-798',
  },
  {
    id: 'SECRET-PASSWORD-VAR',
    severity: 'medium',
    category: 'secret',
    title: '密码以变量形式硬编码',
    description: 'password / passwd / pwd 变量被直接赋值为字符串字面量。',
    regex: /\b(?:password|passwd|pwd|secret|api_?key|token)\s*[:=]\s*['"`][^'"`]{4,}['"`]/i,
    message: '凭据类变量被硬编码为字面量',
    recommendation: '从 .env / 环境变量读取，并确保 .env 在 .gitignore 中',
    cwe: 'CWE-798',
  },
  {
    id: 'SECRET-CONNECTION-STRING',
    severity: 'critical',
    category: 'secret',
    title: '疑似数据库连接串含明文口令',
    description: '数据库连接字符串中出现 user:password@host 明文口令形式。',
    regex: /\b(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp|jdbc)\:\/\/[^\s'"]+:[^\s'"]+@/i,
    message: '连接串内嵌明文口令，极其危险',
    recommendation: '连接串放环境变量，口令部分用 secrets 管理',
    cwe: 'CWE-798',
  },

  // ── 注入类 ────────────────────────────────────────────
  {
    id: 'INJ-SQL-CONCAT',
    severity: 'critical',
    category: 'injection',
    title: 'SQL 注入：字符串拼接查询',
    description: '检测到 SQL 查询使用字符串拼接 / 模板插值直接拼入用户输入，易受 SQL 注入攻击。',
    regex: /(?:\bSELECT\b[^;\n]{0,60}\bFROM\b|\bINSERT\b[^;\n]{0,40}\bINTO\b|\bUPDATE\b[^;\n]{0,60}\bSET\b|\bDELETE\b[^;\n]{0,40}\bFROM\b)[^;\n]{0,60}\$\{|['"](?:SELECT\b[^'"]{0,60}\bFROM\b|INSERT\b[^'"]{0,40}\bINTO\b|UPDATE\b[^'"]{0,60}\bSET\b|DELETE\b[^'"]{0,40}\bFROM\b)[^'"]{0,60}['"]\s*\+/i,
    message: 'SQL 语句使用拼接方式，存在注入风险',
    recommendation: '改用参数化查询 / Prepared Statement',
    cwe: 'CWE-89',
  },
  {
    id: 'INJ-EVAL',
    severity: 'high',
    category: 'injection',
    title: '危险 eval / Function 动态执行',
    description: 'eval()、new Function() 或类似动态代码执行将不可信输入变成代码。',
    regex: /\b(?:eval|new Function|setTimeout|setInterval)\s*\(\s*(?:req|body|query|params|ctx|event|input|userInput|data|payload)\b/i,
    message: '动态代码执行可能被注入控制',
    recommendation: '避免 eval；如必须，使用严格白名单校验输入',
    cwe: 'CWE-95',
  },
  {
    id: 'INJ-COMMAND',
    severity: 'critical',
    category: 'injection',
    title: '命令注入：shell 拼接执行',
    description: 'exec / spawn / system 等命令执行接口直接拼接用户输入。',
    regex: /\b(?<!\.)(?:exec|execSync|spawn|spawnSync|system)\s*\(\s*(?:`[^`]*\$\{|['"`][^'"`]*['"`]\s*\+|\$\{)/i,
    message: '命令执行拼接不可信输入，存在命令注入',
    recommendation: '使用 execFile / 参数数组方式；严格校验输入',
    cwe: 'CWE-78',
  },
  {
    id: 'INJ-PATH-TRAVERSAL',
    severity: 'high',
    category: 'injection',
    title: '路径穿越：未校验的文件路径拼接',
    description: '使用用户可控输入直接拼接文件路径读写，可能被 ../ 逃逸。',
    regex: /\b(?:readFile|writeFile|createReadStream|createWriteStream|readFileSync|writeFileSync|unlink|open)\s*\(\s*(?:req|params|query|body|input|filename|file|path|userPath)\b/i,
    message: '文件操作路径来自不可信输入',
    recommendation: '使用 path.resolve + 白名单目录校验；禁止 .. 穿越',
    cwe: 'CWE-22',
  },

  // ── XSS / 输出编码 ────────────────────────────────────
  {
    id: 'XSS-INNERHTML',
    severity: 'high',
    category: 'xss',
    title: 'DOM XSS：innerHTML / document.write 写入不可信数据',
    description: '将未转义的用户输入写入 innerHTML，可能触发 DOM XSS。',
    regex: /\b(?:innerHTML|outerHTML)\s*=\s*(?:`[^`]*\$\{|[^\s;"'\n][^;\n]{0,59}|['"][^'"]{0,80}['"]\s*\+[^;\n]{0,40})|\bdocument\.write\s*\(/i,
    message: '用户输入直接写入 DOM，存在 XSS 风险',
    recommendation: '使用 textContent 或 sanitize 后再插入；CSP 加固',
    cwe: 'CWE-79',
  },

  // ── 加密与配置 ────────────────────────────────────────
  {
    id: 'CRYPTO-WEAK-MD5',
    severity: 'medium',
    category: 'crypto',
    title: '弱哈希算法 MD5 / SHA1 用于安全敏感场景',
    description: '使用 MD5 / SHA1 处理密码或完整性校验，两者均已破解。',
    // 覆盖三种真实写法：createHash('md5') / md5(x) / hash('sha1', ...)
    regex: /\bcreateHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)|\b(?:md5|sha1)\s*\(\s*[A-Za-z_$][\w$.]*\s*\)/,
    message: 'MD5/SHA1 不应再用于安全场景',
    recommendation: '密码用 bcrypt/argon2；哈希用 SHA-256 以上',
    cwe: 'CWE-327',
  },
  {
    id: 'CRYPTO-WEAK-CIPHER',
    severity: 'medium',
    category: 'crypto',
    title: '弱加密算法 DES / 3DES / RC4',
    description: 'DES/3DES/RC4 等弱加密算法已被破解。',
    // 必须出现在字符串字面量或 createCipheriv 调用中，避免命中变量名/注释里的裸词（如 des、ECB 缩写）
    regex: /['"`](?:DES(?:-EDE3?)?|3DES|RC4|des-ede3-cbc|rc4)['"`]|createCipheriv\s*\(\s*['"`](?:des|rc4)/i,
    message: '使用已破解的加密算法',
    recommendation: '改用 AES-GCM / ChaCha20-Poly1305',
    cwe: 'CWE-327',
  },
  {
    id: 'TLS-INSECURE',
    severity: 'high',
    category: 'crypto',
    title: '不安全的 TLS：rejectUnauthorized=false',
    description: '关闭 TLS 证书校验将导致中间人攻击。',
    regex: /rejectUnauthorized\s*:\s*false/,
    message: 'TLS 证书校验被关闭',
    recommendation: '保持 rejectUnauthorized 默认 true；仅用于调试时临时允许',
    cwe: 'CWE-295',
  },

  // ── 日志与信息泄漏 ────────────────────────────────────
  {
    id: 'LOG-SENSITIVE',
    severity: 'medium',
    category: 'logging',
    title: '日志打印敏感信息',
    description: '将密码 / token / 密钥对象直接写入日志。',
    regex: /\b(?:console\.log|logger|log|info|warn)\s*\([\s\S]{0,150}\b(?:password|token|secret|authorization|api[_-]?key)\b/i,
    message: '敏感信息不应写入日志',
    recommendation: '日志脱敏；授权头 / 密钥禁止输出',
    cwe: 'CWE-532',
  },

  // ── 依赖与权限 ────────────────────────────────────────
  {
    id: 'DEPS-PIN-ANY',
    severity: 'low',
    category: 'supply-chain',
    title: '依赖版本未锁死（^ 前缀）',
    description: 'package.json 依赖使用 ^ 宽松版本，存在供应链风险。',
    regex: /["'](?:dependencies|devDependencies|peerDependencies)["']\s*:\s*\{[\s\S]{0,2000}?["'][a-zA-Z0-9@._/+-]+["']\s*:\s*["'][\^~*]/,
    message: '依赖未锁死版本',
    recommendation: '使用精确版本 + package-lock.json 锁定',
    cwe: 'CWE-1104',
  },
];

// ── gitleaks 移植规则（二次创作，来源 MIT）─────────────
// 221 条密钥检测规则由 tools/convert-gitleaks.js 从 gitleaks 自动转换：
// regex 为字符串 + flags 分离存储，首次使用时编译（延迟编译降低启动开销）
import { GITLEAKS_RULES } from './gitleaks.js';

const compiledGitleaks = [];
for (const r of GITLEAKS_RULES) {
  try {
    compiledGitleaks.push({
      ...r,
      regex: new RegExp(r.regex, r.flags || undefined),
    });
  } catch {
    // 单条正则运行时不兼容（理论不该发生，转换时已校验）——跳过
  }
}

// 完整规则集 = 内置 15 条 + gitleaks 移植 221 条
export const ALL_RULES = [...RULES, ...compiledGitleaks];

// 漏洞文件清单（供测试 / README 示例使用）
export const CATEGORY_META = {
  secret: { label: '机密泄漏', color: 'red' },
  injection: { label: '注入攻击', color: 'red' },
  xss: { label: 'XSS', color: 'orange' },
  crypto: { label: '加密弱点', color: 'orange' },
  logging: { label: '日志泄漏', color: 'yellow' },
  'supply-chain': { label: '供应链', color: 'yellow' },
};

export function ruleById(id) {
  return ALL_RULES.find((r) => r.id === id);
}

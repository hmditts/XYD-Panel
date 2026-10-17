// scripts/build-worker.js
//
// این اسکریپت:
// 1) normal.js را می‌خواند
// 2) CURRENT_VERSION و UPDATE_FIX را با regex از آن استخراج می‌کند (پیش‌فرض اگر پیدا نشد)
// 3) هر دو رشته را جدا جدا XOR می‌کند (کلید نسخه: 198، کلید fix: 124) و به آرایه‌ی عدد تبدیل می‌کند
// 4) خط import را از ابتدای normal.js حذف می‌کند
// 5) شناسه‌های سطح‌بالای normal.js را خودکار پیدا می‌کند (autoDetectIdentifiers) و
//    در کل سورس به نام تصادفی __mNNNNNN تغییر می‌دهد
// 6) export default { ... } را به const __WORKER_EXPORT__ = { ... } تبدیل می‌کند و در پایان
//    return __WORKER_EXPORT__; اضافه می‌کند
// 7) نتیجه را UTF-8 → Base64 می‌کند (معادل Node برای TextEncoder+btoa سمت مرورگر)
// 8) ۲۰۰ متغیر و ۶۰ تابع بی‌مصرف با نام hex تصادفی برای حجیم کردن فایل تولید می‌کند
// 9) همه را داخل worker.template.js جایگذاری می‌کند و worker.js را می‌نویسد
//
// توجه مهم: این یک رمزنگاری واقعی نیست. کلیدهای XOR و منطق دیکد همگی
// داخل همان فایل خروجی worker.js باقی می‌مانند و هرکسی با چند خط کد
// می‌تواند سورس اصلی را برگرداند. تنها چیزی که این روش کم می‌کند، خوانایی
// سرسریِ فایل دیپلوی‌شده برای خودِ شماست (ضدِ grep ساده و ضدِ diff سریع)،
// نه امنیت در برابر یک مهاجم/بازبینِ مصمم.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const NORMAL_JS_PATH = path.join(ROOT, 'normal.js');
const TEMPLATE_PATH = path.join(ROOT, 'worker.template.js');
const OUTPUT_PATH = path.join(ROOT, 'worker.js');

const XOR_KEY_VERSION = 198;
const XOR_KEY_FIX = 124;

const VERSION_REGEX = /(?:const|let|var)\s+CURRENT_VERSION\s*=\s*(['"])([0-9.]+)\1/;
const FIX_REGEX = /(?:const|let|var)\s+UPDATE_FIX\s*=\s*(['"])([^'"]*)\1/;

const JUNK_PLACEHOLDER = '/*__JUNK_BLOCK__*/';
const VERSION_ARRAY_PLACEHOLDER = '/*__VERSION_ARRAY__*/';
const FIX_ARRAY_PLACEHOLDER = '/*__FIX_ARRAY__*/';
const PAYLOAD_PLACEHOLDER = '/*__PAYLOAD_B64__*/';

// به‌جای یک لیست دستیِ ثابت (که باید با دست با normal.js هماهنگ نگه داشته می‌شد و
// با هر تغییر در normal.js از رده خارج می‌شد)، این نسخه شناسه‌های top-level را
// مستقیماً از خودِ normal.js استخراج می‌کند (پایین‌تر، autoDetectIdentifiers).
// دو آرایه‌ی زیر فقط برای موارد استثنا هستند:
const EXTRA_IDENTIFIERS = []; // شناسه‌هایی که auto-detect نمی‌گیرد ولی می‌خواهید rename شوند
const EXCLUDE_IDENTIFIERS = ['CURRENT_VERSION', 'UPDATE_FIX']; // هرگز rename نشوند

// شناسه‌های سطح بالا (ستون صفر، یعنی بیرون از هر تابع/بلوک) را از سورس پیدا می‌کند:
// «const/let/var NAME =» و «function NAME(». چون غیر از این الگوها (مثلاً
// destructuring در سطح بالا) پوشش داده نمی‌شوند، لیست همیشه یک زیرمجموعه‌ی
// امن از شناسه‌هاست، نه لزوماً کامل.
function autoDetectIdentifiers(source) {
  const names = new Set();
  const declRe = /^(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=/gm;
  const funcRe = /^(?:export\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/gm;
  let m;
  while ((m = declRe.exec(source))) names.add(m[1]);
  while ((m = funcRe.exec(source))) names.add(m[1]);
  return [...names];
}

function xorStringToArray(str, key) {
  return Array.from(str).map((c) => c.charCodeAt(0) ^ key);
}

function renameIdentifiers(code, list) {
  // طولانی‌ترین نام‌ها اول جایگزین می‌شوند تا نام‌هایی که زیررشته‌ی نام‌های دیگرند
  // (مثلاً DNS_CACHE داخل DNS_CACHE_TTL) دوباره مبهم‌سازی نشوند.
  const sorted = [...list].sort((a, b) => b.length - a.length);
  const used = new Set();
  for (const id of sorted) {
    let n;
    do {
      n = 100000 + Math.floor(Math.random() * 900000);
    } while (used.has(n));
    used.add(n);
    code = code.replace(new RegExp(`\\b${id}\\b`, 'g'), `__m${n}`);
  }
  return code;
}

function randHex() {
  return crypto.randomBytes(5).toString('hex');
}

function buildJunkBlock() {
  let out = '';
  for (let i = 0; i < 200; i++) {
    out += `let __var_${randHex()}_${i}=${Math.floor(Math.random() * 100000)};\r\n`;
  }
  for (let i = 0; i < 60; i++) {
    out += `function __func_${randHex()}_${i}(){return ${Math.floor(Math.random() * 1000)};}\r\n`;
  }
  return out.replace(/\r\n$/, '');
}

// جایگزینیِ متنیِ ساده (بدون تفسیر الگوهای ویژه‌ی $ که String.prototype.replace
// در رشته‌ی جایگزین تشخیص می‌دهد؛ چون base64/آرایه‌ها می‌توانند طولانی باشند).
function inject(template, placeholder, value) {
  const idx = template.indexOf(placeholder);
  if (idx === -1) throw new Error(`نشانگر ${placeholder} داخل worker.template.js پیدا نشد.`);
  return template.slice(0, idx) + value + template.slice(idx + placeholder.length);
}

function main() {
  if (!fs.existsSync(NORMAL_JS_PATH)) {
    throw new Error(`normal.js پیدا نشد: ${NORMAL_JS_PATH}`);
  }
  if (!fs.existsSync(TEMPLATE_PATH)) {
    throw new Error(`worker.template.js پیدا نشد: ${TEMPLATE_PATH}`);
  }

  const source = fs.readFileSync(NORMAL_JS_PATH, 'utf8');

  const verMatch = source.match(VERSION_REGEX);
  const fixMatch = source.match(FIX_REGEX);
  if (!verMatch) {
    throw new Error('الگوی "const CURRENT_VERSION = \'x.x.x\'" داخل normal.js پیدا نشد.');
  }
  const versionStr = verMatch[2];
  const fixStr = fixMatch ? fixMatch[2] : '';

  const versionArr = xorStringToArray(versionStr, XOR_KEY_VERSION);
  const fixArr = xorStringToArray(fixStr, XOR_KEY_FIX);

  let code = source.replace(
    /^\s*import\s*\{\s*connect\s*\}\s*from\s*["']cloudflare:sockets["']\s*;?/m,
    ''
  );
  const detected = autoDetectIdentifiers(source);
  const toRename = [...new Set([...detected, ...EXTRA_IDENTIFIERS])].filter(
    (id) => !EXCLUDE_IDENTIFIERS.includes(id)
  );
  code = renameIdentifiers(code, toRename);
  code = code.replace(/export\s+default\s*\{/, 'const __WORKER_EXPORT__ = {');
  code += '\nreturn __WORKER_EXPORT__;';

  const base64Payload = Buffer.from(code, 'utf8').toString('base64');
  const junkBlock = buildJunkBlock();

  let template = fs.readFileSync(TEMPLATE_PATH, 'utf8');
  template = inject(template, JUNK_PLACEHOLDER, junkBlock);
  template = inject(template, VERSION_ARRAY_PLACEHOLDER, versionArr.join(','));
  template = inject(template, FIX_ARRAY_PLACEHOLDER, fixArr.join(','));
  template = inject(template, PAYLOAD_PLACEHOLDER, base64Payload);

  fs.writeFileSync(OUTPUT_PATH, template, 'utf8');
  console.log(
    `worker.js generated. CURRENT_VERSION=${versionStr} UPDATE_FIX="${fixStr}" ` +
      `identifiers_renamed=${toRename.length} payload_bytes=${Buffer.byteLength(code, 'utf8')}`
  );
  console.log('renamed identifiers:', toRename.sort().join(', '));
}

main();

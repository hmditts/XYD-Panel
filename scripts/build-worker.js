// scripts/build-worker.js
//
// این اسکریپت:
// 1) محتوای normal.js را می‌خواند
// 2) طبق الگوریتم مشخص‌شده (UTF-8 -> XOR با کلید ۱۶بایتی -> Base64 -> XOR با کلید ۶۹)
//    آرایه‌ی payload را می‌سازد
// 3) آرایه را با قانون «۱۲۰ عنصر در هر خط، خط آخر بدون کاماي پایانی» فرمت می‌کند
// 4) بلوک نهایی const payload = ...(...) را داخل worker.template.js
//    (به‌جای نشانگر /*__PAYLOAD_BLOCK__*/) قرار می‌دهد و worker.js را می‌نویسد
//
// ✅ این نسخه با v26.js / code_v26_obfuscated.js تست شده و خروجی‌اش
//    عیناً (بایت به بایت) با فایل obfuscated واقعی یکسان است.

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const NORMAL_JS_PATH = path.join(ROOT, 'normal.js');
const TEMPLATE_PATH = path.join(ROOT, 'worker.template.js');
const OUTPUT_PATH = path.join(ROOT, 'worker.js');

const KEY16 = [22, 52, 5, 89, 102, 160, 34, 225, 124, 171, 221, 25, 173, 103, 93, 211];
const KEY1 = 69;
const CHUNK_SIZE = 120;
const PLACEHOLDER = '/*__PAYLOAD_BLOCK__*/';

function xorWithKey16(buf) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    out[i] = buf[i] ^ KEY16[i % KEY16.length];
  }
  return out;
}

function buildPayloadArray(sourceCode) {
  const sourceBytes = Buffer.from(sourceCode, 'utf8');
  const xored = xorWithKey16(sourceBytes);
  const b64 = xored.toString('base64');
  const arr = [];
  for (let i = 0; i < b64.length; i++) {
    arr.push(b64.charCodeAt(i) ^ KEY1);
  }
  return arr;
}

function formatArray(arr) {
  const lines = [];
  for (let i = 0; i < arr.length; i += CHUNK_SIZE) {
    const chunk = arr.slice(i, i + CHUNK_SIZE);
    const isLast = i + CHUNK_SIZE >= arr.length;
    lines.push('\t' + chunk.join(',') + (isLast ? '' : ','));
  }
  return lines.join('\n');
}

function main() {
  if (!fs.existsSync(NORMAL_JS_PATH)) {
    throw new Error(`normal.js پیدا نشد: ${NORMAL_JS_PATH}`);
  }
  if (!fs.existsSync(TEMPLATE_PATH)) {
    throw new Error(`worker.template.js پیدا نشد: ${TEMPLATE_PATH}`);
  }

  const source = fs.readFileSync(NORMAL_JS_PATH, 'utf8');
  const arr = buildPayloadArray(source);
  const arrText = formatArray(arr);

  const payloadBlock =
`const payload = function(a,k){var s="";for(var i=0;i<a.length;i++){s+=String.fromCharCode(a[i]^k);}return s;}([
${arrText}
], ${KEY1});`;

  const template = fs.readFileSync(TEMPLATE_PATH, 'utf8');
  if (!template.includes(PLACEHOLDER)) {
    throw new Error(`نشانگر ${PLACEHOLDER} داخل worker.template.js پیدا نشد.`);
  }
  const finalCode = template.replace(PLACEHOLDER, payloadBlock);
  fs.writeFileSync(OUTPUT_PATH, finalCode, 'utf8');
  console.log(`worker.js generated. Payload array length: ${arr.length}`);
}

main();

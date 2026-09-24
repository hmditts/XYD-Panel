const GLOBAL_TRAFFIC_CACHE = new Map();
const ACTIVE_CONNECTIONS_COUNT = new Map();
const GLOBAL_LAST_ACTIVE_WRITE = new Map();
const GLOBAL_LAST_DB_WRITE = new Map();
const GLOBAL_WRITE_LOCK = new Map();
// Serializes read-merge-write cycles on `active_ips` per username within the same isolate
// (promise-chaining mutex). See persistActiveIp() near getActiveIpCount() for why this exists
// (shared with confirmActiveIp() - see the «دیده‌شده/تأییدشده» device policy notes there).
const GLOBAL_ACTIVE_IPS_WRITE_LOCK = new Map();
// «سیاست ثبت دستگاه متصل» (device seen/confirmed policy - see DEVICE_CONFIRM_* below): best-effort,
// per-isolate running total of bytes (both directions) moved by short-lived connections of the
// same (username, clientIP) pair, within a rolling DEVICE_CONFIRM_BURST_WINDOW_MS window. Used to
// confirm a device that never keeps a single connection open for DEVICE_CONFIRM_MIN_DURATION_MS,
// but reconnects often with real usage each time (a chat/browser app is the common case). Not
// shared across isolates and not persisted to D1 - approximate by design, see handlevIees().
// Pruned opportunistically in flushExpiredTraffic().
const IP_BURST_BYTES = new Map();
const DNS_CACHE = new Map();
const USER_REQ_CACHE = new Map();
const LOGIN_ATTEMPTS = new Map();
let GLOBAL_REQ_COUNT = 0;
let GLOBAL_LAST_REQ_WRITE = 0;
const DNS_CACHE_TTL = 5 * 60 * 1000;
const DOH_RESOLVER = "https://cloudflare-dns.com/dns-query";
const UPSTREAM_BUNDLE_TARGET_BYTES = 128 * 1024;
const UPSTREAM_QUEUE_MAX_BYTES = 16 * 1024 * 1024;
const UPSTREAM_QUEUE_MAX_ITEMS = 4096;
const DNS_CACHE_MAX_ENTRIES = 2048;
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();
const TLS_PORTS = new Set(["443", "2053", "2083", "2087", "2096", "8443"]);
function safeDecodeURI(value) {
	try {
		return decodeURIComponent(value);
	} catch (e) {
		return value;
	}
}
async function readJsonBody(request) {
	try {
		const body = await request.json();
		return body && typeof body === "object" ? body : {};
	} catch (e) {
		return {};
	}
}
// «پروکسی‌های دستی» که به‌عنوان بخشی از «مخزن خودمون» (میرور ۴) در نظر گرفته می‌شن؛ موقع sync با
// پروکسی‌های کش‌شده از مخزن اصلی ترکیب می‌شن. هر کد کشور یک آرایه از خط‌های پروکسی (همون فرمتی که
// در proxy_vip/*.txt هست). فعلاً خالی است — خودتان پر کنید، یا بعداً به D1 منتقلش کنید.
const MANUAL_VIP_PROXIES = {
	// DE: ["1.2.3.4:443#My-DE-1", "5.6.7.8:2053#My-DE-2"],
	// US: ["9.9.9.9:443#My-US-1"],
};
function getManualVipProxies(country) {
	const list = MANUAL_VIP_PROXIES[String(country).toUpperCase()];
	return Array.isArray(list) ? list : [];
}
// متن فچ‌شده از مخزن اصلی را با متن مخزن شخصی (میرور ۴) و MANUAL_VIP_PROXIES همون کشور ترکیب و یکتا می‌کند.
function mergeVipProxyText(country, fetchedText, personalText) {
	const fetchedLines = (fetchedText || "").split("\n").map((l) => l.trim()).filter((l) => l.length > 5);
	const personalLines = (personalText || "").split("\n").map((l) => l.trim()).filter((l) => l.length > 5);
	const manualLines = getManualVipProxies(country).map((l) => l.trim()).filter((l) => l.length > 5);
	return [...new Set([...fetchedLines, ...personalLines, ...manualLines])].join("\n");
}
// میرور ۴ - مخزن شخصی خودمون. این خط رو با آدرس raw واقعی ریپوی خودتون پر کنید (owner/repo/branch).
// هم fetchWithFallback (به‌عنوان آخرین میرور توی زنجیره) و هم fetchPersonalRepoFile (که همیشه/بدون
// شرط صداش می‌زنیم، مخصوص proxy_vip/*.txt) از همین یک آدرس استفاده می‌کنن.
const PERSONAL_REPO_RAW_BASE = "https://raw.githubusercontent.com/hmditts/XYD-Panel/main/";
// برخلاف fetchWithFallback (که با اولین جواب OK متوقف می‌شه)، این تابع مستقیم و همیشه از مخزن
// شخصی می‌خونه - even اگه میرورهای ۱ تا ۳ هم OK برگردونده باشن - چون هدفش اینه که وقتی فایل رسمی
// وجود داره ولی پروکسی‌هاش مرده‌ن، پروکسی‌های خودمون همچنان اضافه بشن نه این‌که نادیده گرفته بشن.
async function fetchPersonalRepoFile(path) {
	try {
		const res = await fetch(`${PERSONAL_REPO_RAW_BASE}${path}`);
		if (res.ok) return await res.text();
	} catch (e) { }
	return null;
}
async function fetchWithFallback(path, options = {}) {
	const urls = [
		`https://fesavswgvswgfvasw.hxxyrukih4kvmeawzmdmug2eh5uwtcmt.workers.dev/${path}`,
		`https://testfnryjnrjrurjejne4r6uju.pages.dev/${path}`,
		`https://hoplimit.shop/${path}`,
		// میرور ۴ - مخزن شخصی خودمون
		`${PERSONAL_REPO_RAW_BASE}${path}`
	];
	if (path.includes('zeus.obfuscated.js')) {
		urls.push(`https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main/zeus.obfuscated.js` + (path.includes('?') ? path.substring(path.indexOf('?')) : ''));
	}
	for (const url of urls) {
		try {
			const res = await fetch(url, options);
			if (res.ok) return res;
		} catch (e) { }
	}
	return new Response(null, { status: 500 });
}
// کش مشترک فایل‌های مخزن (proxy_vip/*.txt و غیره) — به‌جای فراخوانی مستقیم fetchWithFallback در
// هر جا، این تابع یک بار فچ می‌کند و تا پایان TTL از حافظه برمی‌گرداند. در حافظه‌ی ایزوله‌ی Worker
// است (نه D1/KV)، پس با هر cold start خالی می‌شود.
const REPO_FILE_CACHE = new Map();
async function getCachedRepoFile(path, ttl = 900000) { // پیش‌فرض: ۱۵ دقیقه
	const now = Date.now();
	const cached = REPO_FILE_CACHE.get(path);
	if (cached && (now - cached.timestamp < ttl)) return cached.data;
	// proxy_vip/<CC>.txt همیشه با مخزن شخصی (میرور ۴) ترکیب می‌شه - حتی اگه fetchWithFallback از
	// میرور ۱ تا ۳ یه جواب OK بگیره (مثلاً فایل رسمی وجود داره ولی پروکسی‌هاش خراب/مرده‌ن)، چون
	// fetchWithFallback با اولین OK متوقف می‌شه و میرور ۴ رو اصلاً چک نمی‌کنه.
	const vipMatch = path.match(/^proxy_vip\/([A-Za-z0-9]+)\.txt$/);
	try {
		const [mainRes, personalText] = await Promise.all([
			fetchWithFallback(path).catch(() => null),
			vipMatch ? fetchPersonalRepoFile(path) : Promise.resolve(null),
		]);
		const mainText = mainRes && mainRes.ok ? await mainRes.text() : "";
		if (mainText || personalText) {
			const finalText = vipMatch ? mergeVipProxyText(vipMatch[1], mainText, personalText) : mainText;
			REPO_FILE_CACHE.set(path, { data: finalText, timestamp: now });
			return finalText;
		}
	} catch (e) { }
	return cached ? cached.data : null; // اگه فچ تازه خراب شد، نسخه‌ی قدیمی رو بده نه خالی
}
// همیشه تازه می‌گیرد (نه از کش) چون فراخوانی‌اش یعنی کاربر صریحاً خواسته بروزرسانی شود؛ ولی نتیجه
// را در REPO_FILE_CACHE می‌نویسد تا بعد از آن getCachedRepoFile (testVipCountryProxy/replaceBrokenProxy)
// تا پایان TTL از همین نسخه‌ی تازه استفاده کنند. فقط proxy_vip/*.txt — به فایل‌های عمومی کاری ندارد.
async function syncAllVipProxies() {
	const now = Date.now();
	const listRes = await fetchWithFallback("vip-list");
	if (!listRes.ok) throw new Error("لیست کشورهای VIP در حال حاضر در دسترس نیست");
	const files = await listRes.json();
	const countries = (Array.isArray(files) ? files : [])
		.filter((f) => f && f.name && f.name.endsWith(".txt"))
		.map((f) => f.name.replace(".txt", "").toUpperCase());
	// کشورهایی که فقط در MANUAL_VIP_PROXIES هستن (در مخزن اصلی نیستن) هم اضافه می‌شن تا حذف نشن.
	const manualOnlyCountries = Object.keys(MANUAL_VIP_PROXIES)
		.map((c) => c.toUpperCase())
		.filter((c) => !countries.includes(c));
	countries.push(...manualOnlyCountries);
	if (countries.length === 0) throw new Error("هیچ کشوری در مخزن VIP یافت نشد");

	const perCountry = {};
	let totalProxies = 0;
	await Promise.all(countries.map(async (cc) => {
		const key = `proxy_vip/${cc}.txt`;
		let text = "";
		let fetchOk = false;
		try {
			const res = await fetchWithFallback(key);
			if (res.ok) { text = await res.text(); fetchOk = true; }
		} catch (e) { }
		if (!fetchOk) {
			// فچ ناموفق بود؛ به‌جای پاک کردن کش قبلی، همون نسخه‌ی قبلی (اگه بود) رو پایه می‌گیریم
			// و فقط دوباره با مخزن شخصی/MANUAL_VIP_PROXIES ترکیب می‌کنیم (idempotent - تکراری اضافه نمی‌شه).
			const prev = REPO_FILE_CACHE.get(key);
			text = prev ? prev.data : "";
		}
		// مخزن شخصی (میرور ۴) همیشه چک می‌شه - حتی وقتی fetchOk true بوده - تا وقتی فایل رسمی وجود
		// داره ولی پروکسی‌هاش خراب/مرده‌ن، پروکسی‌های خودمون همچنان اضافه بشن نه نادیده گرفته بشن.
		const personalText = await fetchPersonalRepoFile(key);
		const merged = mergeVipProxyText(cc, text, personalText);
		const lines = merged.split("\n").filter((l) => l.length > 5);
		REPO_FILE_CACHE.set(key, { data: merged, timestamp: now });
		perCountry[cc] = lines.length;
		totalProxies += lines.length;
	}));

	return { countries, perCountry, totalCountries: countries.length, totalProxies, fetchedAt: now };
}
// Both update endpoints (/api/update-panel, /api/update-panel-github) upload the fetched file to
// Cloudflare unchanged, as an ES module (main_module: "zeus.js"). The plain decoded source (vX_Y.js)
// is only a function BODY that ends with a top-level "return" of the worker object - it is not a
// module (no default export, and a top-level return is illegal in a module), so Cloudflare refuses it.
// Only the obfuscated stub (import ... + default export) or a real module can be deployed this way.
// Fail early with a message that says so, instead of a bare Cloudflare syntax error. A valid module
// can never end in a top-level return, so this can't block a good file; anything else is left to Cloudflare.
function assertDeployableWorkerModule(code, sourceLabel) {
	if (/return\s+__WORKER_EXPORT__\s*;?\s*$/.test(String(code).trim())) {
		throw new Error("فایل «" + sourceLabel + "» نسخه‌ی decode‌شده (خوانا) است، نه فایل قابل‌دیپلوی: با «return __WORKER_EXPORT__» تمام می‌شود و export default ندارد، برای همین کلودفلر آن را رد می‌کند. نسخه‌ی obfuscated (stub دارای export default) را در گیت‌هاب بگذارید.");
	}
}
let localLastAutoResetCheck = 0;
async function checkAutoResets(env, ctx) {
	const now = Date.now();
	if (now - localLastAutoResetCheck < 3600000) return;
	try {
		const cache = caches.default;
		const cacheReq = new Request("https://internal.zeus/auto_reset");
		if (await cache.match(cacheReq)) return;
		const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'last_auto_reset_check'").first();
		const dbLastCheck = row ? parseInt(row.value) || 0 : 0;
		if (now - dbLastCheck < 3600000) {
			localLastAutoResetCheck = dbLastCheck;
			const ttl = Math.floor((3600000 - (now - dbLastCheck)) / 1000);
			if (ttl > 0 && ctx) ctx.waitUntil(cache.put(cacheReq, new Response("1", { headers: { "Cache-Control": `max-age=${ttl}` } })));
			return;
		}
		await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_auto_reset_check', ?)").bind(String(now)).run();
		localLastAutoResetCheck = now;
		if (ctx) ctx.waitUntil(cache.put(cacheReq, new Response("1", { headers: { "Cache-Control": "max-age=3600" } })));
		const todayUtc = Math.floor(now / 86400000) * 86400000;
		await env.DB.prepare(`UPDATE users SET used_gb = 0, is_active = 1, last_reset_vol_time = ? WHERE auto_reset_vol_days > 0 AND ? >= (last_reset_vol_time + (auto_reset_vol_days * 86400000))`).bind(todayUtc, todayUtc).run();
		await env.DB.prepare(`UPDATE users SET used_req = 0, is_active = 1, last_reset_req_time = ? WHERE auto_reset_req_days > 0 AND ? >= (last_reset_req_time + (auto_reset_req_days * 86400000))`).bind(todayUtc, todayUtc).run();
		// پاکسازی ردیف‌های ترافیک روزانه‌ی قدیمی‌تر از 30 روز (کاربر بیشتر از 30 روز نیاز ندارد)
		const cutoffDateStr = utcDateKey(now - 30 * 86400000);
		await env.DB.prepare("DELETE FROM daily_traffic WHERE date < ?").bind(cutoffDateStr).run();
	} catch (e) { }
}
// ---- محدودیت کل ریکوئست روزانه‌ی اکانت (global_req_limit) --------------------------------------
// همون عددی که کارت "Request" توی داشبورد نشون می‌ده، با سقفی که ادمین در تنظیمات ست کرده مقایسه
// می‌شه. این عدد از دو منبع ترکیب می‌شه، دقیقاً به همون شکلی که خود کارت داشبورد (GET /api/users)
// انجامش می‌ده:
//   ۱) شمارنده‌ی خودِ پنل (req_today در جدول settings + GLOBAL_REQ_COUNT هنوز-flush-نشده‌ی این
//      ایزوله) - این روی هر ریکوئستی که وورکر واقعاً اجرا بشه (شامل اسکن/ترافیک مزاحم) افزایش پیدا
//      می‌کنه، صرف‌نظر از اینکه پنل باز باشه یا نه.
//   ۲) عدد واقعیِ Cloudflare (getCfUsage -> GraphQL Analytics، از حساب واقعی کلودفلر شما، نه فقط
//      حدس پنل) - اگه CF_API_TOKEN/CF_ACCOUNT_ID تنظیم نشده باشه، این تابع فقط صفر برمی‌گردونه و
//      محاسبه بی‌صدا فقط به شمارنده‌ی خودِ پنل تکیه می‌کنه.
// هر کدوم بزرگ‌تر بود ملاک عمل قرار می‌گیره (Math.max) - دقیقاً برای همون نگرانی که اگه یه جایی
// شمارنده‌ی خودِ پنل عقب بمونه یا با خطا مواجه بشه (کلد-استارت ایزوله، خطای نوشتن در D1، و...)، عدد
// واقعیِ کلودفلر جایگزینش بشه. اگه عدد کلودفلر از عدد ذخیره‌شده بیشتر بود، همون‌جا هم در settings
// بازنویسی می‌شه تا این «ترمیم» ماندگار بمونه، نه فقط برای همین یک چک.
// نتیجه‌ی نهایی (فقط یک بایت "0"/"1") با TTL کوتاه روی caches.default کش می‌شه تا این چک روی هر
// اتصال/هارتبیت، دیتابیس یا Cloudflare API رو صدا نزنه (خودِ getCfUsage هم کش ۱۵ثانیه‌ای جدا داره).
// چون req_today و عدد کلودفلر هر دو دقیقاً سر تاریخ UTC جدید از نو شمارش می‌شن، این قفل هم خودکار
// سر ساعت 00:00 UTC آزاد می‌شه - عمداً هیچ فیلدی روی جدول users نوشته نمی‌شه (بر خلاف قطعیِ
// per-user)، چون این یک محدودیتِ موقتِ سراسریه، نه غیرفعال‌سازی دائمیِ یک کاربر خاص.
const GLOBAL_REQ_LIMIT_DEFAULT = 75000;
// تی‌تی‌ال کش نتیجه‌ی نهایی (0/1) - چون خودتون گفتید چند ده‌ثانیه/چند دقیقه تاخیر مهم نیست، این عدد
// از ۲۰ به ۶۰ ثانیه افزایش پیدا کرد تا تعداد دفعاتی که این تابع به‌جای cache باید واقعاً به D1/Cloudflare
// سر بزنه، حدود ۳ برابر کمتر بشه (مستقیماً هزینه‌ی D1 read و درخواست به Cloudflare API رو کم می‌کنه).
const GLOBAL_REQ_LIMIT_CACHE_TTL_SECONDS = 60;
// فقط وقتی شمارنده‌ی خودِ پنل به این نسبت از سقف نزدیک شده، زحمت صدا زدن Cloudflare GraphQL API
// (که یک HTTP fetch واقعی به خارج از Workers هست، نه یک خواندن ارزان از D1) رو به خودمون می‌دیم.
// در بقیه‌ی روز (مثلاً وقتی مصرف ۱۰٪ سقفه) اصلاً به کلودفلر سر نمی‌زنیم و فقط شمارنده‌ی خودِ پنل
// (که همیشه در دسترسه و رایگانه) ملاک قرار می‌گیره. این تنها جایی هست که "لایه‌ی دومِ" کلودفلر واقعاً
// لازمه: نزدیکی به سقف، جایی که دقت بیشتر اهمیت داره.
const GLOBAL_REQ_LIMIT_CF_CHECK_THRESHOLD_RATIO = 0.9;
function globalReqLimitCacheRequest() {
	return new Request("https://internal.zeus/global_req_limit_status");
}
async function isGlobalReqLimitReached(env, ctx) {
	try {
		const cached = await caches.default.match(globalReqLimitCacheRequest());
		if (cached) return (await cached.text()) === "1";
	} catch (e) { }
	let reached = false;
	try {
		const today = new Date().toISOString().split("T")[0];
		// به‌جای ۳ کوئری جدای SELECT ... first() (که هر کدوم یه رفت‌وبرگشت جدا به D1 هست)، هر سه
		// کلید توی یک کوئری با IN (...) خونده می‌شن - نتیجه یکیه، ولی یک رفت‌وبرگشت D1 به‌جای سه‌تا.
		const settingsRows = await env.DB.prepare("SELECT key, value FROM settings WHERE key IN ('global_req_limit','req_today','req_last_date')").all();
		const settingsMap = {};
		(settingsRows.results || []).forEach((r) => { settingsMap[r.key] = r.value; });
		const limitVal = settingsMap.global_req_limit;
		const limit = limitVal !== undefined && limitVal !== null && limitVal !== "" ? parseInt(limitVal) || 0 : GLOBAL_REQ_LIMIT_DEFAULT;
		// اگر آخرین flush مربوط به دیروز (یا قبل‌تر) باشه، یعنی هنوز هیچ ایزوله‌ای برای امروز چیزی
		// commit نکرده - req_today فعلاً متعلق به دیروزه، پس نباید به‌عنوان مصرف امروز حساب بشه.
		let dbTodayTotal = settingsMap.req_last_date === today && settingsMap.req_today !== undefined ? parseInt(settingsMap.req_today) || 0 : 0;
		let liveTotal = dbTodayTotal + GLOBAL_REQ_COUNT;
		// فقط اگه به آستانه‌ی نزدیکی به سقف رسیده باشیم، برای اطمینان بیشتر سراغ عدد واقعیِ کلودفلر
		// می‌ریم. تا قبل از اون آستانه، شمارنده‌ی خودِ پنل به‌تنهایی کافیه و هیچ fetch خارجی‌ای زده نمی‌شه.
		if (limit > 0 && liveTotal >= limit * GLOBAL_REQ_LIMIT_CF_CHECK_THRESHOLD_RATIO) {
			const liveCf = await getCfUsage(env);
			const cfTodayTotal = (liveCf && liveCf.today) || 0;
			if (cfTodayTotal > dbTodayTotal) {
				dbTodayTotal = cfTodayTotal;
				liveTotal = dbTodayTotal + GLOBAL_REQ_COUNT;
				const persistTask = (async () => {
					try {
						await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(dbTodayTotal), String(dbTodayTotal)).run();
						await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(today, today).run();
					} catch (e) { }
				})();
				if (ctx) ctx.waitUntil(persistTask);
				else persistTask.catch(() => { });
			}
		}
		reached = limit > 0 && liveTotal >= limit;
	} catch (e) {
		reached = false;
	}
	try {
		const res = new Response(reached ? "1" : "0", { headers: { "Cache-Control": `max-age=${GLOBAL_REQ_LIMIT_CACHE_TTL_SECONDS}` } });
		const task = caches.default.put(globalReqLimitCacheRequest(), res);
		if (ctx) ctx.waitUntil(task);
		else task.catch(() => { });
	} catch (e) { }
	return reached;
}
// کلید روزانه به وقت UTC، به فرم YYYY-MM-DD - ریست ساعت 00:00 UTC. هنوز برای گروه‌بندی
// نمودار 30 روزه (/api/stats-history) و برای cutoff پاکسازی استفاده می‌شود؛ خودِ ذخیره‌سازی
// ردیف‌های daily_traffic/daily_requests دیگر روزانه نیست، ساعتی است (به utcHourKey زیر نگاه کنید).
function utcDateKey(ts) {
	return new Date(ts).toISOString().split("T")[0];
}
// کلید ساعتی به وقت UTC، به فرم YYYY-MM-DDTHH (پیشوند دقیق ISO، پس مرتب‌سازی رشته‌ای = مرتب‌سازی
// زمانی واقعی). این همون ستون TEXT PRIMARY KEY "date" قبلی رو استفاده می‌کنه، فقط دیگه یک روز کامل
// رو نماینده نیست، یک ساعت رو نماینده‌ست - پس نیازی به ALTER TABLE / migration نیست. چون این پیشوند
// همیشه با فرمت روزانه‌ی قدیمی (YYYY-MM-DD) هم‌خوانی داره (۱۰ کاراکتر اول یکسانه)، مقایسه‌های رشته‌ای
// (>=, <, ORDER BY) و همچنین cutoff پاکسازی که هنوز بر مبنای روزه، بدون تغییر درست کار می‌کنن.
function utcHourKey(ts) {
	return new Date(ts).toISOString().slice(0, 13); // "YYYY-MM-DDTHH"
}
// ثبت/جمع‌زدن مقدار مصرف (بر حسب گیگابایت) روی ردیف ساعت جاری (UTC) در daily_traffic.
// این تابع در همان لحظاتی صدا زده می‌شود که ترافیک کاربران از کش حافظه به D1 flush می‌شود.
// قبلاً کلید هر ردیف یک روز کامل بود (خطای بازه‌ی «7/30 روز گذشته» تا ۲۴ ساعت)؛ حالا هر ردیف یک
// ساعت است، پس بازه‌های رولینگ (روزانه/7روزه/30روزه) با دقت ~۱ ساعت محاسبه می‌شن، در حالی که تعداد
// کل ردیف‌ها همچنان محدود و ارزان می‌مونه (حداکثر ۲۴×۳۰=۷۲۰ ردیف با همون نگه‌داری 30 روزه‌ی فعلی) -
// نه یک ردیف مستقل به ازای هر رویداد flush (که رشد نامحدود و هزینه‌ی خواندن/نوشتن غیرقابل‌کنترلی داشت).
function recordDailyTraffic(env, ctx, deltaGb) {
	if (!deltaGb || deltaGb <= 0) return;
	const hourKey = utcHourKey(Date.now());
	const task = env.DB.prepare("INSERT INTO daily_traffic (date, gb) VALUES (?, ?) ON CONFLICT(date) DO UPDATE SET gb = gb + excluded.gb").bind(hourKey, deltaGb).run().catch(() => { });
	if (ctx) ctx.waitUntil(task);
	// خودِ promise برگردونده می‌شه تا صداکننده‌هایی که ctx ندارن (مثل flushExpiredTraffic) بتونن
	// await کنن؛ وگرنه اون نوشتن یتیم می‌موند و ممکن بود با تموم شدن ریکوئست اصلاً اجرا نشه.
	return task;
}
// ---- Per-connection user-auth cache (D1 read reduction) --------------------------------------
// Same caches.default (edge Cache API) pattern as checkAutoResets() above, applied to the
// single hottest D1 read in this file: "which user does this uuid / trojan-hash belong to" -
// executed on every incoming VLESS/Trojan connection attempt, including garbage/scanner traffic
// that never matches a real user. For Trojan specifically, a cache miss on the direct
// trojan_hash/uuid lookup falls back to `SELECT * FROM users WHERE is_active = 1` (a full
// table scan) - caching the outcome (positive AND negative) of that whole lookup means repeat
// traffic from the same client, and repeat garbage from the same scanner, stops hitting D1
// entirely once cached.
//
// TTL is short (10s) on purpose: this cache backs an authorization decision (is_active,
// limit_gb, limit_req, expiry_days), not just display data. On top of the short TTL, every
// place an admin (or the system) changes those fields for a specific user calls
// invalidateUserAuthCache() right away, so a stale read can only survive for whatever is left
// of those 10 seconds - never longer. Fields that are NOT auth/routing-critical (active_ips,
// last_active, the live used_gb/used_req counters, proxy_rotate_cooldowns) are deliberately
// left to expire on TTL alone: they're already eventually-consistent by design elsewhere in
// this file (GLOBAL_TRAFFIC_CACHE / USER_REQ_CACHE add in-memory deltas on top of whatever
// used_gb/used_req came back, cached or not), so invalidating on every one of those routine
// writes would erase most of the D1-read savings for close to no real benefit.
const USER_AUTH_CACHE_TTL_SECONDS = 10;
function userAuthCacheRequest(kind, key) {
	return new Request(`https://internal.zeus/user_auth/${kind}/${encodeURIComponent(String(key))}`);
}
async function getCachedAuthUser(kind, key) {
	if (!key) return undefined;
	try {
		const res = await caches.default.match(userAuthCacheRequest(kind, key));
		if (!res) return undefined; // no cache entry at all -> caller must hit D1
		const text = await res.text();
		return text === "0" ? null : JSON.parse(text); // "0" = cached "no such user" (negative cache)
	} catch (e) {
		return undefined;
	}
}
function putCachedAuthUser(ctx, kind, key, user) {
	if (!key) return;
	try {
		const body = user ? JSON.stringify(user) : "0";
		const res = new Response(body, { headers: { "Cache-Control": `max-age=${USER_AUTH_CACHE_TTL_SECONDS}` } });
		const task = caches.default.put(userAuthCacheRequest(kind, key), res);
		if (ctx) ctx.waitUntil(task);
		else task.catch(() => { });
	} catch (e) { }
}
// Deletes both the vless-style (raw uuid) and trojan-style (sha224 of uuid) cache entries for a
// user, so callers only ever need to pass the uuid they know about. Returns a promise the
// caller may await (replaceBrokenProxy does, since it has no ctx to waitUntil with); when ctx
// is available it's also registered there so callers that don't await still get to completion.
function invalidateUserAuthCache(ctx, uuid, trojanHash) {
	try {
		const tasks = [];
		if (uuid) tasks.push(caches.default.delete(userAuthCacheRequest("u", uuid)));
		const tHash = trojanHash || (uuid ? sha224Pure(uuid) : null);
		if (tHash) tasks.push(caches.default.delete(userAuthCacheRequest("t", tHash)));
		const all = Promise.all(tasks).catch(() => { });
		if (ctx) ctx.waitUntil(all);
		return all;
	} catch (e) {
		return Promise.resolve();
	}
}
let GLOBAL_IPS_CACHE = {};
let GLOBAL_IPS_LAST_FETCH = 0;
async function getCachedIps() {
	const now = Date.now();
	if (now - GLOBAL_IPS_LAST_FETCH < 86400000 && Object.keys(GLOBAL_IPS_CACHE).length > 0) {
		return GLOBAL_IPS_CACHE;
	}
	try {
		const res = await fetchWithFallback("ips.txt");
		if (!res.ok) return GLOBAL_IPS_CACHE;
		const text = await res.text();
		const blocks = text.split("----------");
		let newData = {};
		blocks.forEach((block) => {
			const lines = block
				.trim()
				.split("\n")
				.map((l) => l.trim())
				.filter((l) => l.length > 0);
			if (lines.length === 0) return;
			let opName = "Unknown";
			const ips = [];
			lines.forEach((line) => {
				if (line.includes("#")) opName = line.split("#")[1].trim();
				else if (!line.startsWith("[source")) ips.push(line);
			});
			if (ips.length > 0) newData[opName] = ips;
		});
		if (Object.keys(newData).length > 0) {
			GLOBAL_IPS_CACHE = newData;
			GLOBAL_IPS_LAST_FETCH = now;
		}
	} catch (e) {}
	return GLOBAL_IPS_CACHE;
}
function getRandomIps(cachedIpsData, operator, count) {
	let availableIps = [];
	if (operator === "all") {
		Object.values(cachedIpsData).forEach((ips) => (availableIps = availableIps.concat(ips)));
	} else {
		availableIps = cachedIpsData[operator] || [];
	}
	availableIps = [...new Set(availableIps)];
	if (availableIps.length === 0) return [];
	if (count >= availableIps.length) return availableIps;
	const shuffled = availableIps.slice();
	for (let i = shuffled.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
	}
	return shuffled.slice(0, count);
}
async function checkAutoRotates(env, ctx) {
}

// Default set of countries auto-provisioned for a brand-new user, and the set
// that gets added to already-existing users automatically whenever the admin
// saves the pinned-locations list in settings (see reset_action === "locations"
// below, and applyPinnedLocationsToAllUsers() on the client). This is now just the built-in
// FALLBACK: the real, admin-editable list lives in the `settings` table under
// the key "pinned_locations" (see getPinnedLocationsSetting()). This constant
// is only used if that setting has never been saved yet (fresh install), so
// existing deployments keep working unchanged after this update.
// replaceBrokenProxy() keeps each slot locked to its own country when healing
// a broken proxy, so once a slot is tagged with a country it never drifts to
// another country - regardless of whether that country is still "pinned".
const PINNED_DEFAULT_LOCATIONS_FALLBACK = ["UZ", "KZ", "TR", "LY", "NL", "AL", "EE", "BG", "LV", "SE", "NO", "GB", "US", "ES", "BE"];
// Built-in default/seed values for the three admin-editable settings-modal fields
// "آیپی تمیز سراسری" (global_clean_ip), "آیپی های تمیز دیگر" (other_clean_ips) and
// "Proxy IP" (inline_proxy_ip). Used in two places: (1) ensureSchema() seeds these
// straight into the `settings` table on first run (INSERT OR IGNORE) so they exist
// as real app defaults from the very first deploy - no manual "save" required in
// the panel first - and (2) as the read-side fallback in the getters below, only
// for the case where the row is missing entirely (never configured). If the admin
// has explicitly saved an empty value (to turn a field off on purpose), that empty
// value is respected and is NOT replaced by these defaults.
const DEFAULT_GLOBAL_CLEAN_IP_FALLBACK = "104.20.25.138";
const DEFAULT_OTHER_CLEAN_IPS_FALLBACK = ["104.26.1.116", "104.21.122.162", "185.162.228.105", "185.148.105.218", "104.18.39.219", "185.162.230.76"];
const DEFAULT_INLINE_PROXY_IP_FALLBACK = "178.105.227.210";
// «محدودیت کاربر» (user_limit) - سقف تعداد دستگاه هم‌زمان هر کاربر؛ همون فیلد «محدودیت
// کاربر» توی فرم کاربر (ستون‌های ip_limit/max_connections). سه‌جا استفاده می‌شه: (۱) پیش‌فرض
// کاربر جدید وقتی فرم/API چیزی توی این فیلد نفرستاده باشه (POST /api/users)، (۲) با «ذخیره‌ی
// تنظیمات» یا Push پنل مادر روی ستون‌های ip_limit/max_connections همه‌ی کاربرهای *موجود* هم
// اعمال می‌شه (POST /api/settings/bulk)، (۳) پیش‌فرض placeholder فرم. فقط وقتی مقدار
// fallback استفاده می‌شه که تنظیم 'user_limit' هیچ‌وقت توی settings ذخیره نشده باشه (نصب تازه).
const DEFAULT_USER_LIMIT_FALLBACK = 2;
// «هشدار تعداد دستگاه» (device_warning_threshold) - آستانه‌ی سراسریِ *هشدار*: اگه تعداد
// دستگاه‌های فعالِ یه کاربر از این عدد بیشتر بشه، device_warning_at ست می‌شه (persistActiveIp
// پایین‌تر) و روی کارتش هشدار قرمز می‌آد. این عدد دیگه هیچ ربطی به ip_limit/max_connections
// کاربرها نداره (اون‌ها با «محدودیت کاربر» بالا ست می‌شن) و هیچ اتصالی قطع نمی‌کنه.
// 0 = هشدار خاموش. فقط وقتی fallback استفاده می‌شه که تنظیمش هیچ‌وقت ذخیره نشده باشه.
const DEFAULT_DEVICE_WARNING_THRESHOLD_FALLBACK = 4;
// «سیاست ثبت دستگاه متصل» (device seen/confirmed policy). قبلاً همون لحظه‌ی اول پیام
// VLESS/Trojan یه IP فوری «دستگاه» حساب می‌شد - بدون حداقل زمان یا حجم - برای همین یه
// تست پینگِ چندثانیه‌ای (یا حتی یه هندشیکِ ناتمام) دقیقاً مثل یه دستگاه واقعی می‌شمرد.
// حالا هر IPِ تازه اول فقط «دیده‌شده»ست (فقط توی حافظه‌ی خودِ همون اتصال - نه D1، نه
// سقف ip_limit، نه شمارنده‌ی آنلاین) و با هر کدوم از این دو شرط «تأیید» می‌شه (نگاه
// کنید به confirmActiveIp/checkDeviceConfirmation در handlevIees):
//  (۱) اتصالِ پایدار: همون یک اتصال حداقل DEVICE_CONFIRM_MIN_DURATION_MS باز بمونه و
//      حداقل DEVICE_CONFIRM_MIN_BYTES بایت (مجموع آپلود+دانلود، از addBytes) جابه‌جا کنه.
//  (۲) اتصال‌های کوتاهِ زیاد: مجموع بایتِ همون (کاربر, IP) - نگاه کنید IP_BURST_BYTES -
//      توی یه پنجره‌ی DEVICE_CONFIRM_BURST_WINDOW_MS به DEVICE_CONFIRM_BURST_BYTES برسه.
// این عددها تخمینی‌ان (یه TLS handshake + یه پینگ معمولاً حدود ۵ تا ۸ کیلوبایته)، نه
// اندازه‌گیری‌شده از داده‌ی واقعی - جایی برای تنظیم دقیق‌ترشون در آینده هست. سقفِ
// «محدودیت کاربر»/ip_limit هم از همین نسخه به بعد فقط توی confirmActiveIp (لحظه‌ی
// تأیید) اعمال می‌شه، نه موقع اولین هندشیک - یعنی یه تست پینگ همیشه رد می‌شه، ولی
// استفاده‌ی واقعی‌ای که جا نداره بعد از چند ثانیه/چند KB قطع می‌شه. محدودیت‌های شناخته‌شده
// (عمداً حل نشده): دستگاهی که همیشه خیلی کم‌حجمه اصلاً «تأیید» نمی‌شه (مصرفش همچنان
// روی سهمیه‌ی حجم می‌ره)؛ IPِ قدیمیِ یه دستگاهی که شبکه عوض کرده تا ۱۸۰ ثانیه یه جای
// سقف رو اشغال می‌کنه؛ IP_BURST_BYTES بین isolateها به اشتراک نیست (تقریبیه، نه دقیق).
const DEVICE_CONFIRM_MIN_DURATION_MS = 10000;
const DEVICE_CONFIRM_MIN_BYTES = 30 * 1024;
const DEVICE_CONFIRM_BURST_WINDOW_MS = 5 * 60 * 1000;
const DEVICE_CONFIRM_BURST_BYTES = 1024 * 1024;
// «تأخیر هشدار تعداد دستگاه» - device_warning_at دیگه با همون اولین باری که تعداد
// دستگاه‌های تأییدشده از آستانه (device_warning_threshold) رد می‌شه ست نمی‌شه؛ باید
// این تعداد بار پشت‌سرهم (هر بار = یک تأیید دستگاه تازه یا یک رفرش هیت‌بیت - نگاه کنید
// evaluateDeviceWarning) عبور از آستانه دیده بشه. برگشتن به زیر آستانه (حتی یه بار)
// شمارش رو صفر می‌کنه. یه IP که با یه اتصال کوتاهِ لحظه‌ای از سقف رد بشه و توی همون
// دور بعدی دیگه نباشه، هیچ‌وقت هشدار نمی‌سازه.
const DEVICE_WARNING_CONFIRM_STREAK = 2;
// «پورت» - پورتی که هم به‌عنوان مقدار پیش‌فرض چک‌باکس پورت توی فرم افزودن
// کاربر جدید انتخاب می‌شه (renderPortCheckboxes سمت کلاینت)، و هم موقع «ذخیره
// تنظیمات» به‌صورت override کامل روی ستون port همه‌ی کاربرهای *موجود* هم
// اعمال می‌شه (پورت‌های قبلی‌شون پاک و با همین یکی جایگزین می‌شه - نگاه کنید
// به POST /api/settings/bulk). این مقدار فقط به‌عنوان پیش‌فرضِ اولیه استفاده
// می‌شه، برای وقتی تنظیم 'default_port' هیچ‌وقت توی settings ذخیره نشده باشه
// (نصب تازه).
const DEFAULT_PORT_FALLBACK = "2083";
// «پیش‌فرض‌های کاربر جدید» - دقیقاً همان مقادیری که فرم دستی «ایجاد کاربر جدید»
// (openCreateModal سمت کلاینت) از قبل hardcode می‌کرد، حالا به‌صورت Settings واقعی
// (کلیدهای new_user_* در جدول settings) تا هم از مودال «تنظیمات پـنـل» قابل ویرایش
// باشند و هم پنل مادر بتواند با POST /api/settings/bulk همه‌ی پنل‌ها را با هم
// یکسان کند. سه جا از این‌ها می‌خوانند: (۱) ensureSchema() اگر کلیدی نبود
// seed می‌کند، (۲) POST /api/users برای هر فیلدی که درخواست نفرستاده باشد (مثلاً
// وقتی پنل مادر فقط username می‌فرستد)، (۳) فرم «ایجاد کاربر جدید» و Import Users
// سمت کلاینت. همه‌ی مقدارها رشته‌اند (ستون value جدول settings TEXT است):
// فلگ‌ها "1"/"0"، frag_len/frag_int خالی = فرگمنتیشن خاموش.
const NEW_USER_DEFAULTS_FALLBACK = {
	new_user_fingerprint: "ios",
	new_user_auto_reset_vol_days: "1",
	new_user_auto_reset_req_days: "1",
	new_user_auto_rotate_user_proxy: "1",
	new_user_enable_direct: "0",
	new_user_block_porn: "0",
	new_user_block_ads: "0",
	new_user_frag_len: "",
	new_user_frag_int: "",
	new_user_ip_operator: "all",
	new_user_ip_count: "999999", // no count cap — getRandomIps() returns every available Clean IP once count >= pool size
	new_user_auto_rotate_ip: "0",
	new_user_start_on_first_connect: "0",
	new_user_connection_type: "vless",
	// Early Data (ed=): پیش‌فرض خاموش. new_user_early_data_size بایت early data است (مقدار
	// پیشنهادی 2560، حداکثر 8192 طبق مستندات xray/sing-box WS early data).
	new_user_early_data_enabled: "0",
	new_user_early_data_size: "2560",
};
// فقط این دو کلید مجازند خالی ذخیره شوند (خالی = فرگمنت خاموش)؛ برای بقیه، مقدار
// خالی/نامعتبر یعنی «از NEW_USER_DEFAULTS_FALLBACK استفاده کن».
const NEW_USER_DEFAULTS_EMPTY_OK = ["new_user_frag_len", "new_user_frag_int"];
const NEW_USER_TLS_PORTS = ["443", "2053", "2083", "2087", "2096", "8443"];
// Same list as the Fingerprint <select> of the panel (fingerprint-select / nud-fingerprint) — the only
// values POST /api/settings/bulk accepts when it is asked to write a fingerprint onto existing users.
const NEW_USER_FINGERPRINTS = ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "unsafe"];
// Early Data (ed=): سقف مجاز سایز (بایت) برای new_user_early_data_size وقتی POST /api/settings/bulk قراره اون رو روی
// کاربرهای *موجود* بنویسه؛ همون ۸۱۹۲ که توی مستندات xray/sing-box برای WS early data حداکثره.
const EARLY_DATA_MAX_SIZE = 8192;
// Hard cap on how many location slots a single user can accumulate over time
// via the additive per-user "locations" reset action (see below), which now
// runs automatically for every user right after the admin saves the pinned
// list in settings. Provisioning a
// brand-new user is NOT capped by this (a new user always gets the full
// current pinned list, even if that list itself has grown past this number).
const MAX_LOCATIONS_PER_USER = 20;
// /api/change-password was removed from this list: the mother panel's "Push to All Panels" now sets the
// default admin password through it with X-Master-Key (see the handler below for the master-key branch).
const MASTER_KEY_BLOCKED_PATHS = ["/api/auto-update-setup", "/api/update-panel", "/api/update-panel-github"];

// Full ISO 3166-1 alpha-2 -> alpha-3 table (249 entries), used to compute a
// permanent WS path segment for ANY country in the VIP proxy repository -
// not just the ones currently pinned in settings. This is what makes "پین
// بودن" purely a statement about which countries get auto-added to the
// default sub/config list; it has no bearing on whether a country's path
// works or whether it gets auto-healed - every country in proxy_vip/*.txt
// gets a working path and healing from the moment it's ever assigned to a
// user, pinned or not.
const ISO_ALPHA3_MAP = {
	AD: "AND", AE: "ARE", AF: "AFG", AG: "ATG", AI: "AIA", AL: "ALB",
	AM: "ARM", AO: "AGO", AQ: "ATA", AR: "ARG", AS: "ASM", AT: "AUT",
	AU: "AUS", AW: "ABW", AX: "ALA", AZ: "AZE", BA: "BIH", BB: "BRB",
	BD: "BGD", BE: "BEL", BF: "BFA", BG: "BGR", BH: "BHR", BI: "BDI",
	BJ: "BEN", BL: "BLM", BM: "BMU", BN: "BRN", BO: "BOL", BQ: "BES",
	BR: "BRA", BS: "BHS", BT: "BTN", BV: "BVT", BW: "BWA", BY: "BLR",
	BZ: "BLZ", CA: "CAN", CC: "CCK", CD: "COD", CF: "CAF", CG: "COG",
	CH: "CHE", CI: "CIV", CK: "COK", CL: "CHL", CM: "CMR", CN: "CHN",
	CO: "COL", CR: "CRI", CU: "CUB", CV: "CPV", CW: "CUW", CX: "CXR",
	CY: "CYP", CZ: "CZE", DE: "DEU", DJ: "DJI", DK: "DNK", DM: "DMA",
	DO: "DOM", DZ: "DZA", EC: "ECU", EE: "EST", EG: "EGY", EH: "ESH",
	ER: "ERI", ES: "ESP", ET: "ETH", FI: "FIN", FJ: "FJI", FK: "FLK",
	FM: "FSM", FO: "FRO", FR: "FRA", GA: "GAB", GB: "GBR", GD: "GRD",
	GE: "GEO", GF: "GUF", GG: "GGY", GH: "GHA", GI: "GIB", GL: "GRL",
	GM: "GMB", GN: "GIN", GP: "GLP", GQ: "GNQ", GR: "GRC", GS: "SGS",
	GT: "GTM", GU: "GUM", GW: "GNB", GY: "GUY", HK: "HKG", HM: "HMD",
	HN: "HND", HR: "HRV", HT: "HTI", HU: "HUN", ID: "IDN", IE: "IRL",
	IL: "ISR", IM: "IMN", IN: "IND", IO: "IOT", IQ: "IRQ", IR: "IRN",
	IS: "ISL", IT: "ITA", JE: "JEY", JM: "JAM", JO: "JOR", JP: "JPN",
	KE: "KEN", KG: "KGZ", KH: "KHM", KI: "KIR", KM: "COM", KN: "KNA",
	KP: "PRK", KR: "KOR", KW: "KWT", KY: "CYM", KZ: "KAZ", LA: "LAO",
	LB: "LBN", LC: "LCA", LI: "LIE", LK: "LKA", LR: "LBR", LS: "LSO",
	LT: "LTU", LU: "LUX", LV: "LVA", LY: "LBY", MA: "MAR", MC: "MCO",
	MD: "MDA", ME: "MNE", MF: "MAF", MG: "MDG", MH: "MHL", MK: "MKD",
	ML: "MLI", MM: "MMR", MN: "MNG", MO: "MAC", MP: "MNP", MQ: "MTQ",
	MR: "MRT", MS: "MSR", MT: "MLT", MU: "MUS", MV: "MDV", MW: "MWI",
	MX: "MEX", MY: "MYS", MZ: "MOZ", NA: "NAM", NC: "NCL", NE: "NER",
	NF: "NFK", NG: "NGA", NI: "NIC", NL: "NLD", NO: "NOR", NP: "NPL",
	NR: "NRU", NU: "NIU", NZ: "NZL", OM: "OMN", PA: "PAN", PE: "PER",
	PF: "PYF", PG: "PNG", PH: "PHL", PK: "PAK", PL: "POL", PM: "SPM",
	PN: "PCN", PR: "PRI", PS: "PSE", PT: "PRT", PW: "PLW", PY: "PRY",
	QA: "QAT", RE: "REU", RO: "ROU", RS: "SRB", RU: "RUS", RW: "RWA",
	SA: "SAU", SB: "SLB", SC: "SYC", SD: "SDN", SE: "SWE", SG: "SGP",
	SH: "SHN", SI: "SVN", SJ: "SJM", SK: "SVK", SL: "SLE", SM: "SMR",
	SN: "SEN", SO: "SOM", SR: "SUR", SS: "SSD", ST: "STP", SV: "SLV",
	SX: "SXM", SY: "SYR", SZ: "SWZ", TC: "TCA", TD: "TCD", TF: "ATF",
	TG: "TGO", TH: "THA", TJ: "TJK", TK: "TKL", TL: "TLS", TM: "TKM",
	TN: "TUN", TO: "TON", TR: "TUR", TT: "TTO", TV: "TUV", TW: "TWN",
	TZ: "TZA", UA: "UKR", UG: "UGA", UM: "UMI", US: "USA", UY: "URY",
	UZ: "UZB", VA: "VAT", VC: "VCT", VE: "VEN", VG: "VGB", VI: "VIR",
	VN: "VNM", VU: "VUT", WF: "WLF", WS: "WSM", YE: "YEM", YT: "MYT",
	ZA: "ZAF", ZM: "ZMB", ZW: "ZWE",
};
// Legacy path segments that must NEVER change because they're already baked
// into links that were issued before this table existed (e.g. GB's segment
// was "G-b", 2 letters, not the standard 3-letter "G-b-r" this table would
// otherwise produce). Only add an entry here for a code whose already-issued
// segment doesn't match the auto-generated one below.
const LOCATION_PATH_CODE_OVERRIDES = { GB: "G-b" };
function computePathSegmentFromAlpha3(alpha3) {
	return alpha3
		.split("")
		.map((ch, i) => (i === 0 ? ch : ch.toLowerCase()))
		.join("-");
}
// Built once at module load: every possible path segment -> its country code,
// so incoming requests can be matched in O(1) instead of scanning the table.
const PATH_SEGMENT_TO_COUNTRY = (() => {
	const map = {};
	for (const cc in ISO_ALPHA3_MAP) map[computePathSegmentFromAlpha3(ISO_ALPHA3_MAP[cc])] = cc;
	for (const cc in LOCATION_PATH_CODE_OVERRIDES) {
		const autoSeg = computePathSegmentFromAlpha3(ISO_ALPHA3_MAP[cc]);
		if (autoSeg !== LOCATION_PATH_CODE_OVERRIDES[cc]) delete map[autoSeg];
		map[LOCATION_PATH_CODE_OVERRIDES[cc]] = cc;
	}
	return map;
})();
// Display code shown in the WS path in place of the old sequential "loc-N"
// suffix. Works for ANY ISO country code that has a VIP proxy list, not just
// currently-pinned ones - keyed by country (not array index) so a slot keeps
// the same path segment even after replaceBrokenProxy() heals it in place,
// or if a slot's position in user_socks5 ever changes. Only a country code
// this table has never heard of (not valid ISO 3166-1) falls back to the old
// "loc-<index>" suffix.
function getLocationPathSegment(countryCode, locIdx) {
	if (countryCode) {
		const cc = countryCode.toUpperCase();
		if (LOCATION_PATH_CODE_OVERRIDES[cc]) return LOCATION_PATH_CODE_OVERRIDES[cc];
		if (ISO_ALPHA3_MAP[cc]) return computePathSegmentFromAlpha3(ISO_ALPHA3_MAP[cc]);
	}
	return "loc-" + locIdx;
}
// Reverse of getLocationPathSegment(): given the last path segment of an
// incoming request, returns the country code it belongs to, or null.
function getCountryForPathSegment(segment) {
	return PATH_SEGMENT_TO_COUNTRY[segment] || null;
}
// How many candidate proxy lines per country to live-test when provisioning a
// new user. Kept low (unlike replaceBrokenProxy's 15) because this runs once
// per new user across all countries in the current pinned_locations setting
// (see getPinnedLocationsSetting()) in the same request/invocation, and
// Cloudflare Workers cap subrequests per invocation - each candidate line can
// cost up to 2 subrequests (socks5:// and http:// variants), plus 1 list
// fetch per country. Raise it if you have subrequest budget to spare.
// ⚠️ The pinned list is now admin-editable and can grow past 15: at N
// countries, worst case is N * (1 list fetch + 3 * 2 candidate tests) =
// 7N subrequests for a single invocation - e.g. 15 countries = 105, already
// over the Workers Free plan's 50-subrequest-per-invocation cap (Paid plans
// get far more headroom - 10,000/invocation). The additive "بروزرسانی
// لوکیشن‌ها" update (mergePinnedLocationsForUser) only tests the countries a
// user doesn't already have, so it's cheaper than this per-invocation worst
// case in practice - but a brand-new user still tests the full current list
// at once. testVipCountryProxy() fails gracefully per-country (falls back to
// an untested line) rather than crashing, so going over the cap degrades
// quality - some slots quietly skip live-testing - it won't break
// provisioning outright. Still, if you're on the Free plan and the pinned
// list has grown large, consider lowering this to 1 or testing countries in
// smaller sequential batches instead of all-at-once.
const PINNED_PROVISION_TEST_LIMIT = 3;

// Fetch proxy_vip/<country>.txt, shuffle it, and live-test a handful of
// candidates by actually opening a connection through each one. Returns
// { proxy, country } using a working proxy when one is found. If the file
// exists but nothing answers in time, falls back to an untested line so the
// slot still carries the right country tag (replaceBrokenProxy's same-country
// cooldown/heal logic will keep retrying later). Returns null only if the
// country's VIP list itself is missing or empty.
async function testVipCountryProxy(country, testLimit = PINNED_PROVISION_TEST_LIMIT) {
	try {
		const text = await getCachedRepoFile(`proxy_vip/${country}.txt`);
		if (!text) return null;
		const lines = text.split("\n").map((l) => l.trim()).filter((l) => l.length > 5);
		if (lines.length === 0) return null;
		for (let i = lines.length - 1; i > 0; i--) {
			const j = Math.floor(Math.random() * (i + 1));
			[lines[i], lines[j]] = [lines[j], lines[i]];
		}
		const testBatch = lines.slice(0, testLimit).flatMap((line) => {
			if (line.match(/^(socks4|socks5|socks|http|https|tg):\/\//i) || line.includes("t.me/socks")) return [line];
			return [`socks5://${line}`, `http://${line}`];
		});
		try {
			const working = await Promise.any(
				testBatch.map((p) => {
					return new Promise(async (resolve, reject) => {
						let sock = null;
						const timeoutId = setTimeout(() => {
							try { sock && sock.close(); } catch (e) { }
							reject(new Error("timeout"));
						}, 4000);
						try {
							const payload = TEXT_ENCODER.encode("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n");
							sock = await connectProxy(p, "1.1.1.1", 80, payload);
							const reader = sock.readable.getReader();
							const readRes = await reader.read();
							clearTimeout(timeoutId);
							try { sock.close(); } catch (e) { }
							if (readRes.done || !readRes.value) reject(new Error("empty"));
							else resolve(p);
						} catch (e) {
							clearTimeout(timeoutId);
							try { sock && sock.close(); } catch (err) { }
							reject(e);
						}
					});
				})
			);
			return { proxy: working, country };
		} catch (e) {
			// Nothing answered in time - keep the country tag, use an untested line.
			return { proxy: lines[0], country };
		}
	} catch (e) {
		return null;
	}
}

// Builds the permanent proxy list for a BRAND-NEW user: one slot per country
// in `locations` (the current pinned_locations setting - see
// getPinnedLocationsSetting()), in that exact order, so loc-0..loc-N map to
// them no matter what the VIP pool currently has. A country whose pool is
// empty/unreachable still gets its slot (proxy: "", meaning that config
// falls back to a direct connection until healed).
// NOTE: this always builds the list from scratch and is only meant for a
// user that doesn't have any locations yet. For updating an EXISTING user
// without discarding what they already have, use mergePinnedLocationsForUser
// below instead - it's what reset_action: "locations" calls, which now runs
// automatically for every existing user right after the pinned list is saved.
async function buildPinnedDefaultProxyList(locations) {
	const results = await Promise.all(locations.map((cc) => testVipCountryProxy(cc)));
	return locations.map((cc, i) => ({
		proxy: (results[i] && results[i].proxy) || "",
		country: cc,
	}));
}

// Additive update for an EXISTING user: tests and appends only the pinned
// countries this user doesn't already have (matched by the `country` tag on
// each {proxy, country} slot); every slot already present - pinned or not -
// is left completely untouched (not re-tested, not removed). This is what
// makes changing the pinned_locations setting non-destructive: a country
// that was never pinned (or was added by hand) is never removed by this
// function. NOTE: un-pinning a country in settings DOES now remove it from
// every existing user - see removeCountriesFromAllUsers() and POST
// /api/settings/bulk - but that is a separate step, not part of this merge.
// Never grows a user past MAX_LOCATIONS_PER_USER. If there isn't room for
// every missing pinned country, as many as fit are added and the rest are
// returned in `cappedOut` so the caller can warn the admin (nothing is
// auto-deleted to make room - the admin removes something manually via the
// "حذف کشور از کاربران" bulk action instead).
async function mergePinnedLocationsForUser(existingProxyList, pinnedLocations) {
	const list = Array.isArray(existingProxyList) ? existingProxyList.slice() : [];
	const haveCountries = new Set(
		list
			.map((p) => (typeof p === "object" && p !== null ? p.country : null))
			.filter(Boolean)
			.map((cc) => String(cc).toUpperCase())
	);
	const missing = pinnedLocations.filter((cc) => !haveCountries.has(cc));
	const room = Math.max(0, MAX_LOCATIONS_PER_USER - list.length);
	const toAdd = missing.slice(0, room);
	const cappedOut = missing.slice(room);
	if (toAdd.length > 0) {
		const results = await Promise.all(toAdd.map((cc) => testVipCountryProxy(cc)));
		toAdd.forEach((cc, i) => {
			list.push({ proxy: (results[i] && results[i].proxy) || "", country: cc });
		});
	}
	return { list, added: toAdd, cappedOut };
}

// Re-attaches the {proxy, country} tag to slots the admin did NOT touch when the edit-user
// modal is saved. The modal only keeps the bare proxy string of each slot (populateUserFormFields
// drops the `country` tag) and posts user_socks5 back as a plain string / array of strings, so
// without this every "save" - whatever field was changed - wiped every country tag, and
// getSelectedUserProxy() (which matches /XYZ/<country-code> against slot.country) then found
// nothing and the config silently fell back to a direct/Cloudflare connection.
// Every incoming string that is identical to a tagged slot already stored for this user gets that
// slot's country back (each stored slot is consumed once, so duplicated proxy strings can't steal
// each other's tag). A slot the admin really added/changed by hand stays untagged, exactly as before.
// Objects already carrying a tag are left alone. Returns the original value when nothing matched.
function preserveProxyCountryTags(incomingRaw, existingRaw) {
	if (incomingRaw === undefined || incomingRaw === null || incomingRaw === "") return incomingRaw;
	let existingList = [];
	try {
		const es = String(existingRaw || "").trim();
		if (es.startsWith("[")) {
			const parsed = JSON.parse(es);
			if (Array.isArray(parsed)) existingList = parsed;
		}
	} catch (e) {
		return incomingRaw;
	}
	const tagPool = new Map();
	for (const slot of existingList) {
		if (typeof slot === "object" && slot !== null && slot.country && typeof slot.proxy === "string" && slot.proxy.trim()) {
			const key = slot.proxy.trim();
			if (!tagPool.has(key)) tagPool.set(key, []);
			tagPool.get(key).push(String(slot.country));
		}
	}
	if (tagPool.size === 0) return incomingRaw;
	let incomingList;
	if (Array.isArray(incomingRaw)) {
		incomingList = incomingRaw;
	} else {
		const is = String(incomingRaw).trim();
		if (is.startsWith("[")) {
			try {
				incomingList = JSON.parse(is);
			} catch (e) {
				return incomingRaw;
			}
			if (!Array.isArray(incomingList)) return incomingRaw;
		} else {
			incomingList = [is];
		}
	}
	let changed = false;
	const out = incomingList.map((item) => {
		if (typeof item !== "string") return item;
		const key = item.trim();
		const queue = tagPool.get(key);
		if (queue && queue.length > 0) {
			changed = true;
			return { proxy: key, country: queue.shift() };
		}
		return item;
	});
	return changed ? JSON.stringify(out) : incomingRaw;
}

// Removes every slot tagged with one of `countries` (ISO alpha-2) from EVERY user's
// user_socks5 list. Called from POST /api/settings/bulk when countries were just
// un-pinned (pinned_locations shrank), so an un-pinned country actually disappears
// from the users' configs instead of lingering forever. Only countries that were in
// the previous pinned list and are not in the new one are passed in - a country the
// admin never pinned (or a legacy non-object slot without a country tag) is never
// touched here. Returns { countries, usersUpdated }.
async function removeCountriesFromAllUsers(env, ctx, countries) {
	const targets = new Set((countries || []).map((c) => String(c).trim().toUpperCase()).filter(Boolean));
	if (targets.size === 0) return { countries: [], usersUpdated: 0 };
	const { results } = await env.DB.prepare("SELECT username, uuid, trojan_hash, user_socks5 FROM users WHERE user_socks5 IS NOT NULL AND user_socks5 != ''").all();
	const stmts = [];
	const changedUsers = [];
	for (const row of results || []) {
		const raw = String(row.user_socks5 || "").trim();
		if (!raw.startsWith("[")) continue;
		let list;
		try {
			list = JSON.parse(raw);
		} catch (e) {
			continue;
		}
		if (!Array.isArray(list)) continue;
		const kept = list.filter((p) => !(typeof p === "object" && p !== null && targets.has(String(p.country || "").trim().toUpperCase())));
		if (kept.length === list.length) continue;
		stmts.push(env.DB.prepare("UPDATE users SET user_socks5 = ? WHERE username = ?").bind(JSON.stringify(kept), row.username));
		changedUsers.push(row);
	}
	for (let i = 0; i < stmts.length; i += 50) {
		await env.DB.batch(stmts.slice(i, i + 50));
	}
	await Promise.all(changedUsers.map((r) => invalidateUserAuthCache(ctx, r.uuid, r.trojan_hash)));
	return { countries: Array.from(targets), usersUpdated: changedUsers.length };
}

// "Mirror" variant of removeCountriesFromAllUsers(): instead of being told WHICH countries
// to remove, it is told which to KEEP (`keepCountries` = the pinned list that was just
// saved) and strips every country-tagged slot that is not in it from EVERY user's
// user_socks5 list. Used by POST /api/settings/bulk when the caller (the mother panel's
// "Push") sends prune_unpinned_locations: true. This is what actually cleans up panels
// that already carry countries which are no longer pinned (e.g. the 15 built-in defaults
// left over from before an empty list could be saved) - the "previous vs. now" comparison
// alone can never find those. Slots WITHOUT a country tag (proxies added by hand as a raw
// string, legacy non-object slots) are never touched. Returns { countries, usersUpdated }
// where `countries` = the country codes that were really removed from at least one user.
async function removeUnpinnedCountriesFromAllUsers(env, ctx, keepCountries) {
	const keep = new Set((keepCountries || []).map((c) => String(c).trim().toUpperCase()).filter(Boolean));
	const { results } = await env.DB.prepare("SELECT username, uuid, trojan_hash, user_socks5 FROM users WHERE user_socks5 IS NOT NULL AND user_socks5 != ''").all();
	const stmts = [];
	const changedUsers = [];
	const removedCountries = new Set();
	for (const row of results || []) {
		const raw = String(row.user_socks5 || "").trim();
		if (!raw.startsWith("[")) continue;
		let list;
		try {
			list = JSON.parse(raw);
		} catch (e) {
			continue;
		}
		if (!Array.isArray(list)) continue;
		const kept = list.filter((p) => {
			if (typeof p !== "object" || p === null) return true;
			const cc = String(p.country || "").trim().toUpperCase();
			if (!cc || keep.has(cc)) return true;
			removedCountries.add(cc);
			return false;
		});
		if (kept.length === list.length) continue;
		stmts.push(env.DB.prepare("UPDATE users SET user_socks5 = ? WHERE username = ?").bind(JSON.stringify(kept), row.username));
		changedUsers.push(row);
	}
	for (let i = 0; i < stmts.length; i += 50) {
		await env.DB.batch(stmts.slice(i, i + 50));
	}
	await Promise.all(changedUsers.map((r) => invalidateUserAuthCache(ctx, r.uuid, r.trojan_hash)));
	return { countries: Array.from(removedCountries), usersUpdated: changedUsers.length };
}

async function replaceBrokenProxy(username, env, oldProxy) {
	try {
		if (GLOBAL_WRITE_LOCK.get(username + "_proxy_rotate")) return;
		GLOBAL_WRITE_LOCK.set(username + "_proxy_rotate", true);
		
		const user = await env.DB.prepare("SELECT id, uuid, user_socks5, auto_rotate_user_proxy, proxy_rotate_cooldowns FROM users WHERE username = ?").bind(username).first();
		if (!user || user.auto_rotate_user_proxy !== 1 || !user.user_socks5) {
			GLOBAL_WRITE_LOCK.delete(username + "_proxy_rotate");
			return;
		}
		
		let proxyList = [];
		let isArrayMode = false;
		try {
			if (user.user_socks5.trim().startsWith("[")) {
				proxyList = JSON.parse(user.user_socks5);
				isArrayMode = true;
			} else {
				proxyList = [user.user_socks5];
			}
		} catch (e) {
			proxyList = [user.user_socks5];
		}
		
		let matchIndex = -1;
		for (let i = 0; i < proxyList.length; i++) {
			let itemStr = typeof proxyList[i] === "object" && proxyList[i] !== null ? proxyList[i].proxy : proxyList[i];
			if (itemStr === oldProxy) {
				matchIndex = i;
				break;
			}
		}
		if (matchIndex === -1) {
			GLOBAL_WRITE_LOCK.delete(username + "_proxy_rotate");
			return;
		}
		
		let cooldowns = {};
		try {
			cooldowns = user.proxy_rotate_cooldowns ? JSON.parse(user.proxy_rotate_cooldowns) : {};
		} catch (e) {
			cooldowns = {};
		}
		const COOLDOWN_MS = 3600000; // 1h per (user, country) - avoids hammering the VIP list with repeated failed attempts
		const isOnCooldown = (cc) => {
			const last = cooldowns[cc];
			return typeof last === "number" && (Date.now() - last) < COOLDOWN_MS;
		};
		const markAttempt = async (cc) => {
			cooldowns[cc] = Date.now();
			try {
				await env.DB.prepare("UPDATE users SET proxy_rotate_cooldowns = ? WHERE id = ?").bind(JSON.stringify(cooldowns), user.id).run();
			} catch (e) { }
		};
		
		let countryCode = typeof proxyList[matchIndex] === "object" && proxyList[matchIndex] !== null && proxyList[matchIndex].country ? proxyList[matchIndex].country : "all";
		
		if (countryCode === "all" || countryCode === "UN") {
			try {
				const payload = new TextEncoder().encode("GET /json/?fields=countryCode HTTP/1.1\r\nHost: ip-api.com\r\nConnection: close\r\n\r\n");
				const s = await connectProxy(oldProxy, "ip-api.com", 80, payload);
				const reader = s.readable.getReader();
				let resStr = "";
				const dec = new TextDecoder();
				const timeoutId = setTimeout(() => {
					try { s.close(); } catch (e) { }
				}, 2000);
				try {
					while (true) {
						const res = await reader.read();
						if (res.done || !res.value) break;
						resStr += dec.decode(res.value, { stream: true });
						if (resStr.includes("countryCode")) break;
					}
				} finally {
					clearTimeout(timeoutId);
					try { s.close(); } catch (e) { }
				}
				const jsonMatch = resStr.match(/\{[^}]*"countryCode"\s*:\s*"([^"]+)"[^}]*\}/);
				if (jsonMatch && jsonMatch[1]) countryCode = jsonMatch[1];
			} catch (e) { }
			
			if (countryCode === "all" || countryCode === "UN") {
				try {
					let remain = oldProxy.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
					if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
					if (remain.startsWith("[")) remain = remain.substring(1, remain.indexOf("]"));
					else if (remain.includes(":")) remain = remain.substring(0, remain.lastIndexOf(":"));
					const geoRes = await fetch(`http://ip-api.com/json/${remain}?fields=countryCode`);
					const geoData = await geoRes.json();
					if (geoData && geoData.countryCode) countryCode = geoData.countryCode;
				} catch (e) { }
			}
		}
		
		let newProxy = null;
		let finalCountry = null;
		const upperCountry = (countryCode || "ALL").toUpperCase();
		
		// Same-country-only policy: never switch the user to a different country.
		// If we couldn't determine a specific country for this proxy, there's nothing
		// to restrict the search to, so we skip replacement entirely rather than guessing.
		if (upperCountry === "ALL" || upperCountry === "UN") {
			GLOBAL_WRITE_LOCK.delete(username + "_proxy_rotate");
			return;
		}
		
		// Per-(user, country) 1h cooldown: if we already tried this country recently
		// (success or failure), don't hammer the VIP list again until it expires.
		if (isOnCooldown(upperCountry)) {
			GLOBAL_WRITE_LOCK.delete(username + "_proxy_rotate");
			return;
		}
		await markAttempt(upperCountry);
		
		const sources = [{ url: `proxy_vip/${upperCountry}.txt`, type: "repo", country: upperCountry }];
		
		for (const src of sources) {
			try {
				const text = await getCachedRepoFile(src.url);
				if (!text) continue;
				const lines = text
					.split("\n")
					.map((l) => l.trim())
					.filter((l) => l.length > 5);
					
				if (lines.length > 0) {
					for (let i = lines.length - 1; i > 0; i--) {
						const j = Math.floor(Math.random() * (i + 1));
						[lines[i], lines[j]] = [lines[j], lines[i]];
					}
					
					const testLimit = (src.country === upperCountry) ? 15 : 3;
					
					const testBatch = lines.slice(0, testLimit).flatMap((line) => {
						if (line.match(/^(socks4|socks5|socks|http|https|tg):\/\//i) || line.includes("t.me/socks")) {
							return [line];
						}
						if (src.type === "socks5") return [`socks5://${line}`];
						if (src.type === "http") return [`http://${line}`];
						return [`socks5://${line}`, `http://${line}`];
					});
					
					try {
						newProxy = await Promise.any(
							testBatch.map((p) => {
								return new Promise(async (resolve, reject) => {
									let sock = null;
									const timeoutId = setTimeout(() => {
										try { sock && sock.close(); } catch (e) { }
										reject(new Error("timeout"));
									}, 4000); 
									try {
										const payload = TEXT_ENCODER.encode("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n");
										sock = await connectProxy(p, "1.1.1.1", 80, payload);
										const reader = sock.readable.getReader();
										const res = await reader.read();
										clearTimeout(timeoutId);
										try { sock.close(); } catch (e) { }
										if (res.done || !res.value) reject(new Error("empty"));
										else resolve(p);
									} catch (e) {
										clearTimeout(timeoutId);
										try { sock && sock.close(); } catch (err) { }
										reject(e);
									}
								});
							})
						);
					} catch (e) {
						continue;
					}
					
					if (newProxy) {
						finalCountry = src.country; 
						break;
					}
				}
			} catch (e) { }
		}
		
		if (newProxy) {
			let finalProxyVal = newProxy;
			if (isArrayMode) {
				if (typeof proxyList[matchIndex] === "object" && proxyList[matchIndex] !== null) {
					proxyList[matchIndex].proxy = newProxy;
					if (finalCountry && finalCountry !== "ALL" && finalCountry !== "UN") {
						proxyList[matchIndex].country = finalCountry;
					}
				} else {
					if (finalCountry && finalCountry !== "ALL" && finalCountry !== "UN") {
						proxyList[matchIndex] = { proxy: newProxy, country: finalCountry };
					} else {
						proxyList[matchIndex] = newProxy;
					}
				}
				finalProxyVal = JSON.stringify(proxyList);
			} else {
				if (finalCountry && finalCountry !== "ALL" && finalCountry !== "UN") {
					finalProxyVal = JSON.stringify([{ proxy: newProxy, country: finalCountry }]);
				}
			}
			await env.DB.prepare("UPDATE users SET user_socks5 = ? WHERE id = ?").bind(finalProxyVal, user.id).run();
			await invalidateUserAuthCache(null, user.uuid); // the auth cache holds this same row, incl. the now-stale user_socks5
		}
	} catch (e) {
	} finally {
		GLOBAL_WRITE_LOCK.delete(username + "_proxy_rotate");
	}
}
const __WORKER_EXPORT__ = {
	async fetch(request, env, ctx) {
		if (!env.DB) {
			return new Response("Database binding 'DB' is missing in Cloudflare Workers settings.", { status: 500 });
		}
		try {
			try {
				await DbService.ensureSchema(env.DB);
			} catch (e) { }
			trackRequest(env, ctx);
			if (schemaEnsured) {
				ctx.waitUntil(checkAutoResets(env, ctx));
				ctx.waitUntil(checkAutoRotates(env, ctx));
			}
			const url = new URL(request.url);
			if (Router.isWebSocketUpgrade(request)) {
				return await Router.handleWebSocket(request, env, ctx);
			}
			if (Router.isSubscriptionPath(url.pathname)) {
				return await Router.handleSubscription(url, env);
			}
			if (url.pathname === "/icon.svg" || url.pathname === "/favicon.ico" || url.pathname === "/icon.png" || url.pathname === "/apple-touch-icon.png") {
				return new Response(ICON_SVG, {
					headers: {
						"Content-Type": "image/svg+xml; charset=utf-8",
						"Cache-Control": "public, max-age=604800, immutable",
					},
				});
			}
			if (url.pathname === "/manifest.json") {
				// این فایل، بدون هیچ نشانه‌ای از پنل، فقط برای کاربر واردشده (کوکی سشن معتبر) سرو می‌شود؛
				// در غیر این صورت 404 برمی‌گردد تا با درخواست مستقیم این آدرس هم چیزی لو نرود.
				const manifestAuthorized = await DbService.verifyApiAuth(request, env);
				if (!manifestAuthorized) {
					return new Response("Not Found", { status: 404 });
				}
				return new Response(PWA_MANIFEST, {
					headers: {
						"Content-Type": "application/manifest+json; charset=utf-8",
						"Cache-Control": "no-store",
					},
				});
			}
			if (url.pathname === "/sw.js") {
				const swAuthorized = await DbService.verifyApiAuth(request, env);
				if (!swAuthorized) {
					return new Response("Not Found", { status: 404 });
				}
				return new Response(PWA_SERVICE_WORKER, {
					headers: {
						"Content-Type": "application/javascript; charset=utf-8",
						"Cache-Control": "no-store",
					},
				});
			}
			if (url.pathname.startsWith("/api/")) {
				return await Router.handleApi(request, url, env, ctx);
			}
			if (url.pathname === "/ppannell") {
				return await Router.handlePanel(request, env);
			}
			if (url.pathname.startsWith("/profile/")) {
				return await Router.handleUserStatus(url, env);
			}
			return new Response(HTML_TEMPLATES.nginx, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		} catch (err) {
			let msg = err.message || "";
			if (msg.toLowerCase().includes("d1") && (msg.toLowerCase().includes("limit") || msg.toLowerCase().includes("exceeded") || msg.toLowerCase().includes("daily row"))) {
				return new Response(JSON.stringify({ error: "سهمیه دیتابیس شما تمام شده و ساعت 3:30 درست میشه" }), { 
					status: 500, 
					headers: { "Content-Type": "application/json; charset=utf-8" } 
				});
			}
			return new Response("Internal Server Error", { status: 500 });
		}
	},
};
const ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <defs>
    <radialGradient id="zeusBg" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#0e2348"/>
      <stop offset="100%" stop-color="#020617"/>
    </radialGradient>
    <filter id="zeusGlow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="0" stdDeviation="16" flood-color="#3b82f6" flood-opacity="0.6"/>
    </filter>
  </defs>
  <rect width="512" height="512" rx="128" fill="#000000"/>
  <rect x="48" y="48" width="416" height="416" rx="96" fill="url(#zeusBg)" stroke="#3b82f6" stroke-width="16" filter="url(#zeusGlow)"/>
  <rect x="56" y="56" width="400" height="400" rx="88" fill="none" stroke="#60a5fa" stroke-width="4" stroke-opacity="0.4"/>
  <g transform="translate(128, 128) scale(10.666)" filter="url(#zeusGlow)">
    <path d="M13 10V3L4 14h7v7l9-11h-7z" fill="#38bdf8" fill-opacity="0.3" stroke="#60a5fa" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
  </g>
</svg>`;
const PWA_MANIFEST = JSON.stringify({
	name: "Admin Panel",
	short_name: "Admin Panel",
	description: "پنل مدیریت پیشرفته کانفیگ",
	start_url: "/ppannell",
	scope: "/",
	display: "standalone",
	background_color: "#000000",
	theme_color: "#000000",
	dir: "rtl",
	lang: "fa-IR",
	orientation: "any",
	icons: [
		{
			src: "/icon.svg",
			sizes: "192x192 512x512",
			type: "image/svg+xml",
			purpose: "any maskable"
		},
		{
			src: "data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%20512%20512%22%20width%3D%22512%22%20height%3D%22512%22%3E%0A%20%20%3Cdefs%3E%0A%20%20%20%20%3CradialGradient%20id%3D%22zeusBg%22%20cx%3D%2250%25%22%20cy%3D%2250%25%22%20r%3D%2250%25%22%3E%0A%20%20%20%20%20%20%3Cstop%20offset%3D%220%25%22%20stop-color%3D%22%230e2348%22%2F%3E%0A%20%20%20%20%20%20%3Cstop%20offset%3D%22100%25%22%20stop-color%3D%22%23020617%22%2F%3E%0A%20%20%20%20%3C%2FradialGradient%3E%0A%20%20%20%20%3Cfilter%20id%3D%22zeusGlow%22%20x%3D%22-20%25%22%20y%3D%22-20%25%22%20width%3D%22140%25%22%20height%3D%22140%25%22%3E%0A%20%20%20%20%20%20%3CfeDropShadow%20dx%3D%220%22%20dy%3D%220%22%20stdDeviation%3D%2216%22%20flood-color%3D%22%233b82f6%22%20flood-opacity%3D%220.6%22%2F%3E%0A%20%20%20%20%3C%2Ffilter%3E%0A%20%20%3C%2Fdefs%3E%0A%20%20%3Crect%20width%3D%22512%22%20height%3D%22512%22%20rx%3D%22128%22%20fill%3D%22%23000000%22%2F%3E%0A%20%20%3Crect%20x%3D%2248%22%20y%3D%2248%22%20width%3D%22416%22%20height%3D%22416%22%20rx%3D%2296%22%20fill%3D%22url(%23zeusBg)%22%20stroke%3D%22%233b82f6%22%20stroke-width%3D%2216%22%20filter%3D%22url(%23zeusGlow)%22%2F%3E%0A%20%20%3Crect%20x%3D%2256%22%20y%3D%2256%22%20width%3D%22400%22%20height%3D%22400%22%20rx%3D%2288%22%20fill%3D%22none%22%20stroke%3D%22%2360a5fa%22%20stroke-width%3D%224%22%20stroke-opacity%3D%220.4%22%2F%3E%0A%20%20%3Cg%20transform%3D%22translate(128%2C%20128)%20scale(10.666)%22%20filter%3D%22url(%23zeusGlow)%22%3E%0A%20%20%20%20%3Cpath%20d%3D%22M13%2010V3L4%2014h7v7l9-11h-7z%22%20fill%3D%22%2338bdf8%22%20fill-opacity%3D%220.3%22%20stroke%3D%22%2360a5fa%22%20stroke-width%3D%221.6%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%2F%3E%0A%20%20%3C%2Fg%3E%0A%3C%2Fsvg%3E",
			sizes: "192x192 512x512",
			type: "image/svg+xml",
			purpose: "any maskable"
		}
	],
	categories: ["utilities", "productivity"]
});
const PWA_SERVICE_WORKER = `
const CACHE_NAME = "zeus-pwa-cache-v1";
const STATIC_ASSETS = [
	"https://cdn.tailwindcss.com",
	"https://cdn.jsdelivr.net/npm/sortablejs@1.15.2/Sortable.min.js",
	"https://cdn.jsdelivr.net/npm/qr-code-styling@1.5.0/lib/qr-code-styling.js",
	"https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css",
	"https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.3.2/css/flag-icons.min.css"
];
self.addEventListener("install", (e) => {
	self.skipWaiting();
	e.waitUntil(
		caches.open(CACHE_NAME).then((cache) => {
			return cache.addAll(STATIC_ASSETS).catch(() => {});
		})
	);
});
self.addEventListener("activate", (e) => {
	e.waitUntil(
		caches.keys().then((keys) => {
			return Promise.all(
				keys.map((k) => {
					if (k !== CACHE_NAME) return caches.delete(k);
				})
			);
		}).then(() => self.clients.claim())
	);
});
self.addEventListener("fetch", (e) => {
	const url = new URL(e.request.url);
	if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/notes/") || url.pathname.startsWith("/bundle/") || url.pathname.startsWith("/profile/") || url.pathname.startsWith("/stream/")) {
		return;
	}
	if (STATIC_ASSETS.includes(e.request.url)) {
		e.respondWith(
			caches.match(e.request).then((cached) => cached || fetch(e.request).then((res) => {
				const clone = res.clone();
				caches.open(CACHE_NAME).then((cache) => cache.put(e.request, clone));
				return res;
			}))
		);
	}
});
`;
const Router = {
	isWebSocketUpgrade(request) {
	const upgradeHeader = (request.headers.get("Upgrade") || "").toLowerCase();
	return upgradeHeader === "websocket";
	},
	isSubscriptionPath(pathname) {
		return pathname.startsWith("/notes/") || pathname.startsWith("/bundle/");
	},
	async handleWebSocket(request, env, ctx) {
		try {
			return handlevIees(env, null, ctx, request);
		} catch (e) {
			return new Response("Internal Server Error", { status: 500 });
		}
	},
	async handleSubscription(url, env) {
		const isSingbox = url.pathname.startsWith("/bundle/");
		const offset = isSingbox ? 8 : 7;
		let subUser = safeDecodeURI(url.pathname.slice(offset));
		const host = url.hostname;
		try {
			const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE OR uuid = ?").bind(subUser, subUser).first();
			if (!user) {
				return new Response("Not Found", { status: 404 });
			}
			try {
				USER_REQ_CACHE.set(user.username, (USER_REQ_CACHE.get(user.username) || 0) + 1);
			} catch (e) { }
			if (isSingbox) {
				return await SubscriptionService.generateSingbox(user, host, env);
			}
			return await SubscriptionService.generateText(user, host, env);
		} catch (err) {
			return new Response("Error building config: " + err.message, { status: 500 });
		}
	},
	async handlePanel(request, env) {
		const hasPassword = await DbService.getPanelPassword(env.DB);
		if (!hasPassword) {
			return new Response(HTML_TEMPLATES.setup, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		}
		const authorized = await DbService.verifyApiAuth(request, env);
		if (!authorized) {
			return new Response(HTML_TEMPLATES.login, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		}
		return new Response(HTML_TEMPLATES.panel, {
			headers: {
				"Content-Type": "text/html; charset=utf-8",
				"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
				Pragma: "no-cache",
				Expires: "0",
			},
		});
	},
	async handleUserStatus(url, env) {
		const username = safeDecodeURI(url.pathname.slice(9));
		if (!username) {
			return new Response("Username is required", { status: 400 });
		}
		try {
			const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE OR uuid = ?").bind(username, username).first();
			if (!user) {
				return new Response("User not found", { status: 404 });
			}
			const subResponse = await SubscriptionService.generateText(user, url.hostname, env);
			const subBase64 = await subResponse.text();
			let plainLinks = "";
			try {
				plainLinks = decodeURIComponent(escape(atob(subBase64)));
			} catch (e) {
				plainLinks = atob(subBase64);
			}
			if (user.auto_rotate_ip === 1) {
				const cachedIpsData = await getCachedIps();
				const randomIps = getRandomIps(cachedIpsData, user.ip_operator || "all", user.ip_count || 999999);
				if (randomIps.length > 0) user.ips = randomIps.join("\n");
			}
			const statusPageIpSettings = await getSubscriptionIpSettings(env);
			const inlineProxyIpForStatusPage = statusPageIpSettings.inlineProxyIp;
			const otherCleanIpsForStatusPage = statusPageIpSettings.otherCleanIps;
			const userJson = JSON.stringify({
				username: user.username,
				uuid: user.uuid,
				limit_gb: user.limit_gb,
				expiry_days: user.expiry_days,
				used_gb: (user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024)),
				limit_req: user.limit_req,
				used_req: (user.used_req || 0) + (USER_REQ_CACHE.get(user.username) || 0),
				is_active: user.is_active,
				online_count: getActiveIpCount(user.active_ips),
				ip_limit: user.ip_limit,
				created_at: user.created_at,
				tls: user.tls,
				port: user.port,
				ips: user.ips,
				fingerprint: user.fingerprint || "chrome",
				connection_type: user.connection_type || "vless",
				user_proxy_iata: user.user_proxy_iata,
				user_socks5: user.user_socks5,
				user_proxy_ip: user.user_proxy_ip,
				start_on_first_connect: user.start_on_first_connect,
				first_connection_time: user.first_connection_time,
				enable_direct: user.enable_direct !== 0 ? 1 : 0,
				early_data_enabled: Number(user.early_data_enabled) === 1 ? 1 : 0,
				early_data_size: user.early_data_size,
			});
			const html = HTML_TEMPLATES.status.replace("/* {{USER_DATA_PLACEHOLDER}} */", `window.statusUser = ${userJson}; window.INLINE_PROXY_IP = ${JSON.stringify(inlineProxyIpForStatusPage)}; window.OTHER_CLEAN_IPS = ${JSON.stringify(otherCleanIpsForStatusPage)};`);
			const finalHtml = html + "\n<!-- HIDDEN_CONFIGS -->\n<div style='display:none; white-space:pre-wrap;'>\n" + plainLinks + "\n</div>";
			try {
				const ua = (request.headers.get("User-Agent") || "").toLowerCase();
				if (!ua.includes("mozilla") && !ua.includes("chrome") && !ua.includes("safari")) {
					USER_REQ_CACHE.set(user.username, (USER_REQ_CACHE.get(user.username) || 0) + 1);
				}
			} catch (e) { }
			return new Response(finalHtml, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		} catch (err) {
			return new Response("Error: " + err.message, { status: 500 });
		}
	},
	async handleApi(request, url, env, ctx) {
		const hasPassword = await DbService.getPanelPassword(env.DB);
		if (url.pathname === "/api/setup-password" && request.method === "POST") {
			if (hasPassword) {
				return new Response(JSON.stringify({ error: "رمز عبور از قبل تعریف شده است" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const { password } = await readJsonBody(request);
			const cleanPassword = (password || "").trim();
			if (!cleanPassword || cleanPassword.length < 4) {
				return new Response(JSON.stringify({ error: "رمز عبور باید حداقل ۴ کاراکتر باشد" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const hashed = await DbService.sha256(cleanPassword);
			await DbService.setPanelPassword(env.DB, hashed);
			LOGIN_ATTEMPTS.clear();
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=" + hashed + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
				},
			});
		}
		if (url.pathname === "/api/login" && request.method === "POST") {
			const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
			const now = Date.now();
			if (LOGIN_ATTEMPTS.size > 256) {
				for (const [ip, rec] of LOGIN_ATTEMPTS) {
					if (now - rec.lastAttempt > 900000) LOGIN_ATTEMPTS.delete(ip);
				}
			}
			const attemptRecord = LOGIN_ATTEMPTS.get(clientIP) || { count: 0, lastAttempt: 0 };
			if (attemptRecord.count >= 15 && now - attemptRecord.lastAttempt < 900000) {
				const remaining = Math.ceil((900000 - (now - attemptRecord.lastAttempt)) / 60000);
				return new Response(JSON.stringify({ error: `دسترسی شما مسدود شد. لطفاً ${remaining} دقیقه دیگر تلاش کنید.` }), {
					status: 429,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const { password } = await readJsonBody(request);
			const cleanPassword = (password || "").trim();
			const hashedInput = await DbService.sha256(cleanPassword);
			const storedHash = await DbService.getPanelPassword(env.DB, true);
			let isValid = false;
			if (storedHash === hashedInput) {
				isValid = true;
			} else {
				const oldHashedInput = await DbService.oldSha256(cleanPassword);
				if (storedHash === oldHashedInput) {
					isValid = true;
					await DbService.setPanelPassword(env.DB, hashedInput);
				}
			}
			if (isValid) {
				LOGIN_ATTEMPTS.delete(clientIP);
				return new Response(JSON.stringify({ success: true }), {
					headers: {
						"Content-Type": "application/json; charset=utf-8",
						"Set-Cookie": "panel_session=" + hashedInput + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
					},
				});
			} else {
				attemptRecord.count = now - attemptRecord.lastAttempt > 900000 ? 1 : attemptRecord.count + 1;
				attemptRecord.lastAttempt = now;
				LOGIN_ATTEMPTS.set(clientIP, attemptRecord);
				return new Response(JSON.stringify({ error: `رمز عبور اشتباه است (تلاش‌های باقی‌مانده: ${15 - attemptRecord.count})` }), {
					status: 401,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
		}
		if (url.pathname === "/api/logout" && request.method === "POST") {
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax",
				},
			});
		}
		if (url.pathname === "/api/recover" && request.method === "POST") {
			const { api_token } = await readJsonBody(request);
			if (!api_token) {
				return new Response(JSON.stringify({ error: "Token is required" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			try {
				const cfRes = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
					headers: { Authorization: "Bearer " + api_token },
				});
				const cfData = await cfRes.json();
				if (!cfRes.ok || !cfData.success) {
					return new Response(JSON.stringify({ error: "Invalid or expired Cloudflare token" }), {
						status: 401,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
				const host = url.hostname;
				let isAuthorized = false;
				if (host.endsWith(".workers.dev")) {
					const parts = host.split(".");
					const targetSubdomain = parts[parts.length - 3];
					const accountsRes = await fetch("https://api.cloudflare.com/client/v4/accounts", {
						headers: { Authorization: "Bearer " + api_token },
					});
					const accountsData = await accountsRes.json();
					if (accountsData.success && accountsData.result) {
						for (const acc of accountsData.result) {
							const subRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${acc.id}/workers/subdomain`, {
								headers: { Authorization: "Bearer " + api_token },
							});
							const subData = await subRes.json();
							if (subData.success && subData.result && subData.result.subdomain === targetSubdomain) {
								isAuthorized = true;
								break;
							}
						}
					}
				} else {
					const zonesRes = await fetch("https://api.cloudflare.com/client/v4/zones", {
						headers: { Authorization: "Bearer " + api_token },
					});
					const zonesData = await zonesRes.json();
					if (zonesData.success && zonesData.result) {
						for (const zone of zonesData.result) {
							if (host === zone.name || host.endsWith("." + zone.name)) {
								isAuthorized = true;
								break;
							}
						}
					}
				}
				if (!isAuthorized) {
					return new Response(JSON.stringify({ error: "این توکن متعلق به صاحب پـنـل نیست (ای کــثـــکـــش)" }), {
						status: 403,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
				await env.DB.prepare("DELETE FROM settings WHERE key = 'panel_password'").run();
				cachedPanelPassword = null;
				LOGIN_ATTEMPTS.clear();
				return new Response(JSON.stringify({ success: true }), {
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			} catch (err) {
				return new Response(JSON.stringify({ error: "Cloudflare API connection error" }), {
					status: 500,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
		}
		const authorized = await DbService.verifyApiAuth(request, env);
		if (!authorized && url.pathname !== "/api/test-proxy") {
			return new Response(JSON.stringify({ error: "Unauthorized" }), {
				status: 401,
				headers: { "Content-Type": "application/json; charset=utf-8" },
			});
		}
		if (url.pathname === "/api/auto-update-setup" && request.method === "POST") {
			const body = await readJsonBody(request);
			if (body.action === "check") {
				const dbTokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_token'").first();
				const hasToken = !!env.CF_API_TOKEN || !!(dbTokenRow && dbTokenRow.value);
				const autoUpdateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'auto_update'").first();
				const isAutoUpdateEnabled = autoUpdateRow ? autoUpdateRow.value === "1" : true;
				return new Response(JSON.stringify({ has_token: hasToken, auto_update: isAutoUpdateEnabled }), { headers: { "Content-Type": "application/json" } });
			}
			if (body.action === "enable") {
				const dbTokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_token'").first();
				let token = body.token || env.CF_API_TOKEN || (dbTokenRow ? dbTokenRow.value : null);
				if (!token) return new Response(JSON.stringify({ error: "TOKEN_MISSING" }), { status: 400, headers: { "Content-Type": "application/json" } });
				try {
					const cfRes = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
						headers: { Authorization: "Bearer " + token },
					});
					const cfData = await cfRes.json();
					if (!cfRes.ok || !cfData.success) {
						return new Response(JSON.stringify({ error: "INVALID_TOKEN" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('cf_token', ?)").bind(token).run();
					await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('auto_update', '1')").run();
					return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
				} catch (e) {
					return new Response(JSON.stringify({ error: "خطا در بررسی توکن با کلودفلر" }), { status: 500, headers: { "Content-Type": "application/json" } });
				}
			}
			if (body.action === "disable") {
				await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('auto_update', '0')").run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/restart-core" && request.method === "POST") {
			try {
				GLOBAL_TRAFFIC_CACHE.clear();
				ACTIVE_CONNECTIONS_COUNT.clear();
				GLOBAL_LAST_ACTIVE_WRITE.clear();
				GLOBAL_LAST_DB_WRITE.clear();
				GLOBAL_WRITE_LOCK.clear();
				DNS_CACHE.clear();
				USER_REQ_CACHE.clear();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/update-panel" && request.method === "POST") {
			const body = await request.json().catch(() => ({}));
			const dbTokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_token'").first();
			let currentToken = env.CF_API_TOKEN || (dbTokenRow ? dbTokenRow.value : null) || body.cf_token || null;
			let currentAccountId = env.CF_ACCOUNT_ID;
			if (!currentToken) {
				return new Response(JSON.stringify({ error: "TOKEN_REQUIRED" }), { status: 400, headers: { "Content-Type": "application/json" } });
			}
			try {
				const cfHeaders = {
					Authorization: "Bearer " + currentToken,
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ZeusPanel/1.0",
				};
				if (!currentAccountId) {
					const accRes = await fetch("https://api.cloudflare.com/client/v4/accounts", { headers: cfHeaders });
					if (!accRes.ok) throw new Error("کلودفلر درخواست اکانت را رد کرد (وضعیت: " + accRes.status + ")");
					const accData = await accRes.json().catch(() => ({}));
					if (!accData.success || !accData.result || accData.result.length === 0) throw new Error("توکن نامعتبر است یا اکانتی یافت نشد.");
					currentAccountId = accData.result[0].id;
				}
				const githubRes = await fetchWithFallback("zeus.obfuscated.js?t=" + Date.now(), {
					headers: {
						"User-Agent": "Mozilla/5.0",
						"Cache-Control": "no-cache",
					},
				});
				if (!githubRes.ok) throw new Error("خطا در دریافت سورس جدید از گیت‌هاب (وضعیت: " + githubRes.status + ")");
				const newCode = await githubRes.text();
				assertDeployableWorkerModule(newCode, "zeus.obfuscated.js");
				const scriptName = env.WORKER_NAME || url.hostname.split(".")[0];
				const bindingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}/bindings`, {
					headers: cfHeaders,
				});
				if (!bindingsRes.ok) {
					const bindingsErr = await bindingsRes.json().catch(() => ({}));
					const bindingsErrMsg = bindingsErr && bindingsErr.errors && bindingsErr.errors[0] ? bindingsErr.errors[0].message : "";
					throw new Error("عدم دسترسی به تنظیمات ورکر «" + scriptName + "». کلودفلر خطا داد (وضعیت: " + bindingsRes.status + ")" + (bindingsErrMsg ? ": " + bindingsErrMsg : ""));
				}
				const bindingsData = await bindingsRes.json().catch(() => ({}));
				if (!bindingsData.success) throw new Error("توکن فاقد دسترسی ویرایش ورکر است.");
				const newBindings = [];
				for (const b of bindingsData.result || []) {
					if (b.name === "CF_API_TOKEN" || b.name === "CF_ACCOUNT_ID") continue;
					if (b.type === "d1") {
						newBindings.push({ type: "d1", name: b.name, id: b.database_id || b.id });
					} else if (b.type === "kv_namespace") {
						newBindings.push({ type: "kv_namespace", name: b.name, namespace_id: b.namespace_id || b.id });
					} else if (b.type === "plain_text") {
						newBindings.push({ type: "plain_text", name: b.name, text: b.text || "" });
					} else if (b.type !== "secret_text") {
						newBindings.push(b);
					}
				}
				newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
				newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });
				const metadata = {
					main_module: "zeus.js",
					compatibility_date: "2026-07-10",
					compatibility_flags: ["nodejs_compat"],
					bindings: newBindings,
				};
				const formData = new FormData();
				formData.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }), "metadata.json");
				formData.append("zeus.js", new Blob([newCode], { type: "application/javascript+module" }), "zeus.js");
				const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}`, {
					method: "PUT",
					headers: cfHeaders,
					body: formData,
				});
				if (!deployRes.ok) {
					const errText = await deployRes.text().catch(() => "");
					throw new Error("خطای کلودفلر هنگام دیپلوی (" + deployRes.status + "): " + errText.substring(0, 150));
				}
				const deployData = await deployRes.json().catch(() => ({}));
				if (!deployData.success) {
					const cfError = deployData.errors && deployData.errors.length > 0 ? deployData.errors[0].message : "خطا در اعمال آپدیت.";
					throw new Error(cfError);
				}
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				return new Response(JSON.stringify({ error: err.message }), { status: 400, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/update-panel-github" && request.method === "POST") {
			// آپدیت مستقیم از روی سورس شخصی کاربر در گیت‌هاب (به‌جای مخزن رسمی زئوس)
			// دقیقاً همان مکانیزم /api/update-panel: خواندن توکن/اکانت، حفظ بایندینگ‌های فعلی، دیپلوی روی کلودفلر
			const body = await request.json().catch(() => ({}));
			const dbTokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_token'").first();
			let currentToken = env.CF_API_TOKEN || (dbTokenRow ? dbTokenRow.value : null) || body.cf_token || null;
			let currentAccountId = env.CF_ACCOUNT_ID;
			if (!currentToken) {
				return new Response(JSON.stringify({ error: "TOKEN_REQUIRED" }), { status: 400, headers: { "Content-Type": "application/json" } });
			}
			try {
				const cfHeaders = {
					Authorization: "Bearer " + currentToken,
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ZeusPanel/1.0",
				};
				if (!currentAccountId) {
					const accRes = await fetch("https://api.cloudflare.com/client/v4/accounts", { headers: cfHeaders });
					if (!accRes.ok) throw new Error("کلودفلر درخواست اکانت را رد کرد (وضعیت: " + accRes.status + ")");
					const accData = await accRes.json().catch(() => ({}));
					if (!accData.success || !accData.result || accData.result.length === 0) throw new Error("توکن نامعتبر است یا اکانتی یافت نشد.");
					currentAccountId = accData.result[0].id;
				}
				const githubUrl = "https://raw.githubusercontent.com/hmditts/XYD-Panel/refs/heads/main/worker.js?t=" + Date.now();
				const githubRes = await fetch(githubUrl, {
					headers: {
						"User-Agent": "Mozilla/5.0",
						"Cache-Control": "no-cache",
					},
				});
				if (!githubRes.ok) throw new Error("خطا در دریافت سورس جدید از گیت‌هاب (وضعیت: " + githubRes.status + ")");
				const newCode = await githubRes.text();
				if (!newCode || newCode.trim().length < 100) throw new Error("فایل دریافتی از گیت‌هاب خالی یا نامعتبر است.");
				assertDeployableWorkerModule(newCode, "worker.js");
				const scriptName = env.WORKER_NAME || url.hostname.split(".")[0];
				const bindingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}/bindings`, {
					headers: cfHeaders,
				});
				if (!bindingsRes.ok) {
					const bindingsErr = await bindingsRes.json().catch(() => ({}));
					const bindingsErrMsg = bindingsErr && bindingsErr.errors && bindingsErr.errors[0] ? bindingsErr.errors[0].message : "";
					throw new Error("عدم دسترسی به تنظیمات ورکر «" + scriptName + "». کلودفلر خطا داد (وضعیت: " + bindingsRes.status + ")" + (bindingsErrMsg ? ": " + bindingsErrMsg : ""));
				}
				const bindingsData = await bindingsRes.json().catch(() => ({}));
				if (!bindingsData.success) throw new Error("توکن فاقد دسترسی ویرایش ورکر است.");
				const newBindings = [];
				for (const b of bindingsData.result || []) {
					if (b.name === "CF_API_TOKEN" || b.name === "CF_ACCOUNT_ID") continue;
					if (b.type === "d1") {
						newBindings.push({ type: "d1", name: b.name, id: b.database_id || b.id });
					} else if (b.type === "kv_namespace") {
						newBindings.push({ type: "kv_namespace", name: b.name, namespace_id: b.namespace_id || b.id });
					} else if (b.type === "plain_text") {
						newBindings.push({ type: "plain_text", name: b.name, text: b.text || "" });
					} else if (b.type !== "secret_text") {
						newBindings.push(b);
					}
				}
				newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
				newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });
				const metadata = {
					main_module: "zeus.js",
					compatibility_date: "2026-07-10",
					compatibility_flags: ["nodejs_compat"],
					bindings: newBindings,
				};
				const formData = new FormData();
				formData.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }), "metadata.json");
				formData.append("zeus.js", new Blob([newCode], { type: "application/javascript+module" }), "zeus.js");
				const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}`, {
					method: "PUT",
					headers: cfHeaders,
					body: formData,
				});
				if (!deployRes.ok) {
					const errText = await deployRes.text().catch(() => "");
					throw new Error("خطای کلودفلر هنگام دیپلوی (" + deployRes.status + "): " + errText.substring(0, 150));
				}
				const deployData = await deployRes.json().catch(() => ({}));
				if (!deployData.success) {
					const cfError = deployData.errors && deployData.errors.length > 0 ? deployData.errors[0].message : "خطا در اعمال آپدیت.";
					throw new Error(cfError);
				}
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				return new Response(JSON.stringify({ error: err.message }), { status: 400, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/change-password" && request.method === "POST") {
			const { current_password, new_password, password } = await readJsonBody(request);
			// Master-key call (mother panel): the gate above already validated X-Master-Key against
			// settings.master_api_key (verifyApiAuth uses ONLY the header when it is present), so the
			// current password is not required. The mother sends the new password as `password`;
			// the panel's own UI keeps sending current_password + new_password, unchanged.
			const viaMasterKey = !!request.headers.get("X-Master-Key");
			const cleanCurrent = (current_password || "").trim();
			const cleanNew = (new_password || password || "").trim();
			if (!cleanNew || (!viaMasterKey && !cleanCurrent)) {
				return new Response(JSON.stringify({ error: viaMasterKey ? "رمز عبور جدید الزامی است" : "رمز عبور فعلی و جدید الزامی هستند" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			if (!viaMasterKey) {
				const currentHash = await DbService.sha256(cleanCurrent);
				const oldCurrentHash = await DbService.oldSha256(cleanCurrent);
				const storedHash = await DbService.getPanelPassword(env.DB, true);
				if (storedHash && storedHash !== currentHash && storedHash !== oldCurrentHash) {
					return new Response(JSON.stringify({ error: "رمز عبور فعلی اشتباه است" }), {
						status: 401,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
			}
			if (cleanNew.length < 4) {
				return new Response(JSON.stringify({ error: "رمز عبور جدید باید حداقل ۴ کاراکتر باشد" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const newHash = await DbService.sha256(cleanNew);
			await DbService.setPanelPassword(env.DB, newHash);
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=" + newHash + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
				},
			});
		}
		if (url.pathname === "/api/settings/bulk") {
			if (request.method === "GET") {
				try {
					const { results } = await env.DB.prepare("SELECT * FROM settings").all();
					const settingsObj = {};
					if (results) {
						results.forEach((r) => {
							if (r.key !== "cf_token" && r.key !== "panel_password" && r.key !== "master_api_key") settingsObj[r.key] = r.value;
						});
					}
					return new Response(JSON.stringify(settingsObj), { headers: { "Content-Type": "application/json" } });
				} catch (e) {
					return new Response(JSON.stringify({}), { headers: { "Content-Type": "application/json" } });
				}
			}
			if (request.method === "POST") {
				const body = await readJsonBody(request);
				let unpinRemoval = { countries: [], usersUpdated: 0 };
				let fragApplied = false;
				let earlyDataApplied = false;
				let userLimitApplied = false;
				let fingerprintApplied = false;
				let connTypeApplied = false;
				let cleanIpApplied = false;
				let portApplied = false;
				if (body.settings && typeof body.settings === "object") {
					// «محدودیت کاربر» (user_limit): برخلاف بقیه‌ی تنظیمات global، این یکی روی ستون
					// ip_limit/max_connections همه‌ی کاربرهای *موجود* هم override می‌شه (نه فقط پیش‌فرض
					// کاربر تازه‌ساز - نگاه کنید به POST /api/users). هم «ذخیره‌ی تنظیمات» همین پنل و
					// هم «Push to Panels» پنل مادر از همین مسیر می‌رن. (تنظیم «هشدار تعداد دستگاه» -
					// device_warning_threshold - فقط ذخیره می‌شه و آستانه‌ی هشدار رو تعیین می‌کنه؛
					// دیگه روی ip_limit/max_connections کاربرها اثری نداره.)
					let overrideUserLimit = undefined;
					if (Object.prototype.hasOwnProperty.call(body.settings, "user_limit")) {
						const parsedUserLimit = parseInt(body.settings.user_limit);
						if (!isNaN(parsedUserLimit) && parsedUserLimit >= 0) overrideUserLimit = parsedUserLimit;
					}
					// «پورت»: مثل بالا، این یکی هم - برخلاف بقیه‌ی تنظیمات global - روی ستون
					// port همه‌ی کاربرهای *موجود* بازنویسی کامل می‌شه (نه فقط پیش‌فرض کاربر
					// تازه‌ساز؛ نگاه کنید به getDefaultPortSetting() برای اون بخش). پورت(های)
					// قبلی هر کاربر پاک و با همین یکی جایگزین می‌شه. مثل user_limit/global_clean_ip
					// بالا و پایین، موفقیتش با port_applied: true توی جواب گزارش می‌شه تا پنل
					// مادر هم بتونه پنل‌های آپدیت‌نشده رو (که این کلید رو نادیده می‌گیرن) تشخیص بده.
					let overrideDefaultPort = undefined;
					if (Object.prototype.hasOwnProperty.call(body.settings, "default_port")) {
						const parsedPort = parseInt(body.settings.default_port);
						if (!isNaN(parsedPort) && parsedPort > 0 && parsedPort <= 65535) overrideDefaultPort = String(parsedPort);
					}
					// «آی‌پی تمیز سراسری» (global_clean_ip): مثل «پورت» و «محدودیت کاربر» بالا -
					// برخلاف بقیه‌ی تنظیمات global - این یکی هم روی ستون ips همه‌ی کاربرهای
					// *موجود* بازنویسی کامل می‌شود (نه فقط پیش‌فرض کاربر تازه‌ساز؛ نگاه کنید به
					// POST /api/users که nud.global_clean_ip را فقط وقتی می‌خواند که خودِ کاربر
					// در لحظه‌ی ساخت مقدار ips جدا نداشته باشد). قبل از این تغییر این کلید فقط
					// در جدول settings ذخیره می‌شد و هیچ‌وقت به کارت‌های موجود نمی‌رسید — همین
					// نبود override باعث می‌شد تغییر «Global Clean IP» در پنل مادر روی کارت
					// کاربرهایی که از قبل ساخته شده بودند اثر نکند.
					let overrideGlobalCleanIp = undefined;
					if (Object.prototype.hasOwnProperty.call(body.settings, "global_clean_ip")) {
						const cleanIpVal = String(body.settings.global_clean_ip == null ? "" : body.settings.global_clean_ip).trim();
						if (cleanIpVal) overrideGlobalCleanIp = cleanIpVal;
					}
					// «فرگمنت» (new_user_frag_len / new_user_frag_int): کلیدهای new_user_* فقط
					// پیش‌فرضِ کاربر *تازه‌ساز*ند. لینک‌ها از ستون‌های frag_len/frag_int خودِ هر
					// کاربر ساخته می‌شوند (SubscriptionService.generateText)، نه از settings؛ پس
					// ذخیره‌ی این دو کلید به‌تنهایی روی کانفیگ کاربرهای موجود هیچ اثری ندارد.
					// فقط وقتی فراخواننده (Push پنل مادر) صریحاً apply_frag_to_existing_users: true
					// بفرستد (فلگ بیرون از body.settings، مثل prune_unpinned_locations)، همین دو
					// مقدار روی ستون frag_len/frag_int همه‌ی کاربرهای *موجود* هم نوشته می‌شود؛
					// مقدار خالی = فرگمنتیشن خاموش. «ذخیره‌ی تنظیمات» خودِ همین پنل این فلگ را
					// نمی‌فرستد، پس فقط برای کاربر بعدی اثر دارد. هر دو کلید باید در درخواست باشند.
					let overrideFrag = undefined;
					if (
						body.apply_frag_to_existing_users === true &&
						Object.prototype.hasOwnProperty.call(body.settings, "new_user_frag_len") &&
						Object.prototype.hasOwnProperty.call(body.settings, "new_user_frag_int")
					) {
						overrideFrag = {
							len: String(body.settings.new_user_frag_len == null ? "" : body.settings.new_user_frag_len).trim(),
							int: String(body.settings.new_user_frag_int == null ? "" : body.settings.new_user_frag_int).trim(),
						};
					}
					// «فینگرپرینت» (new_user_fingerprint) و «پروتکل» (new_user_connection_type): مثل فرگمنت،
					// این دو کلید هم فقط پیش‌فرضِ کاربر *تازه‌ساز*ند؛ لینک‌ها از ستون‌های fingerprint/
					// connection_type خودِ هر کاربر ساخته می‌شوند (SubscriptionService.generateText و
					// چک پروتکل هنگام اتصال)، نه از settings؛ پس ذخیره‌ی کلید به‌تنهایی روی کانفیگ
					// کاربرهای موجود اثری نداشت. فقط وقتی فراخواننده (Push پنل مادر) صریحاً
					// apply_fingerprint_to_existing_users / apply_connection_type_to_existing_users: true
					// بفرستد (فلگ بیرون از body.settings، مثل apply_frag_to_existing_users)، مقدار روی
					// ستون همه‌ی کاربرهای *موجود* هم نوشته می‌شود. «ذخیره‌ی تنظیمات» خودِ همین پنل این
					// فلگ‌ها را نمی‌فرستد، پس فقط برای کاربر بعدی اثر دارد. مقدار نامعتبر = نادیده گرفته
					// می‌شود (و چون *_applied برنمی‌گردد، مادر آن را به‌عنوان خطا گزارش می‌کند).
					let overrideFingerprint = undefined;
					if (body.apply_fingerprint_to_existing_users === true && Object.prototype.hasOwnProperty.call(body.settings, "new_user_fingerprint")) {
						const fpVal = String(body.settings.new_user_fingerprint == null ? "" : body.settings.new_user_fingerprint).trim();
						if (NEW_USER_FINGERPRINTS.includes(fpVal)) overrideFingerprint = fpVal;
					}
					let overrideConnType = undefined;
					if (body.apply_connection_type_to_existing_users === true && Object.prototype.hasOwnProperty.call(body.settings, "new_user_connection_type")) {
						const ctParts = String(body.settings.new_user_connection_type == null ? "" : body.settings.new_user_connection_type)
							.split(",")
							.map((x) => x.trim().toLowerCase());
						const ctFinal = ["vless", "trojan"].filter((x) => ctParts.includes(x));
						if (ctFinal.length > 0) overrideConnType = ctFinal.join(",");
					}
					// «Early Data» (new_user_early_data_enabled / new_user_early_data_size): مثل فرگمنت،
					// این دو کلید هم فقط پیش‌فرضِ کاربر *تازه‌ساز*ند؛ لینک‌ها از ستون‌های
					// early_data_enabled/early_data_size خودِ هر کاربر ساخته می‌شوند، نه از settings. فقط وقتی
					// فراخواننده صریحاً apply_early_data_to_existing_users: true بفرستد (فلگ بیرون از
					// body.settings، مثل apply_frag_to_existing_users) هر دو مقدار روی ستون‌های همه‌ی کاربرهای
					// *موجود* هم نوشته می‌شود. «ذخیره‌ی تنظیمات» همین پنل این فلگ را فقط وقتی می‌فرستد که
					// چک‌باکس «اعمال روی کاربرهای موجود» تیک خورده باشد. هر دو کلید باید در درخواست باشند؛
					// enabled فقط "0"/"1" و size فقط عدد صحیح 1..EARLY_DATA_MAX_SIZE؛ مقدار نامعتبر = نادیده
					// گرفته می‌شود (و چون early_data_applied برنمی‌گردد، فراخواننده آن را به‌عنوان خطا می‌بیند).
					let overrideEarlyData = undefined;
					if (
						body.apply_early_data_to_existing_users === true &&
						Object.prototype.hasOwnProperty.call(body.settings, "new_user_early_data_enabled") &&
						Object.prototype.hasOwnProperty.call(body.settings, "new_user_early_data_size")
					) {
						const edEnabledRaw = String(body.settings.new_user_early_data_enabled == null ? "" : body.settings.new_user_early_data_enabled).trim();
						const edSizeRaw = String(body.settings.new_user_early_data_size == null ? "" : body.settings.new_user_early_data_size).trim();
						const edSize = /^[0-9]+$/.test(edSizeRaw) ? parseInt(edSizeRaw, 10) : NaN;
						if ((edEnabledRaw === "0" || edEnabledRaw === "1") && edSize >= 1 && edSize <= EARLY_DATA_MAX_SIZE) {
							overrideEarlyData = { enabled: edEnabledRaw === "1" ? 1 : 0, size: edSize };
						}
					}
					// همه‌ی کلیدها در یک db.batch() (یک رفت‌وبرگشت D1 به‌جای یکی به ازای هر کلید).
					// «ذخیره‌ی تنظیمات» پنل معمولاً ۵ تا ۱۰ کلید را با هم می‌فرستد.
					// «لیست لوکیشن‌های پین‌شده»: اگه این کلید توی همین درخواست هست، لیست قبلی رو
					// قبل از نوشتن نگه می‌داریم تا بعدش بفهمیم کدوم کشورها آن‌پین شدن (چه از
					// تنظیمات همین پنل، چه از «Push to All Panels» پنل مادر).
					let previousPinnedLocations = null;
					if (Object.prototype.hasOwnProperty.call(body.settings, "pinned_locations")) {
						previousPinnedLocations = await getPinnedLocationsSetting(env);
					}
					const settingsStmts = Object.entries(body.settings).map(([k, v]) =>
						env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(k, String(v))
					);
					if (settingsStmts.length > 0) await env.DB.batch(settingsStmts);
					// کشوری که از لیست پین‌شده‌ها حذف شده، از کانفیگ همه‌ی کاربرهای موجود هم
					// پاک می‌شه (فقط کشورهایی که همین الان آن‌پین شدن - نه هر کشوری که پین نبوده).
					// اگه فراخواننده (Push پنل مادر) فلگ prune_unpinned_locations رو هم فرستاده
					// باشه، حالت «آینه‌ای» اجرا می‌شه: هر کشور تگ‌دار که توی لیست جدید نیست از
					// همه‌ی کاربرها پاک می‌شه (نه فقط اونایی که همین الان آن‌پین شدن). فلگ باید
					// بیرون از body.settings باشه، چون settings بدون whitelist ذخیره می‌شه.
					if (previousPinnedLocations) {
						const nowPinnedLocations = await getPinnedLocationsSetting(env);
						if (body.prune_unpinned_locations === true) {
							unpinRemoval = await removeUnpinnedCountriesFromAllUsers(env, ctx, nowPinnedLocations);
						} else {
							const unpinned = previousPinnedLocations.filter((cc) => !nowPinnedLocations.includes(cc));
							if (unpinned.length > 0) {
								unpinRemoval = await removeCountriesFromAllUsers(env, ctx, unpinned);
							}
						}
					}
					if (overrideUserLimit !== undefined) {
						await env.DB.prepare("UPDATE users SET ip_limit = ?, max_connections = ?").bind(overrideUserLimit, overrideUserLimit).run();
						userLimitApplied = true;
					}
					if (overrideDefaultPort !== undefined) {
						await env.DB.prepare("UPDATE users SET port = ?").bind(overrideDefaultPort).run();
						portApplied = true;
					}
					if (overrideGlobalCleanIp !== undefined) {
						await env.DB.prepare("UPDATE users SET ips = ?").bind(overrideGlobalCleanIp).run();
						cleanIpApplied = true;
					}
					if (overrideFrag !== undefined) {
						await env.DB.prepare("UPDATE users SET frag_len = ?, frag_int = ?").bind(overrideFrag.len, overrideFrag.int).run();
						fragApplied = true;
					}
					if (overrideEarlyData !== undefined) {
						await env.DB.prepare("UPDATE users SET early_data_enabled = ?, early_data_size = ?").bind(overrideEarlyData.enabled, overrideEarlyData.size).run();
						earlyDataApplied = true;
					}
					if (overrideFingerprint !== undefined) {
						await env.DB.prepare("UPDATE users SET fingerprint = ?").bind(overrideFingerprint).run();
						fingerprintApplied = true;
					}
					if (overrideConnType !== undefined) {
						await env.DB.prepare("UPDATE users SET connection_type = ?").bind(overrideConnType).run();
						connTypeApplied = true;
						// connection_type is also checked on every incoming connection (VLESS/Trojan), and that
						// lookup is cached for a few seconds — drop the cached entries so the new protocol
						// takes effect immediately instead of after the TTL.
						try {
							const { results: ctUsers } = await env.DB.prepare("SELECT uuid, trojan_hash FROM users").all();
							await Promise.all((ctUsers || []).map((r) => invalidateUserAuthCache(ctx, r.uuid, r.trojan_hash)));
						} catch (e) { /* best-effort: the cache expires by itself within seconds */ }
					}
				}
				return new Response(JSON.stringify({ success: true, unpinned_countries: unpinRemoval.countries, users_updated: unpinRemoval.usersUpdated, frag_applied: fragApplied, early_data_applied: earlyDataApplied, user_limit_applied: userLimitApplied, fingerprint_applied: fingerprintApplied, connection_type_applied: connTypeApplied, clean_ip_applied: cleanIpApplied, port_applied: portApplied }), { headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/settings/sync-vip-proxies") {
			if (request.method === "POST") {
				try {
					const result = await syncAllVipProxies();
					return new Response(JSON.stringify({ success: true, ...result }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
				} catch (e) {
					return new Response(JSON.stringify({ error: e.message || "خطا در دریافت مخزن VIP" }), { status: 502, headers: { "Content-Type": "application/json; charset=utf-8" } });
				}
			}
			// GET: بدون فچ تازه، همون چیزی که الان توی REPO_FILE_CACHE هست را (فقط کلیدهای proxy_vip/*)
			// به تفکیک کشور برمی‌گرداند — برای پاپ‌آپ «مشاهده لیست کش‌شده» در Settings.
			if (request.method === "GET") {
				const perCountry = {};
				let fetchedAt = null;
				for (const [key, entry] of REPO_FILE_CACHE) {
					const m = key.match(/^proxy_vip\/([A-Za-z0-9]+)\.txt$/);
					if (!m) continue;
					const cc = m[1].toUpperCase();
					const lines = (entry.data || "").split("\n").map((l) => l.trim()).filter((l) => l.length > 5);
					if (lines.length === 0) continue;
					perCountry[cc] = lines;
					if (fetchedAt === null || entry.timestamp > fetchedAt) fetchedAt = entry.timestamp;
				}
				return new Response(JSON.stringify({ success: true, perCountry, totalCountries: Object.keys(perCountry).length, fetchedAt }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
			}
		}
		if (url.pathname === "/api/proxy-ip") {
			if (request.method === "POST") {
				const { proxy_ip, iata, socks5 } = await readJsonBody(request);
				if (proxy_ip) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_ip', ?)").bind(proxy_ip).run();
				if (iata !== undefined) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_location_iata', ?)").bind(iata).run();
				if (socks5 !== undefined) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('socks5', ?)").bind(socks5).run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			}
			if (request.method === "GET") {
				// سه کلید در یک کوئری (یک رفت‌وبرگشت D1 به‌جای سه‌تا) - خروجی بدون تغییر.
				const proxyIpRows = await env.DB.prepare("SELECT key, value FROM settings WHERE key IN ('proxy_ip','proxy_location_iata','socks5')").all();
				const proxyIpMap = {};
				(proxyIpRows.results || []).forEach((r) => { proxyIpMap[r.key] = r.value; });
				const rowIp = proxyIpMap.proxy_ip !== undefined ? { value: proxyIpMap.proxy_ip } : null;
				const rowIata = proxyIpMap.proxy_location_iata !== undefined ? { value: proxyIpMap.proxy_location_iata } : null;
				const rowSocks = proxyIpMap.socks5 !== undefined ? { value: proxyIpMap.socks5 } : null;
				return new Response(
					JSON.stringify({
						proxy_ip: rowIp ? rowIp.value : "",
						iata: rowIata ? rowIata.value : "",
						socks5: rowSocks ? rowSocks.value : "",
					}),
					{ headers: { "Content-Type": "application/json" } },
				);
			}
		}
		if (url.pathname === "/api/test-proxy" && request.method === "POST") {
			const { proxy, skip_country, username, replace_on_fail } = await readJsonBody(request);
			if (!proxy) return new Response(JSON.stringify({ error: "پـروکـسـی وارد نشده است" }), { status: 400, headers: { "Content-Type": "application/json" } });
			
			if (proxy === "direct") {
				const startT = Date.now();
				try {
					const controller = new AbortController();
					const tid = setTimeout(() => controller.abort(), 3000);
					await fetch("https://cp.cloudflare.com/generate_204", { method: "HEAD", signal: controller.signal });
					clearTimeout(tid);
					return new Response(JSON.stringify({ success: true, ping: (Date.now() - startT), country: "UN" }), { headers: { "Content-Type": "application/json" } });
				} catch (e) {
					return new Response(JSON.stringify({ error: "نت آزاد قطع است" }), { status: 200, headers: { "Content-Type": "application/json" } });
				}
			}
			try {
				let ip = "";
				let workingProxy = proxy;
				if (proxy.includes("t.me/socks") || proxy.includes("tg://socks")) {
					ip = proxy.match(/server=([^&]+)/)?.[1] || "";
				} else {
					let cleanProxy = proxy.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
					let remain = cleanProxy;
					if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
					if (remain.startsWith("[")) {
						ip = remain.substring(1, remain.indexOf("]"));
					} else {
						const lastColon = remain.lastIndexOf(":");
						if (lastColon !== -1 && remain.indexOf(":") === lastColon) ip = remain.substring(0, lastColon);
						else ip = remain;
					}
				}
				let country = "UN";
				const startTime = Date.now();
				let targetHost = skip_country ? "1.1.1.1" : "ip-api.com";
				let reqPath = skip_country ? "/" : "/json/?fields=countryCode";
				const payload = new TextEncoder().encode("GET " + reqPath + " HTTP/1.1\r\nHost: " + targetHost + "\r\nConnection: close\r\n\r\n");
				
				const s = await connectProxy(proxy, targetHost, 80, payload);
				
				const reader = s.readable.getReader();
				let resStr = "";
				const dec = new TextDecoder();
				const timeoutId = setTimeout(() => {
					try {
						s.close();
					} catch (e) { }
				}, 7000);
				try {
					while (true) {
						const res = await reader.read();
						if (res.done || !res.value) break;
						resStr += dec.decode(res.value, { stream: true });
						if (skip_country) {
							if (resStr.includes("HTTP/1.")) break;
						} else {
							if (resStr.includes("countryCode")) break;
						}
					}
				} finally {
					clearTimeout(timeoutId);
					try {
						s.close();
					} catch (e) { }
				}
				if (!resStr) {
					throw new Error("تایم‌اوت در دریافت دیتا");
				}
				const ping = Date.now() - startTime;
				if (!skip_country) {
					try {
						const jsonMatch = resStr.match(/\{[^}]*"countryCode"\s*:\s*"([^"]+)"[^}]*\}/);
						if (jsonMatch && jsonMatch[1]) country = jsonMatch[1];
					} catch (e) { }
					if (country === "UN" && ip) {
						try {
							const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=countryCode`);
							const geoData = await geoRes.json();
							if (geoData && geoData.countryCode) country = geoData.countryCode;
						} catch (e) { }
					}
				}
				return new Response(JSON.stringify({ success: true, ping, country }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				if (username && replace_on_fail) {
					const replaceTask = replaceBrokenProxy(username, env, proxy);
					if (ctx) ctx.waitUntil(replaceTask);
					else replaceTask.catch(() => { });
				}
				let msg = e.message;
				if (msg.includes("Stream was cancelled") || msg.includes("network")) msg = "ارتباط با سرور قطع شد (احتمالاً پـروکـسـی مسدود یا خاموش است)";
				else if (msg.includes("timeout") || msg.includes("timed out") || msg.includes("تایم‌اوت")) msg = "تایم‌اوت در اتصال (پـروکـسـی در دسترس نیست)";
				else if (msg.includes("Invalid URL") || msg.includes("Invalid format")) msg = "فرمت وارد شده برای پـروکـسـی اشتباه است";
				else if (msg === "err") msg = "خطای نامشخص (ارتباط برقرار نشد)";
				return new Response(JSON.stringify({ error: msg }), { status: 200, headers: { "Content-Type": "application/json" } });
			}
		}
		// GET /api/stats-history: 30-day daily history for the Request and Traffic
		// dashboard cards, used to draw the click-to-expand line charts. Reuses the
		// same daily_requests / daily_traffic tables (and utcDateKey helper) as the
		// existing 7d/30d aggregate stats above. Today's entry additionally folds in
		// the not-yet-flushed in-memory counters (GLOBAL_REQ_COUNT / GLOBAL_TRAFFIC_CACHE)
		// so the last (today) point on the chart reflects live, not-yet-persisted usage.
		// NOTE: storage rows are now hourly (utcHourKey), but this chart still wants one
		// point per calendar day, so we let SQLite roll the hourly rows up with
		// substr(date,1,10)+GROUP BY (works transparently on both old day-only rows and
		// new hour-keyed rows, since both share the same 10-char YYYY-MM-DD prefix).
		if (url.pathname === "/api/stats-history" && request.method === "GET") {
			try {
				const now = Date.now();
				const days = [];
				for (let i = 29; i >= 0; i--) days.push(utcDateKey(now - i * 86400000));
				const startKey = days[0];
				const todayKey = days[days.length - 1];
				const [reqRows, trafficRows] = await Promise.all([
					env.DB.prepare("SELECT substr(date,1,10) as date, SUM(count) as count FROM daily_requests WHERE date >= ? GROUP BY substr(date,1,10)").bind(startKey).all(),
					env.DB.prepare("SELECT substr(date,1,10) as date, SUM(gb) as gb FROM daily_traffic WHERE date >= ? GROUP BY substr(date,1,10)").bind(startKey).all(),
				]);
				const reqMap = new Map((reqRows.results || []).map((r) => [r.date, r.count || 0]));
				const trafficMap = new Map((trafficRows.results || []).map((r) => [r.date, r.gb || 0]));
				let pendingGb = 0;
				for (const v of GLOBAL_TRAFFIC_CACHE.values()) pendingGb += v || 0;
				pendingGb = pendingGb / (1024 * 1024 * 1024);
				const pendingReq = GLOBAL_REQ_COUNT || 0;
				const requests = days.map((d) => ({ date: d, value: (reqMap.get(d) || 0) + (d === todayKey ? pendingReq : 0) }));
				const traffic = days.map((d) => ({ date: d, value: (trafficMap.get(d) || 0) + (d === todayKey ? pendingGb : 0) }));
				return new Response(JSON.stringify({ requests, traffic }), {
					headers: { "Content-Type": "application/json", "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0" },
				});
			} catch (e) {
				return new Response(JSON.stringify({ requests: [], traffic: [], error: e.message }), {
					status: 200,
					headers: { "Content-Type": "application/json" },
				});
			}
		}
		if (url.pathname.startsWith("/api/users")) {
			const pathParts = url.pathname.split("/");
			const isUserAction = pathParts.length > 3;
			if (isUserAction) {
				const username = safeDecodeURI(pathParts.pop());
				if (request.method === "PUT") {
					const body = await readJsonBody(request);
					if (Object.keys(body).length === 0) {
						return new Response(JSON.stringify({ error: "Invalid request body" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					if (body.toggle_only !== undefined) {
						await env.DB.prepare("UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE username = ?").bind(username).run();
						const toggledUser = await env.DB.prepare("SELECT uuid, trojan_hash FROM users WHERE username = ?").bind(username).first();
						if (toggledUser) await invalidateUserAuthCache(ctx, toggledUser.uuid, toggledUser.trojan_hash);
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} else if (body.reset_action !== undefined) {
						if (body.reset_action === "volume") {
							await env.DB.prepare("UPDATE users SET used_gb = 0, is_active = 1 WHERE username = ?").bind(username).run();
							GLOBAL_TRAFFIC_CACHE.set(username, 0);
						} else if (body.reset_action === "req") {
							await env.DB.prepare("UPDATE users SET used_req = 0, is_active = 1 WHERE username = ?").bind(username).run();
							USER_REQ_CACHE.set(username, 0);
						} else if (body.reset_action === "time") {
							await env.DB.prepare("UPDATE users SET created_at = CURRENT_TIMESTAMP, first_connection_time = NULL, is_active = 1 WHERE username = ?").bind(username).run();
							for (const [lockK] of GLOBAL_WRITE_LOCK.entries()) { if (lockK.endsWith("_first_conn")) GLOBAL_WRITE_LOCK.delete(lockK); }
						} else if (body.reset_action === "locations") {
							// Additive retrofit for an existing user: adds any currently-pinned
							// country (getPinnedLocationsSetting()) this user doesn't already
							// have. Everything already on the user - pinned or not - is left
							// untouched (see mergePinnedLocationsForUser() for why: an unpinned
							// country must keep working for anyone who already has it).
							const pinnedLocations = await getPinnedLocationsSetting(env);
							const existingRow = await env.DB.prepare("SELECT user_socks5 FROM users WHERE username = ?").bind(username).first();
							let existingList = [];
							try {
								if (existingRow && existingRow.user_socks5 && existingRow.user_socks5.trim().startsWith("[")) {
									existingList = JSON.parse(existingRow.user_socks5);
								}
							} catch (e) {
								existingList = [];
							}
							const { list: mergedList, cappedOut } = await mergePinnedLocationsForUser(existingList, pinnedLocations);
							await env.DB.prepare("UPDATE users SET user_socks5 = ?, auto_rotate_user_proxy = 1 WHERE username = ?").bind(JSON.stringify(mergedList), username).run();
							const locUser = await env.DB.prepare("SELECT uuid, trojan_hash FROM users WHERE username = ?").bind(username).first();
							if (locUser) await invalidateUserAuthCache(ctx, locUser.uuid, locUser.trojan_hash);
							// cappedOut: pinned countries this user hit MAX_LOCATIONS_PER_USER
							// before receiving (nothing is auto-deleted to make room - see the
							// comment on MAX_LOCATIONS_PER_USER). The panel surfaces this per
							// username so the admin can manually free up a slot if they want them.
							return new Response(JSON.stringify({ success: true, username, capped: cappedOut.length > 0, cappedCountries: cappedOut }), { headers: { "Content-Type": "application/json" } });
						} else if (body.reset_action === "remove_location") {
							// Manual cleanup: strips one specific country (body.country, e.g.
							// "TR") out of this user's proxy list, if present. Independent of
							// the additive "locations" action above - un-pinning a country in
							// settings now removes the country from all users automatically (see
							// removeCountriesFromAllUsers()); this action is for removing a country
							// from one specific user by hand.
							const targetCountry = String(body.country || "").trim().toUpperCase();
							if (!targetCountry) {
								return new Response(JSON.stringify({ error: "Missing country" }), { status: 400, headers: { "Content-Type": "application/json" } });
							}
							const rmRow = await env.DB.prepare("SELECT user_socks5 FROM users WHERE username = ?").bind(username).first();
							let rmList = [];
							try {
								if (rmRow && rmRow.user_socks5 && rmRow.user_socks5.trim().startsWith("[")) {
									rmList = JSON.parse(rmRow.user_socks5);
								}
							} catch (e) {
								rmList = [];
							}
							const beforeLen = rmList.length;
							rmList = rmList.filter((p) => !(typeof p === "object" && p !== null && (p.country || "").toUpperCase() === targetCountry));
							const removed = rmList.length < beforeLen;
							if (removed) {
								await env.DB.prepare("UPDATE users SET user_socks5 = ? WHERE username = ?").bind(JSON.stringify(rmList), username).run();
								const rmUser = await env.DB.prepare("SELECT uuid, trojan_hash FROM users WHERE username = ?").bind(username).first();
								if (rmUser) await invalidateUserAuthCache(ctx, rmUser.uuid, rmUser.trojan_hash);
							}
							return new Response(JSON.stringify({ success: true, username, removed }), { headers: { "Content-Type": "application/json" } });
						}
						const resetUser = await env.DB.prepare("SELECT uuid, trojan_hash FROM users WHERE username = ?").bind(username).first();
						if (resetUser) await invalidateUserAuthCache(ctx, resetUser.uuid, resetUser.trojan_hash);
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} else {
						const { username: new_username, uuid: new_uuid, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, block_porn, block_ads, frag_len, frag_int, advanced_frag, cipher_suites, tls_mask, user_proxy_iata, user_socks5, user_proxy_ip, auto_reset_vol_days, auto_reset_req_days, auto_rotate_ip, rotate_time, ip_operator, ip_count, auto_rotate_user_proxy, start_on_first_connect, enable_direct, connection_type, protocols } = body;
						if (new_username && new_username !== username) {
							if (!/^[a-zA-Z0-9_-]+$/.test(new_username)) {
								return new Response(JSON.stringify({ error: "نام کاربری جدید غیرمجاز است" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
							}
							const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").bind(new_username).first();
							if (existing) {
								return new Response(JSON.stringify({ error: "این نام کاربری از قبل وجود دارد" }), { status: 400, headers: { "Content-Type": "application/json" } });
							}
							if (GLOBAL_TRAFFIC_CACHE.has(username)) {
								GLOBAL_TRAFFIC_CACHE.set(new_username, GLOBAL_TRAFFIC_CACHE.get(username));
								GLOBAL_TRAFFIC_CACHE.delete(username);
							}
							if (USER_REQ_CACHE.has(username)) {
								USER_REQ_CACHE.set(new_username, USER_REQ_CACHE.get(username));
								USER_REQ_CACHE.delete(username);
							}
							if (ACTIVE_CONNECTIONS_COUNT.has(username)) {
								ACTIVE_CONNECTIONS_COUNT.set(new_username, ACTIVE_CONNECTIONS_COUNT.get(username));
								ACTIVE_CONNECTIONS_COUNT.delete(username);
							}
							if (GLOBAL_LAST_ACTIVE_WRITE.has(username)) {
								GLOBAL_LAST_ACTIVE_WRITE.set(new_username, GLOBAL_LAST_ACTIVE_WRITE.get(username));
								GLOBAL_LAST_ACTIVE_WRITE.delete(username);
							}
						}
						let finalConnType = undefined;
						if (protocols && Array.isArray(protocols) && protocols.length > 0) {
							finalConnType = protocols.join(",");
						} else if (connection_type) {
							finalConnType = connection_type;
						}
						const existingUser = await env.DB.prepare("SELECT id, uuid, trojan_hash, user_socks5 FROM users WHERE username = ?").bind(username).first();
						let finalUuid = existingUser ? existingUser.uuid : null;
						if (new_uuid !== undefined && new_uuid !== null && String(new_uuid).trim() !== "") {
							const trimmedUuid = String(new_uuid).trim().toLowerCase();
							if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(trimmedUuid)) {
								return new Response(JSON.stringify({ error: "فرمت UUID نامعتبر است" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
							}
							if (trimmedUuid !== (existingUser && existingUser.uuid ? String(existingUser.uuid).toLowerCase() : null)) {
								const existingUuidUser = await env.DB.prepare("SELECT id FROM users WHERE uuid = ? COLLATE NOCASE AND id != ?").bind(trimmedUuid, existingUser ? existingUser.id : -1).first();
								if (existingUuidUser) {
									return new Response(JSON.stringify({ error: "این UUID قبلاً برای کاربر دیگری استفاده شده است" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
								}
							}
							finalUuid = trimmedUuid;
						}
						const trojanHash = finalUuid ? sha224Pure(finalUuid) : null;
						// "Reset to Default" (edit-user modal): the form already carries every other field at its
						// new-user default (the client did that), so the rest of this PUT just saves them; usage
						// counters (used_gb, used_req, lifetime_used_gb, created_at, first_connection_time ...) are
						// not in the UPDATE below and stay untouched. What only the server can do is throw the
						// user's proxy list away and rebuild it from the pinned locations in Settings - the same
						// list a brand-new user gets. Otherwise keep the country tag of every slot the admin left
						// unchanged (see preserveProxyCountryTags() for why the form alone can't do it).
						const resetProxyToDefault = body.reset_user_to_default === true;
						let finalUserSocks5 = user_socks5;
						if (resetProxyToDefault) {
							const pinnedForReset = await getPinnedLocationsSetting(env);
							const rebuiltList = await buildPinnedDefaultProxyList(pinnedForReset);
							// Every VIP list unreachable/empty (e.g. the source is down right now) would turn a
							// working-but-mistagged user into a direct-only one - refuse and leave the user untouched.
							if (rebuiltList.length > 0 && rebuiltList.every((slot) => !slot.proxy)) {
								return new Response(JSON.stringify({ error: "لیست پروکسی‌های VIP در حال حاضر در دسترس نیست؛ هیچ تغییری اعمال نشد. کمی بعد دوباره تلاش کنید." }), { status: 502, headers: { "Content-Type": "application/json; charset=utf-8" } });
							}
							finalUserSocks5 = JSON.stringify(rebuiltList);
						} else {
							finalUserSocks5 = preserveProxyCountryTags(user_socks5, existingUser ? existingUser.user_socks5 : null);
						}
						try {
							await env.DB.prepare("UPDATE users SET username = ?, uuid = ?, limit_gb = ?, expiry_days = ?, limit_req = ?, ips = ?, tls = ?, port = ?, fingerprint = ?, max_connections = ?, ip_limit = ?, block_porn = ?, block_ads = ?, frag_len = ?, frag_int = ?, advanced_frag = ?, cipher_suites = ?, tls_mask = ?, user_proxy_iata = ?, user_socks5 = ?, user_proxy_ip = ?, auto_reset_vol_days = ?, auto_reset_req_days = ?, auto_rotate_ip = ?, rotate_time = ?, ip_operator = ?, ip_count = ?, auto_rotate_user_proxy = ?, start_on_first_connect = ?, enable_direct = ?, connection_type = CASE WHEN ? IS NOT NULL THEN ? ELSE connection_type END, trojan_hash = ? WHERE username = ?")
								.bind(new_username || username, finalUuid, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, ips || null, tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, block_porn ? 1 : 0, block_ads ? 1 : 0, frag_len !== undefined ? frag_len : "200-3000", frag_int !== undefined ? frag_int : "1-2", advanced_frag || null, cipher_suites || null, tls_mask || null, user_proxy_iata || null, finalUserSocks5 || null, user_proxy_ip || null, auto_reset_vol_days ? parseInt(auto_reset_vol_days) : 0, auto_reset_req_days ? parseInt(auto_reset_req_days) : 0, auto_rotate_ip || 0, rotate_time || 0, ip_operator || "all", ip_count || 999999, (resetProxyToDefault || auto_rotate_user_proxy) ? 1 : 0, start_on_first_connect ? 1 : 0, enable_direct !== undefined ? (enable_direct ? 1 : 0) : 1, finalConnType !== undefined ? finalConnType : null, finalConnType !== undefined ? finalConnType : null, trojanHash, username)
								.run();
						} catch (err) {
							// اگه این خطا دقیقاً برخورد با ایندکس UNIQUE جدید uuid باشه (فقط در یک ریس-کاندیشن واقعی ممکنه، چون بالاتر همین uuid چک شده)، همون پیام دوستانه‌ی همیشگی رو برگردون؛ برای هر خطای دیگه‌ی دیتابیس هم به‌جای کرش کردن، خطای تمیز JSON برگردون
							const msg = String((err && err.message) || "");
							if (msg.toLowerCase().includes("unique")) {
								return new Response(JSON.stringify({ error: "این UUID قبلاً برای کاربر دیگری استفاده شده است" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
							}
							return new Response(JSON.stringify({ error: msg }), { status: 500, headers: { "Content-Type": "application/json" } });
						}
						if (resetProxyToDefault) {
							// fresh list => old per-country auto-heal cooldowns no longer apply. The auto-reset timers
							// are restarted from today exactly like POST /api/users does for a new user: last_reset_*_time
							// defaults to 0 for old rows, so once the defaults switch auto-reset on, checkAutoResets()
							// would otherwise see a "period long overdue" and zero used_gb / used_req at its next run.
							const resetTodayUtc = Math.floor(Date.now() / 86400000) * 86400000;
							try { await env.DB.prepare("UPDATE users SET proxy_rotate_cooldowns = '{}', last_reset_vol_time = ?, last_reset_req_time = ? WHERE username = ?").bind(resetTodayUtc, resetTodayUtc, new_username || username).run(); } catch (e) { }
						}
						// Invalidate the old identity's cache entries (covers the common case where
						// uuid didn't change too). If the admin also assigned a new uuid, invalidate
						// that as well in case a stale negative-cache ("no such user") entry exists
						// for it from an earlier probe/connection attempt.
						if (existingUser) await invalidateUserAuthCache(ctx, existingUser.uuid, existingUser.trojan_hash);
						if (finalUuid && (!existingUser || finalUuid !== existingUser.uuid)) await invalidateUserAuthCache(ctx, finalUuid, trojanHash);
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					}
				}
				if (request.method === "DELETE") {
					let userToDelete = null;
					try {
						userToDelete = await env.DB.prepare("SELECT uuid, trojan_hash, lifetime_used_gb, used_gb FROM users WHERE username = ?").bind(username).first();
						if (userToDelete) {
							const gbToKeep = userToDelete.lifetime_used_gb || userToDelete.used_gb || 0;
							if (gbToKeep > 0) {
								await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('deleted_users_gb', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS REAL) + ?").bind(String(gbToKeep), String(gbToKeep)).run();
							}
						}
					} catch(e) {}
					await env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
					if (userToDelete) await invalidateUserAuthCache(ctx, userToDelete.uuid, userToDelete.trojan_hash);
					return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
				}
			} else {
				if (request.method === "GET") {
					try {
						await flushExpiredTraffic(env);
					} catch (e) { }
					try {
						const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY id DESC").all();
						const now = Date.now();
						const cachedIpsData = await getCachedIps();
						const enrichedUsers = (results || []).map((user) => {
							let finalIps = user.ips;
							if (user.auto_rotate_ip === 1) {
								const randomIps = getRandomIps(cachedIpsData, user.ip_operator || "all", user.ip_count || 999999);
								if (randomIps.length > 0) finalIps = randomIps.join("\n");
							}
							const currentOnlineCount = Math.max((ACTIVE_CONNECTIONS_COUNT.get(user.username) || 0), getActiveIpCount(user.active_ips));
							// «هشدار تعداد دستگاه»: تا ۲۴ ساعت بعد از آخرین باری که تعداد دستگاه فعال
							// این کاربر از ip_limit‌ش بیشتر شده (device_warning_at - ست‌شده توسط
							// persistActiveIp)، این پرچم true می‌مونه تا پنل روی کارت کاربر نشونش بده.
							const deviceWarning = !!(user.device_warning_at && now - user.device_warning_at < 24 * 60 * 60 * 1000);
							return {
								...user,
								ips: finalIps,
								used_gb: (user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024)),
								used_req: (user.used_req || 0) + (USER_REQ_CACHE.get(user.username) || 0),
								is_online: currentOnlineCount > 0 ? 1 : 0,
								online_count: currentOnlineCount,
								device_warning: deviceWarning,
							};
						});
						// چهار کلیدی که این endpoint از جدول settings لازم داره، به‌جای چهار SELECT جدا
						// (چهار رفت‌وبرگشت D1 روی هر بار رفرش پنل) با یک کوئری IN (...) خونده می‌شن -
						// همون الگوی isGlobalReqLimitReached. نتیجه دقیقاً یکیه، فقط ارزون‌تر.
						const panelSettings = {};
						try {
							const settingsRes = await env.DB.prepare("SELECT key, value FROM settings WHERE key IN ('req_last_date','req_total','req_today','deleted_users_gb')").all();
							(settingsRes.results || []).forEach((r) => { panelSettings[r.key] = r.value; });
						} catch (e) { }
						let cfReqs = { today: 0, total: 0, d1Reads: 0, d1Writes: 0 };
						try {
							const liveCf = await getCfUsage(env);
							const todayStr = new Date().toISOString().split("T")[0];
							let dbTotal = parseInt(panelSettings.req_total) || 0;
							let dbToday = panelSettings.req_last_date === todayStr ? parseInt(panelSettings.req_today) || 0 : 0;
							if (liveCf.today > dbToday) {
								dbToday = liveCf.today;
								await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(dbToday), String(dbToday)).run();
								await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(todayStr, todayStr).run();
							}
							if (liveCf.total > dbTotal) {
								dbTotal = liveCf.total;
								await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_total', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(dbTotal), String(dbTotal)).run();
							}
							cfReqs.today = dbToday + GLOBAL_REQ_COUNT;
							cfReqs.total = dbTotal + GLOBAL_REQ_COUNT;
							cfReqs.d1Reads = liveCf.d1Reads;
							cfReqs.d1Writes = liveCf.d1Writes;
						} catch (e) { }
						// از همون panelSettings بالا (بدون SELECT جداگانه).
						const deletedGb = parseFloat(panelSettings.deleted_users_gb) || 0;
						// آمار ترافیک روزانه / 7 روز گذشته / 30 روز گذشته از جدول daily_traffic - حالا که ذخیره‌سازی
						// ساعتی‌ست، این‌ها بازه‌ی رولینگ واقعی‌اند (دقیقاً 24/7×24/30×24 ساعت گذشته از همین لحظه،
						// با دقت ~۱ ساعت)، نه از نیمه‌شب UTC. حداکثر 24/168/720 ردیف اسکن می‌شه، هنوز ارزان.
						// + مقدار هنوز-flush-نشده‌ی حافظه (GLOBAL_TRAFFIC_CACHE) برای اینکه عدد لحظه‌ای باشد
						let trafficDaily = 0, traffic7d = 0, traffic30d = 0;
						try {
							const dailyCutoffKey = utcHourKey(now - 24 * 3600000);
							const sevenAgoKey = utcHourKey(now - 7 * 86400000);
							const thirtyAgoKey = utcHourKey(now - 30 * 86400000);
							const [dailyRow, sevenRow, thirtyRow] = await Promise.all([
								env.DB.prepare("SELECT SUM(gb) as s FROM daily_traffic WHERE date >= ?").bind(dailyCutoffKey).first(),
								env.DB.prepare("SELECT SUM(gb) as s FROM daily_traffic WHERE date >= ?").bind(sevenAgoKey).first(),
								env.DB.prepare("SELECT SUM(gb) as s FROM daily_traffic WHERE date >= ?").bind(thirtyAgoKey).first(),
							]);
							let pendingGb = 0;
							for (const v of GLOBAL_TRAFFIC_CACHE.values()) pendingGb += v || 0;
							pendingGb = pendingGb / (1024 * 1024 * 1024);
							trafficDaily = (dailyRow?.s || 0) + pendingGb;
							traffic7d = (sevenRow?.s || 0) + pendingGb;
							traffic30d = (thirtyRow?.s || 0) + pendingGb;
						} catch (e) { }
						// آمار تعداد ریکوئست‌های 7 روز گذشته / 30 روز گذشته از جدول daily_requests - همون منطق رولینگ بالا
						// + مقدار هنوز-flush-نشده‌ی حافظه (GLOBAL_REQ_COUNT) برای اینکه عدد لحظه‌ای باشد
						let cfRequests7d = 0, cfRequests30d = 0;
						try {
							const sevenAgoKey = utcHourKey(now - 7 * 86400000);
							const thirtyAgoKey = utcHourKey(now - 30 * 86400000);
							const [sevenReqRow, thirtyReqRow] = await Promise.all([
								env.DB.prepare("SELECT SUM(count) as s FROM daily_requests WHERE date >= ?").bind(sevenAgoKey).first(),
								env.DB.prepare("SELECT SUM(count) as s FROM daily_requests WHERE date >= ?").bind(thirtyAgoKey).first(),
							]);
							cfRequests7d = (sevenReqRow?.s || 0) + GLOBAL_REQ_COUNT;
							cfRequests30d = (thirtyReqRow?.s || 0) + GLOBAL_REQ_COUNT;
						} catch (e) { }
						return new Response(
							JSON.stringify({
								users: enrichedUsers,
								serverTime: now,
								cfRequestsToday: cfReqs.today,
								cfRequestsTotal: cfReqs.total,
								cfRequests7d: cfRequests7d,
								cfRequests30d: cfRequests30d,
								d1Reads: cfReqs.d1Reads,
								d1Writes: cfReqs.d1Writes,
								deletedGb: deletedGb,
								trafficDaily: trafficDaily,
								traffic7d: traffic7d,
								traffic30d: traffic30d,
							}),
							{
								headers: {
									"Content-Type": "application/json",
									"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
								},
							},
						);
					} catch (dbErr) {
						return new Response(
							JSON.stringify({
								users: [],
								serverTime: Date.now(),
								cfRequestsToday: 0,
								cfRequestsTotal: 0,
								cfRequests7d: 0,
								cfRequests30d: 0,
								error: dbErr.message,
							}),
							{
								status: 200,
								headers: {
									"Content-Type": "application/json",
									"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
								},
							},
						);
					}
				}
				if (request.method === "POST") {
					const { username, uuid, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, advanced_frag, cipher_suites, tls_mask, user_proxy_iata, user_socks5, user_proxy_ip, auto_reset_vol_days, auto_reset_req_days, auto_rotate_ip, rotate_time, ip_operator, ip_count, auto_rotate_user_proxy, start_on_first_connect, enable_direct, connection_type, protocols } = await readJsonBody(request);
					if (!username) {
						return new Response(JSON.stringify({ error: "نام کاربری اجباری است" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					if (username.length > 32) {
						return new Response(JSON.stringify({ error: "نام کاربری نمی‌تواند بیشتر از ۳۲ کاراکتر باشد" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
						return new Response(JSON.stringify({ error: "نام کاربری غیرمجاز است (فقط حروف، اعداد، خط تیره و آندرلاین)" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
					}
					let finalUuid = uuid ? String(uuid).trim().toLowerCase() : "";
					if (finalUuid) {
						if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(finalUuid)) {
							return new Response(JSON.stringify({ error: "فرمت UUID نامعتبر است" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
						}
						const existingUuidUser = await env.DB.prepare("SELECT id FROM users WHERE uuid = ? COLLATE NOCASE").bind(finalUuid).first();
						if (existingUuidUser) {
							return new Response(JSON.stringify({ error: "این UUID قبلاً برای کاربر دیگری استفاده شده است" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
						}
					} else {
						finalUuid = crypto.randomUUID();
					}
					const parsedUsedGb = parseFloat(used_gb);
					const finalUsedGb = !isNaN(parsedUsedGb) ? parsedUsedGb : 0;
					const parsedUsedReq = parseInt(used_req);
					const finalUsedReq = !isNaN(parsedUsedReq) ? parsedUsedReq : 0;
					const finalCreatedAt = created_at || new Date().toISOString();
					const parsedIsActive = parseInt(is_active);
					const finalIsActive = !isNaN(parsedIsActive) ? parsedIsActive : 1;
					const existingUser = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").bind(username).first();
					if (existingUser) {
						return new Response(JSON.stringify({ error: "این نام کاربری از قبل وجود دارد" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
					}
					try {
						const todayUtc = Math.floor(Date.now() / 86400000) * 86400000;
						const nowTime = Date.now();
						let finalConnType = "vless";
						if (protocols && Array.isArray(protocols) && protocols.length > 0) {
							finalConnType = protocols.join(",");
						} else if (connection_type) {
							finalConnType = connection_type;
						}
						const trojanHash = sha224Pure(finalUuid);
						// «محدودیت کاربر»: اگه ادمین/فرم/API چیزی توی این فیلد نفرستاده باشه (ip_limit
						// خالی/نال)، به‌جای نال، عدد سراسریِ تنظیم‌شده (user_limit - پیش‌فرض ۲) روی
						// ip_limit و max_connections این کاربر جدید ست می‌شه. اگه عدد دیگه‌ای (حتی ۰)
						// فرستاده شده باشه، همون عدد برنده‌ست، نه پیش‌فرض سراسری. (تنظیم جدای «هشدار
						// تعداد دستگاه» - device_warning_threshold - دیگه اینجا هیچ نقشی نداره.)
						const finalIpLimit = ip_limit !== undefined && ip_limit !== null && String(ip_limit).trim() !== "" ? parseInt(ip_limit) : await getUserLimitSetting(env);
						// «پورت»: اگه ادمین/فرم چیزی برای port نفرستاده باشه (خالی/نال)، به‌جای
						// نال، پورت پیش‌فرض سراسری تنظیم‌شده (default_port - پیش‌فرض ۲۰۸۳) روی
						// این کاربر تازه ست می‌شه. اگه مقداری فرستاده شده باشه (مثلاً از چک‌باکس‌های
						// فرم افزودن کاربر)، همون مقدار برنده‌ست.
						const finalPort = port !== undefined && port !== null && String(port).trim() !== "" ? port : await getDefaultPortSetting(env);
						// «پیش‌فرض‌های کاربر جدید» (Settings → new_user_*): هر فیلدی که درخواست
						// اصلاً نفرستاده باشد (undefined/null) از این‌جا پر می‌شود، تا کاربری که با API
						// ساخته می‌شود (مثلاً از پنل مادر) دقیقاً همان مقادیری را بگیرد که فرم دستی
						// «ایجاد کاربر جدید» پیش‌فرض می‌کند. فرم دستی همه‌ی این فیلدها را صریح
						// می‌فرستد، پس رفتار آن عوض نمی‌شود - مقدار صریح همیشه برنده است.
						const nud = await getNewUserDefaults(env);
						const given = (v) => v !== undefined && v !== null;
						const flagOf = (v, dfltStr) => (given(v) ? (v && v !== "0" && v !== "false" ? 1 : 0) : dfltStr === "1" ? 1 : 0);
						const intOf = (v, dfltStr) => (given(v) ? parseInt(v) || 0 : parseInt(dfltStr) || 0);
						const finalFingerprint = fingerprint || nud.new_user_fingerprint;
						const finalIps = ips !== undefined ? ips : nud.global_clean_ip;
						const finalTls = given(tls) && String(tls).trim() !== "" ? tls : String(finalPort).split(",").some((p) => NEW_USER_TLS_PORTS.includes(p.trim())) ? "on" : "off";
						if (!(protocols && Array.isArray(protocols) && protocols.length > 0) && !connection_type) finalConnType = nud.new_user_connection_type;
						// Every new user is always pinned to whatever the current
						// pinned_locations setting holds (see getPinnedLocationsSetting();
						// falls back to the built-in 15-country default if that setting
						// was never saved) - whatever was submitted for user_socks5 is
						// ignored on create. The actual VIP proxies are fetched/tested in
						// the background right after insert (see ctx.waitUntil below) so
						// this request doesn't have to wait on a full round of live
						// proxy testing.
						await env.DB.prepare("INSERT INTO users (username, uuid, limit_gb, expiry_days, limit_req, ips, connection_type, tls, port, fingerprint, max_connections, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, advanced_frag, cipher_suites, tls_mask, user_proxy_iata, user_socks5, user_proxy_ip, auto_reset_vol_days, auto_reset_req_days, last_reset_vol_time, last_reset_req_time, auto_rotate_ip, rotate_time, ip_operator, ip_count, last_rotate_time, auto_rotate_user_proxy, start_on_first_connect, first_connection_time, trojan_hash, enable_direct) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
							.bind(username, finalUuid, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, finalIps || null, finalConnType, finalTls, finalPort, finalFingerprint, finalIpLimit, finalIpLimit, finalUsedGb, finalUsedReq, finalCreatedAt, finalIsActive, flagOf(block_porn, nud.new_user_block_porn), flagOf(block_ads, nud.new_user_block_ads), frag_len !== undefined ? frag_len : nud.new_user_frag_len, frag_int !== undefined ? frag_int : nud.new_user_frag_int, advanced_frag || null, cipher_suites || null, tls_mask || null, user_proxy_iata || null, null, user_proxy_ip || null, intOf(auto_reset_vol_days, nud.new_user_auto_reset_vol_days), intOf(auto_reset_req_days, nud.new_user_auto_reset_req_days), todayUtc, todayUtc, given(auto_rotate_ip) ? auto_rotate_ip || 0 : intOf(undefined, nud.new_user_auto_rotate_ip), rotate_time || 0, ip_operator || nud.new_user_ip_operator, ip_count || parseInt(nud.new_user_ip_count) || 999999, nowTime, flagOf(auto_rotate_user_proxy, nud.new_user_auto_rotate_user_proxy), flagOf(start_on_first_connect, nud.new_user_start_on_first_connect), null, trojanHash, flagOf(enable_direct, nud.new_user_enable_direct))
							.run();
						// Clears any stale negative-cache ("no such user") entry that might exist for
						// this uuid/hash from an earlier probe or connection attempt with this UUID.
						await invalidateUserAuthCache(ctx, finalUuid, trojanHash);
						if (ctx) {
							ctx.waitUntil((async () => {
								try {
									const pinnedLocations = await getPinnedLocationsSetting(env);
									const pinnedList = await buildPinnedDefaultProxyList(pinnedLocations);
									await env.DB.prepare("UPDATE users SET user_socks5 = ? WHERE username = ?").bind(JSON.stringify(pinnedList), username).run();
								} catch (e) { }
								// The row above may already have been cached (with a null user_socks5)
								// by a connection that landed in the gap between insert and this
								// background update finishing - invalidate again so the next
								// connection picks up the real pinned proxy list instead of a stale copy.
								await invalidateUserAuthCache(ctx, finalUuid, trojanHash);
							})());
						}
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} catch (err) {
						return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
					}
				}
			}
		}
		return new Response(JSON.stringify({ error: "Not Found" }), { status: 404, headers: { "Content-Type": "application/json" } });
	},
};
let schemaEnsured = false;
let schemaPromise = null;
let cachedPanelPassword = null;
const DbService = {
	async ensureSchema(db) {
	if (schemaEnsured) return;
		if (schemaPromise) {
			await schemaPromise;
			return;
		}
		schemaPromise = (async () => {
			try {
				await db.prepare(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, uuid TEXT, limit_gb REAL, expiry_days INTEGER, ips TEXT, connection_type TEXT, tls TEXT, port INTEGER, used_gb REAL DEFAULT 0, is_active INTEGER DEFAULT 1, last_active INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`).run();
			} catch (e) { }
			try {
				await db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)").run();
			} catch (e) { }
			try {
				// پیش‌فرض‌های آیپی تمیز سراسری/آیپی‌های تمیز دیگر/Proxy IP رو همین‌جا توی
				// دیتابیس seed می‌کنیم (نه فقط توی فرم سمت کلاینت)، تا از همون دیپلوی اول
				// این مقادیر واقعاً در تنظیمات وجود داشته باشن و نیازی به زدن دستی دکمه‌ی
				// «ذخیره» بعد از دیپلوی نباشه. INSERT OR IGNORE یعنی اگه ادمین قبلاً این
				// کلید رو (حتی با مقدار خالی) ذخیره کرده باشه، دست‌نخورده می‌مونه.
				await db.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES ('global_clean_ip', ?)").bind(DEFAULT_GLOBAL_CLEAN_IP_FALLBACK).run();
				await db.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES ('other_clean_ips', ?)").bind(DEFAULT_OTHER_CLEAN_IPS_FALLBACK.join("\n")).run();
				await db.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES ('inline_proxy_ip', ?)").bind(DEFAULT_INLINE_PROXY_IP_FALLBACK).run();
				await db.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES ('default_port', ?)").bind(DEFAULT_PORT_FALLBACK).run();
				// پیش‌فرض‌های کاربر جدید (new_user_*) - یک batch، INSERT OR IGNORE: کلیدی که
				// ادمین/پنل مادر قبلاً ذخیره کرده دست‌نخورده می‌ماند.
				await db.batch(Object.entries(NEW_USER_DEFAULTS_FALLBACK).map(([k, v]) => db.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)").bind(k, v)));
			} catch (e) { }
			try {
				// جدول ترافیک، به تفکیک ساعت UTC (ستون "date" همچنان TEXT PRIMARY KEY است، فقط از این پس
				// مقداری به فرم YYYY-MM-DDTHH در آن ذخیره می‌شود - نه YYYY-MM-DD؛ به utcHourKey نگاه کنید).
				// برای نگه‌داری تاریخچه‌ی 30 روز اخیر و محاسبه‌ی آمار رولینگ "روزانه"/"7 روز"/"30 روز گذشته"
				// با دقت ~۱ ساعت. هر ساعت فقط یک ردیف دارد (UPSERT، حداکثر 24×30=720 ردیف کل)؛ قدیمی‌تر
				// از 30 روز به‌صورت دوره‌ای پاک می‌شود (ردیف‌های قدیمیِ فرمت روزانه هم با همان cutoff رشته‌ای
				// درست پاک می‌شوند، چون هر دو فرمت با همان 10 کاراکتر YYYY-MM-DD شروع می‌شوند).
				await db.prepare("CREATE TABLE IF NOT EXISTS daily_traffic (date TEXT PRIMARY KEY, gb REAL DEFAULT 0)").run();
			} catch (e) { }
			try {
				// جدول تعداد ریکوئست‌ها، به تفکیک ساعت UTC - همون توضیح جدول daily_traffic بالا صدق می‌کند.
				await db.prepare("CREATE TABLE IF NOT EXISTS daily_requests (date TEXT PRIMARY KEY, count INTEGER DEFAULT 0)").run();
			} catch (e) { }
			try {
				// ایندکس روی uuid برای سریع/ارزون‌تر شدن پرتکرارترین query سیستم (چک اعتبار هر کانکشن کاربر)
				// اول تلاش برای UNIQUE (هم سرعت هم یکپارچگی داده)؛ اگر به هر دلیلی (مثلاً داده‌ی تکراری قدیمی) شکست خورد، ایندکس معمولی جایگزین می‌شود تا حداقل سرعت query حفظ شود
				await db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid)").run();
			} catch (e) {
				try {
					await db.prepare("CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid)").run();
				} catch (e2) { }
			}
			try {
				const { results } = await db.prepare("PRAGMA table_info(users)").all();
				const existingCols = new Set((results || []).map((r) => r.name));
				const colsToAdd = [
					{ name: "advanced_frag", def: "TEXT DEFAULT NULL" },
					{ name: "cipher_suites", def: "TEXT DEFAULT NULL" },
					{ name: "tls_mask", def: "TEXT DEFAULT NULL" },
					{ name: "is_active", def: "INTEGER DEFAULT 1" },
					{ name: "last_active", def: "INTEGER" },
					{ name: "fingerprint", def: "TEXT DEFAULT 'chrome'" },
					{ name: "max_connections", def: "INTEGER" },
					{ name: "limit_req", def: "INTEGER" },
					{ name: "used_req", def: "INTEGER DEFAULT 0" },
					{ name: "ip_limit", def: "INTEGER DEFAULT NULL" },
					{ name: "active_ips", def: "TEXT DEFAULT NULL" },
					{ name: "block_porn", def: "INTEGER DEFAULT 0" },
					{ name: "block_ads", def: "INTEGER DEFAULT 0" },
					{ name: "frag_len", def: "TEXT DEFAULT '200-3000'" },
					{ name: "frag_int", def: "TEXT DEFAULT '1-2'" },
					{ name: "lifetime_used_gb", def: "REAL DEFAULT 0" },
					{ name: "user_proxy_ip", def: "TEXT DEFAULT NULL" },
					{ name: "user_proxy_iata", def: "TEXT DEFAULT NULL" },
					{ name: "user_socks5", def: "TEXT DEFAULT NULL" },
					{ name: "auto_reset_vol_days", def: "INTEGER DEFAULT 0" },
					{ name: "auto_reset_req_days", def: "INTEGER DEFAULT 0" },
					{ name: "last_reset_vol_time", def: "INTEGER DEFAULT 0" },
					{ name: "last_reset_req_time", def: "INTEGER DEFAULT 0" },
					{ name: "auto_rotate_ip", def: "INTEGER DEFAULT 1" },
					{ name: "rotate_time", def: "INTEGER DEFAULT 0" },
					{ name: "ip_operator", def: "TEXT DEFAULT 'all'" },
					{ name: "ip_count", def: "INTEGER DEFAULT 999999" },
					{ name: "last_rotate_time", def: "INTEGER DEFAULT 0" },
					{ name: "auto_rotate_user_proxy", def: "INTEGER DEFAULT 0" },
					{ name: "start_on_first_connect", def: "INTEGER DEFAULT 0" },
					{ name: "first_connection_time", def: "INTEGER DEFAULT NULL" },
					{ name: "trojan_hash", def: "TEXT DEFAULT NULL" },
					{ name: "enable_direct", def: "INTEGER DEFAULT 1" },
					{ name: "proxy_rotate_cooldowns", def: "TEXT DEFAULT '{}'" },
					{ name: "device_warning_at", def: "INTEGER DEFAULT NULL" },
					{ name: "device_warning_peak_count", def: "INTEGER DEFAULT NULL" },
					{ name: "device_warning_streak", def: "INTEGER DEFAULT 0" },
					// Early Data (فاز ۱): ستون‌های خام کاربر. تا فاز ۲ (POST/PUT /api/users و
					// SubscriptionService) این دو ستون رو نمی‌خونه/نمی‌نویسه؛ فقط با DEFAULT
					// ساخته می‌شن تا کاربرهای موجود هم early_data_enabled=0 داشته باشن (نه NULL)
					// و شرط‌های آینده (user.early_data_enabled) بدون نیاز به fallback جدا درست کار کنن.
					{ name: "early_data_enabled", def: "INTEGER DEFAULT 0" },
					{ name: "early_data_size", def: "INTEGER DEFAULT 2560" },
				];
				const stmts = [];
				for (const col of colsToAdd) {
					if (!existingCols.has(col.name)) {
						stmts.push(db.prepare(`ALTER TABLE users ADD COLUMN ${col.name} ${col.def}`));
					}
				}
				if (stmts.length > 0) {
					await db.batch(stmts);
				}
			} catch (e) { }
			try {
				await db.prepare("UPDATE users SET ip_limit = max_connections WHERE ip_limit IS NULL AND max_connections IS NOT NULL").run();
			} catch (e) { }
			try {
				// این UPDATE فقط برای backfill یک‌باره‌ی ردیف‌های قدیمی لازم بود (قبل از اضافه شدن ستون lifetime_used_gb).
				// چون schemaEnsured فقط یه فلگ حافظه‌ای isolate هست و در D1 ذخیره نمی‌شه، بدون این چک این UPDATE
				// روی هر cold start دوباره اجرا می‌شد و هر کاربر idle/صفر-مصرف رو (که lifetime_used_gb=0 هست) دوباره WRITE می‌کرد.
				// اینجا با یه فلگ ماندگار در settings، migration واقعاً فقط یک‌بار در کل عمر دیتابیس اجرا می‌شه؛
				// از دفعه‌ی دوم به بعد فقط همین یک SELECT سبک اجرا می‌شه و هیچ UPDATE ای روی users نمی‌ره.
				const migRow = await db.prepare("SELECT value FROM settings WHERE key = 'migrated_lifetime_used_gb'").first();
				if (!migRow) {
					await db.prepare("UPDATE users SET lifetime_used_gb = used_gb WHERE lifetime_used_gb = 0 OR lifetime_used_gb IS NULL").run();
					await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('migrated_lifetime_used_gb', '1')").run();
				}
			} catch (e) { }
		})();
		await schemaPromise;
		schemaEnsured = true;
	},
	async getPanelPassword(db, forceRefresh = true) {
		try {
			const row = await db.prepare("SELECT value FROM settings WHERE key = 'panel_password'").first();
			cachedPanelPassword = row && row.value ? row.value : null;
			return cachedPanelPassword;
		} catch (e) {
			return null;
		}
	},
	async setPanelPassword(db, password) {
		await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_password', ?)").bind(password).run();
		cachedPanelPassword = password;
	},
	async verifyApiAuth(request, env) {
		// --- جدید: راه دوم ورود، مخصوص پنل مادر ---
		const masterKeyHeader = request.headers.get("X-Master-Key");
		if (masterKeyHeader) {
			const path = new URL(request.url).pathname;
			if (MASTER_KEY_BLOCKED_PATHS.includes(path)) return false; // این مسیرها با کلید مادر مجاز نیستن
			const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'master_api_key'").first();
			return !!(row && row.value && masterKeyHeader === row.value);
		}
		// --- قبلی: چک کوکی، بدون تغییر ---
		const storedPasswordHash = await this.getPanelPassword(env.DB);
		if (!storedPasswordHash) return true;
		const cookies = request.headers.get("Cookie") || "";
		const sessionCookie = cookies.split(";").find((c) => c.trim().startsWith("panel_session="));
		if (!sessionCookie) return false;
		const sessionToken = sessionCookie.split("=")[1].trim();
		return sessionToken === storedPasswordHash;
	},
	async sha256(message) {
		const msgBuffer = new TextEncoder().encode(message);
		const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
	},
	async oldSha256(message) {
		const msgBuffer = new TextEncoder().encode(message);
		const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
	},
};
// Fix (device-counter bug): user rows served from the 10s auth cache (getCachedAuthUser)
// carry a possibly-stale `active_ips`. Writing that stale snapshot back to D1 on every new
// connection / heartbeat tick could silently erase other devices' entries when several
// connections for the same account land within the same 10s window (last write wins).
//
// Fix, scoped to stay cheap: only at the moment we were ALREADY about to write (the caller
// still does its own isNewIp / 15-min throttling on the cached copy - unchanged, and cheap),
// re-read just the `active_ips` column fresh from D1, merge this one IP onto THAT copy, and
// write the merge back. This keeps the extra D1 read bound to the existing write frequency
// instead of every connection/heartbeat. A per-username promise-chain lock serializes this
// within the same isolate so two near-simultaneous writes for the same user can't still race
// each other on the read step.
//
// «تأخیر هشدار تعداد دستگاه» (device_warning_at delay/streak - نگاه کنید DEVICE_WARNING_CONFIRM_STREAK
// بالای فایل): به‌جای ثبتِ فوریِ هشدار همون اولین باری که activeDeviceCount از آستانه رد
// می‌شه، device_warning_at فقط وقتی واقعاً ست می‌شه که این تعداد بار پشت‌سرهم عبور از
// آستانه دیده شده باشه. persistActiveIp (رفرش IP از قبل تأییدشده) و confirmActiveIp (تأیید
// IP تازه) هر دو از همین یه تابع استفاده می‌کنن تا این حساب یه‌جا بمونه و دوبار نوشته نشه.
function evaluateDeviceWarning(activeDeviceCount, warnThreshold, prevStreak, prevWarningAt, prevPeakCount, now) {
	const overThreshold = !!(warnThreshold && warnThreshold > 0 && activeDeviceCount > warnThreshold);
	// برگشتن به زیر آستانه (حتی یه بار) شمارش رو صفر می‌کنه - یعنی نوسانِ کوتاه دور
	// آستانه هیچ‌وقت به تنهایی هشدار نمی‌سازه، باید واقعاً پشت‌سرهم بمونه.
	const newStreak = overThreshold ? (prevStreak || 0) + 1 : 0;
	const shouldWarn = newStreak >= DEVICE_WARNING_CONFIRM_STREAK;
	// «بیشترین تعداد دستگاه» (device_warning_peak_count): همون منطق قبلی، دست‌نخورده -
	// فقط وقتی چرخه‌ی هشدارِ قبلی هنوز منقضی نشده (کمتر از ۲۴ ساعت) بیشینه نگه داشته
	// می‌شه؛ وگرنه یه چرخه‌ی تازه از همین عدد فعلی شروع می‌شه.
	const warningStillFresh = !!(prevWarningAt && now - prevWarningAt < 24 * 60 * 60 * 1000);
	const newPeakCount = warningStillFresh ? Math.max(prevPeakCount || 0, activeDeviceCount) : activeDeviceCount;
	return { shouldWarn, newStreak, newPeakCount };
}
async function persistActiveIp(env, ctx, uuid, username, clientIP, now) {
	const run = async () => {
		let freshIps = {};
		let warnThreshold = DEFAULT_DEVICE_WARNING_THRESHOLD_FALLBACK;
		let prevWarningAt = null;
		let prevPeakCount = null;
		let prevStreak = 0;
		try {
			// آستانه‌ی سراسری «هشدار تعداد دستگاه» (settings.device_warning_threshold) با همون کوئری
			// ردیف کاربر و به‌صورت subselect خونده می‌شه - بدون رفت‌وبرگشت اضافه‌ی D1.
			const row = await env.DB.prepare("SELECT active_ips, device_warning_at, device_warning_peak_count, device_warning_streak, (SELECT value FROM settings WHERE key = 'device_warning_threshold') AS dw_threshold FROM users WHERE uuid = ?").bind(uuid).first();
			freshIps = JSON.parse((row && row.active_ips) || "{}");
			warnThreshold = parseDeviceWarningThreshold(row ? row.dw_threshold : null);
			prevWarningAt = row ? row.device_warning_at : null;
			prevPeakCount = row ? row.device_warning_peak_count : null;
			prevStreak = (row && row.device_warning_streak) || 0;
		} catch (e) { }
		for (const [ip, data] of Object.entries(freshIps)) {
			const lastSeen = data && typeof data === "object" ? data.timestamp : data;
			const lastSeenNum = typeof lastSeen === "number" ? lastSeen : Number(lastSeen);
			// مقدار خراب/غیرعددی (undefined، null، رشته‌ی نامعتبر) هم «کهنه» حساب می‌شه: قبلاً
			// now - lastSeen برای این‌ها NaN می‌شد، مقایسه false برمی‌گشت و اون IP هیچ‌وقت
			// prune نمی‌شد - یعنی برای همیشه توی شمارنده‌ی دستگاه‌های آنلاین می‌موند.
			if (ip !== clientIP && (!isFinite(lastSeenNum) || now - lastSeenNum > 180000)) delete freshIps[ip];
		}
		if (freshIps[clientIP] && typeof freshIps[clientIP] === "object") {
			freshIps[clientIP].timestamp = now;
			freshIps[clientIP].count = (freshIps[clientIP].count || 0) + 1;
		} else {
			freshIps[clientIP] = { timestamp: now, count: 1 };
		}
		// «هشدار تعداد دستگاه» (admin-facing only - NOT enforcement, enforcement moved to
		// confirmActiveIp() - نگاه کنید توضیح DEVICE_CONFIRM_* بالای فایل): همین‌جا، دقیقاً
		// روی همون snapshot تازه‌ای که بالا merge شد (نه یک کپی جدا)، evaluateDeviceWarning
		// تصمیم می‌گیره که آیا device_warning_at واقعاً ست بشه یا فقط شمارش (streak) جلو بره.
		const activeDeviceCount = Object.keys(freshIps).length;
		const { shouldWarn, newStreak, newPeakCount } = evaluateDeviceWarning(activeDeviceCount, warnThreshold, prevStreak, prevWarningAt, prevPeakCount, now);
		try {
			if (shouldWarn) {
				await env.DB.prepare("UPDATE users SET active_ips = ?, last_active = ?, device_warning_at = ?, device_warning_peak_count = ?, device_warning_streak = ? WHERE uuid = ?").bind(JSON.stringify(freshIps), now, now, newPeakCount, newStreak, uuid).run();
			} else {
				await env.DB.prepare("UPDATE users SET active_ips = ?, last_active = ?, device_warning_streak = ? WHERE uuid = ?").bind(JSON.stringify(freshIps), now, newStreak, uuid).run();
			}
		} catch (e) { }
	};
	const prior = GLOBAL_ACTIVE_IPS_WRITE_LOCK.get(username) || Promise.resolve();
	const chained = prior.then(run, run);
	GLOBAL_ACTIVE_IPS_WRITE_LOCK.set(username, chained);
	if (ctx) ctx.waitUntil(chained);
	else await chained;
}
// «تأیید دستگاه» (confirmActiveIp) - طبق سیاستِ «دیده‌شده/تأییدشده» (نگاه کنید توضیح
// DEVICE_CONFIRM_* بالای فایل)، این تنها جاییه که یک IPِ *تازه* واقعاً «تأییدشده» می‌شه:
// توی active_ips نوشته می‌شه، جزو تعداد دستگاه‌ها حساب می‌شه، و به سقف «محدودیت
// کاربر»/ip_limit می‌خوره - این سقف هم از همین نسخه به بعد فقط همین‌جا (لحظه‌ی تأیید)
// چک می‌شه، نه موقع هندشیک اولیه‌ی اتصال. فقط از checkDeviceConfirmation() توی
// handlevIees صدا زده می‌شه، وقتی شرطِ «اتصال پایدار» یا «اتصال‌های کوتاهِ زیاد» رد شده
// باشه. با persistActiveIp() روی همون قفلِ per-username (GLOBAL_ACTIVE_IPS_WRITE_LOCK)
// مشترکه تا این دوتا هیچ‌وقت رو نوشتنِ همدیگه روی ستون active_ips مسابقه ندن. خروجی:
// true = تأیید شد/جا بود، false = سقف پر بود (تماس‌گیرنده باید همین اتصال رو ببنده).
async function confirmActiveIp(env, ctx, uuid, username, clientIP, now) {
	let admitted = true;
	const run = async () => {
		let freshIps = {};
		let warnThreshold = DEFAULT_DEVICE_WARNING_THRESHOLD_FALLBACK;
		let prevWarningAt = null;
		let prevPeakCount = null;
		let prevStreak = 0;
		let ipLimit = null;
		try {
			const row = await env.DB.prepare("SELECT active_ips, device_warning_at, device_warning_peak_count, device_warning_streak, ip_limit, (SELECT value FROM settings WHERE key = 'device_warning_threshold') AS dw_threshold FROM users WHERE uuid = ?").bind(uuid).first();
			freshIps = JSON.parse((row && row.active_ips) || "{}");
			warnThreshold = parseDeviceWarningThreshold(row ? row.dw_threshold : null);
			prevWarningAt = row ? row.device_warning_at : null;
			prevPeakCount = row ? row.device_warning_peak_count : null;
			prevStreak = (row && row.device_warning_streak) || 0;
			ipLimit = row ? row.ip_limit : null;
		} catch (e) { }
		for (const [ip, data] of Object.entries(freshIps)) {
			const lastSeen = data && typeof data === "object" ? data.timestamp : data;
			const lastSeenNum = typeof lastSeen === "number" ? lastSeen : Number(lastSeen);
			if (ip !== clientIP && (!isFinite(lastSeenNum) || now - lastSeenNum > 180000)) delete freshIps[ip];
		}
		if (!freshIps[clientIP]) {
			// «سقف در لحظه‌ی تأیید، نه هندشیک»: دقیقاً همون مقایسه‌ای که قبلاً موقع هندشیک
			// انجام می‌شد (>= ip_limit یعنی جا نیست)، فقط حالا اینجا و روی دیتای تازه.
			const confirmedCount = Object.keys(freshIps).length;
			if (ipLimit && ipLimit > 0 && confirmedCount >= ipLimit) {
				admitted = false;
				return;
			}
			freshIps[clientIP] = { timestamp: now, count: 1 };
		} else {
			// یه اتصال دیگه از همین (کاربر, IP) زودتر (مثلاً هم‌زمان) تأیید کرده بوده - فقط رفرش.
			if (typeof freshIps[clientIP] === "object") {
				freshIps[clientIP].timestamp = now;
				freshIps[clientIP].count = (freshIps[clientIP].count || 0) + 1;
			} else {
				freshIps[clientIP] = { timestamp: now, count: 1 };
			}
		}
		const activeDeviceCount = Object.keys(freshIps).length;
		const { shouldWarn, newStreak, newPeakCount } = evaluateDeviceWarning(activeDeviceCount, warnThreshold, prevStreak, prevWarningAt, prevPeakCount, now);
		try {
			if (shouldWarn) {
				await env.DB.prepare("UPDATE users SET active_ips = ?, last_active = ?, device_warning_at = ?, device_warning_peak_count = ?, device_warning_streak = ? WHERE uuid = ?").bind(JSON.stringify(freshIps), now, now, newPeakCount, newStreak, uuid).run();
			} else {
				await env.DB.prepare("UPDATE users SET active_ips = ?, last_active = ?, device_warning_streak = ? WHERE uuid = ?").bind(JSON.stringify(freshIps), now, newStreak, uuid).run();
			}
		} catch (e) { }
	};
	const prior = GLOBAL_ACTIVE_IPS_WRITE_LOCK.get(username) || Promise.resolve();
	const chained = prior.then(run, run);
	GLOBAL_ACTIVE_IPS_WRITE_LOCK.set(username, chained);
	if (ctx) ctx.waitUntil(chained);
	await chained;
	return admitted;
}
// «دیده‌شده/تأییدشده» - کمک‌تابع‌های DEVICE_CONFIRM_BURST_* (شرط «اتصال‌های کوتاهِ زیاد»):
// recordBurstBytes روی هر addBytes صدا زده می‌شه (فقط تا وقتی همون اتصال تأیید نشده)،
// getBurstBytes فقط می‌خونه (از checkDeviceConfirmation/هیت‌بیت). کلید همیشه
// `${username}|${clientIP}` است - نگاه کنید توضیح IP_BURST_BYTES بالای فایل.
function recordBurstBytes(key, bytes, now) {
	let entry = IP_BURST_BYTES.get(key);
	if (!entry || now - entry.windowStart > DEVICE_CONFIRM_BURST_WINDOW_MS) {
		entry = { bytes: 0, windowStart: now };
	}
	entry.bytes += bytes;
	IP_BURST_BYTES.set(key, entry);
}
function getBurstBytes(key, now) {
	const entry = IP_BURST_BYTES.get(key);
	if (!entry || now - entry.windowStart > DEVICE_CONFIRM_BURST_WINDOW_MS) return 0;
	return entry.bytes;
}
function getActiveIpCount(activeIpsJson) {
	if (!activeIpsJson) return 0;
	try {
		const activeIps = JSON.parse(activeIpsJson);
		const now = Date.now();
		let count = 0;
		for (const [ip, data] of Object.entries(activeIps)) {
			const lastSeen = data && typeof data === "object" ? data.timestamp : data;
			if (now - lastSeen <= 180000) {
				count++;
			}
		}
		return count;
	} catch (e) {
		return 0;
	}
}
// Builds the optional trailing path segment consumed by decodeInlinePanelIPs()
// (see the "inline ProxyIP" fallback feature above), from the admin-configured
// "Proxy IP" panel setting. Only ever appended where a config link would
// otherwise use the bare rawPath (no per-user location suffix) - see call sites.
function generateInlineProxyJunk(len = 10) {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	let out = "";
	for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
	return out;
}
function buildInlineProxyIpSegment(ip) {
	if (!ip || typeof ip !== "string" || !ip.trim()) return "";
	try {
		const payload = { junk: generateInlineProxyJunk(10), protocol: "vl", mode: "proxyip", panelIPs: [ip.trim()] };
		return "/" + btoa(JSON.stringify(payload)).replace(/\+/g, "-").replace(/\//g, "_");
	} catch (e) {
		return "";
	}
}
// «Proxy IP» (inline_proxy_ip) و «آیپی‌های تمیز دیگر» (other_clean_ips) همیشه با هم و در
// همون یک درخواست لازم می‌شن (ساب متنی، ساب Singbox، و رندر صفحه‌ی status). قبلاً هرکدوم
// یک SELECT جدا بودن، یعنی دو رفت‌وبرگشت D1 روی هر فچ ساب؛ حالا هر دو کلید با یک کوئری
// IN (...) خونده می‌شن - همون الگوی isGlobalReqLimitReached و GET /api/users.
// فالبک‌ها عیناً همون رفتار قبلیِ دو getter جدا هستن: «کلید اصلاً ذخیره نشده» (نصب تازه)
// فالبک می‌گیره، ولی «کلیدِ ذخیره‌شده‌ی خالی» عمداً خالی می‌مونه و فیچر خاموش می‌شه -
// به همین خاطر نبودِ ردیف با مقدارِ خالی تفکیک می‌شه، نه فقط falsy بودن مقدار.
async function getSubscriptionIpSettings(env) {
	const fallback = { inlineProxyIp: DEFAULT_INLINE_PROXY_IP_FALLBACK, otherCleanIps: DEFAULT_OTHER_CLEAN_IPS_FALLBACK.slice() };
	if (!env || !env.DB) return fallback;
	try {
		const res = await env.DB.prepare("SELECT key, value FROM settings WHERE key IN ('inline_proxy_ip','other_clean_ips')").all();
		const map = {};
		(res.results || []).forEach((r) => { map[r.key] = r.value; });
		const hasInline = Object.prototype.hasOwnProperty.call(map, "inline_proxy_ip");
		const hasOther = Object.prototype.hasOwnProperty.call(map, "other_clean_ips");
		return {
			inlineProxyIp: !hasInline ? DEFAULT_INLINE_PROXY_IP_FALLBACK : (map.inline_proxy_ip ? String(map.inline_proxy_ip).trim() : ""),
			otherCleanIps: !hasOther
				? DEFAULT_OTHER_CLEAN_IPS_FALLBACK.slice()
				: !map.other_clean_ips
					? []
					: String(map.other_clean_ips).split("\n").map((ip) => ip.trim()).filter((ip) => ip.length > 0),
		};
	} catch (e) {
		return fallback;
	}
}
// Extra always-on clean-IP addresses ("آیپی های تمیز دیگر" panel setting).
// One extra VLESS/Trojan config per entry is appended to every user's
// configs, addressed at that IP, using the same Path as the admin-configured
// "Proxy IP" inline segment (see buildInlineProxyIpSegment above), and
// named with a German flag + zero-padded index (see call sites).
// Reads the admin-editable pinned-locations list from the settings table
// (see the "لوکیشن‌ها" section of the settings modal / saveLocations() on
// the client side). Falls back to PINNED_DEFAULT_LOCATIONS_FALLBACK ONLY if the
// setting was never saved (no row / empty string) or is malformed (not valid
// JSON, or not an array) - so a fresh install (or a corrupted value) never
// breaks user provisioning.
// An EXPLICITLY saved empty list ("[]", i.e. the admin removed every pinned
// country) is respected and returned as [] - it is NOT turned back into the
// 15-country default. (Before, an empty list silently came back as the
// defaults, so "remove all countries" never actually removed anything: the
// "which countries were un-pinned" comparison saw the defaults on both sides.)
// Only valid ISO 3166-1 alpha-2 codes are kept; duplicates are dropped,
// order is preserved (this order becomes loc-0..loc-N for new users).
async function getPinnedLocationsSetting(env) {
	if (!env || !env.DB) return PINNED_DEFAULT_LOCATIONS_FALLBACK;
	try {
		const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'pinned_locations'").first();
		if (!row || !row.value) return PINNED_DEFAULT_LOCATIONS_FALLBACK;
		const parsed = JSON.parse(row.value);
		if (!Array.isArray(parsed)) return PINNED_DEFAULT_LOCATIONS_FALLBACK;
		const cleaned = [];
		for (const raw of parsed) {
			if (typeof raw !== "string") continue;
			const cc = raw.trim().toUpperCase();
			if (cc && ISO_ALPHA3_MAP[cc] && !cleaned.includes(cc)) cleaned.push(cc);
		}
		return cleaned;
	} catch (e) {
		return PINNED_DEFAULT_LOCATIONS_FALLBACK;
	}
}
// Reads the admin-editable «محدودیت کاربر» (user limit) global from settings (key
// 'user_limit'). Used as the value auto-filled into a brand-new user's ip_limit and
// max_connections columns at creation time when the request didn't carry one (see the
// POST /api/users handler). The same setting is also written onto every EXISTING user by
// POST /api/settings/bulk. Falls back to DEFAULT_USER_LIMIT_FALLBACK if never configured
// (fresh install) or malformed; an explicitly-saved 0 is respected as-is (0 = no limit,
// exactly like an empty per-user field).
async function getUserLimitSetting(env) {
	if (!env || !env.DB) return DEFAULT_USER_LIMIT_FALLBACK;
	try {
		const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'user_limit'").first();
		if (!row || row.value === null || row.value === undefined || String(row.value).trim() === "") return DEFAULT_USER_LIMIT_FALLBACK;
		const parsed = parseInt(row.value);
		return !isNaN(parsed) && parsed >= 0 ? parsed : DEFAULT_USER_LIMIT_FALLBACK;
	} catch (e) {
		return DEFAULT_USER_LIMIT_FALLBACK;
	}
}
// Parses the raw value of the admin-editable «هشدار تعداد دستگاه» (device-count warning)
// global threshold (settings key 'device_warning_threshold') - persistActiveIp reads it
// together with the user row in one query and passes the raw text here. Missing/empty/
// malformed => DEFAULT_DEVICE_WARNING_THRESHOLD_FALLBACK; an explicitly-saved 0 is respected
// (0 = the warning is off, since persistActiveIp skips the exceeded-check for a falsy value).
function parseDeviceWarningThreshold(raw) {
	if (raw === null || raw === undefined || String(raw).trim() === "") return DEFAULT_DEVICE_WARNING_THRESHOLD_FALLBACK;
	const parsed = parseInt(raw);
	return !isNaN(parsed) && parsed >= 0 ? parsed : DEFAULT_DEVICE_WARNING_THRESHOLD_FALLBACK;
}
// Reads the admin-editable «پورت» global default from settings (key
// 'default_port'). Used only to pre-fill a brand-new user's `port` column at
// creation time when the request didn't explicitly include one (see POST
// /api/users) - the *existing*-user override on save is handled separately
// in POST /api/settings/bulk. Falls back to DEFAULT_PORT_FALLBACK if never
// configured or malformed/empty.
async function getDefaultPortSetting(env) {
	if (!env || !env.DB) return DEFAULT_PORT_FALLBACK;
	try {
		const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'default_port'").first();
		if (!row || row.value === null || row.value === undefined || String(row.value).trim() === "") return DEFAULT_PORT_FALLBACK;
		return String(row.value).trim();
	} catch (e) {
		return DEFAULT_PORT_FALLBACK;
	}
}
// «پیش‌فرض‌های کاربر جدید»: همه‌ی کلیدهای new_user_* (+ global_clean_ip برای ستون
// ips) در یک کوئری. برای هر کلیدی که نبود/خالی بود (به‌جز frag_len/frag_int که
// خالی معنی‌دار دارد) مقدار NEW_USER_DEFAULTS_FALLBACK برمی‌گردد. فقط وقتی
// global_clean_ip اصلاً در settings نیست، DEFAULT_GLOBAL_CLEAN_IP_FALLBACK؛ اگر
// ادمین عمداً خالی ذخیره کرده باشد همان خالی رعایت می‌شود.
async function getNewUserDefaults(env) {
	const out = Object.assign({}, NEW_USER_DEFAULTS_FALLBACK, { global_clean_ip: DEFAULT_GLOBAL_CLEAN_IP_FALLBACK });
	if (!env || !env.DB) return out;
	try {
		const { results } = await env.DB.prepare("SELECT key, value FROM settings WHERE key LIKE 'new_user_%' OR key = 'global_clean_ip'").all();
		(results || []).forEach((r) => {
			if (r.value === null || r.value === undefined) return;
			const v = String(r.value);
			if (r.key === "global_clean_ip") { out.global_clean_ip = v; return; }
			if (!Object.prototype.hasOwnProperty.call(NEW_USER_DEFAULTS_FALLBACK, r.key)) return;
			if (v.trim() === "" && !NEW_USER_DEFAULTS_EMPTY_OK.includes(r.key)) return;
			out[r.key] = v.trim();
		});
	} catch (e) { }
	return out;
}
const SubscriptionService = {
	async generateText(user, host, env) {
		let ips = [host];
		if (user.auto_rotate_ip === 1) {
			const cachedIpsData = await getCachedIps();
			const randomIps = getRandomIps(cachedIpsData, user.ip_operator || "all", user.ip_count || 999999);
			if (randomIps.length > 0) ips = randomIps;
		}
		if (ips.length === 1 && ips[0] === host && user.ips) {
			const parsedIps = user.ips
				.split("\n")
				.map((ip) => ip.trim())
				.filter((ip) => ip.length > 0);
			if (parsedIps.length > 0) ips = parsedIps;
		}
		const ports = String(user.port || "443")
			.split(",")
			.map((p) => p.trim())
			.filter((p) => p.length > 0);
		const fp = user.fingerprint || "chrome";
		const links = [];
		let remVol = "Unlimited";
		if (user.limit_gb) {
			let liveUsedGb = (user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(user.username) || 0) / (1024 * 1024 * 1024));
			let rem = user.limit_gb - liveUsedGb;
			remVol = rem > 0 ? rem.toFixed(2) + "GB" : "0GB";
		}
		let remTime = "Unlimited";
		if (user.expiry_days) {
			if (user.start_on_first_connect === 1) {
				if (user.first_connection_time) {
					const expiryDate = new Date(user.first_connection_time + user.expiry_days * 86400000);
					const diffDays = Math.ceil((expiryDate.getTime() - Date.now()) / 86400000);
					remTime = diffDays > 0 ? diffDays + "Days" : "0Days";
				} else {
					remTime = user.expiry_days + "Days (Not Started)";
				}
			} else if (user.created_at) {
				const created = new Date(user.created_at);
				const expiryDate = new Date(created.getTime() + user.expiry_days * 86400000);
				const diffDays = Math.ceil((expiryDate.getTime() - Date.now()) / 86400000);
				remTime = diffDays > 0 ? diffDays + "Days" : "0Days";
			}
		}
		let remReq = "Unlimited";
		if (user.limit_req) {
			let liveUsedReq = (user.used_req || 0) + (USER_REQ_CACHE.get(user.username) || 0);
			let rem = user.limit_req - liveUsedReq;
			remReq = rem > 0 ? rem.toLocaleString() + "Req" : "0Req";
		}
		const rawPath = "/XYZ";
		const subIpSettings = await getSubscriptionIpSettings(env);
		const inlineProxySegment = buildInlineProxyIpSegment(subIpSettings.inlineProxyIp);
		let proxyList = [];
		try {
			if (user.user_socks5 && user.user_socks5.trim().startsWith("[")) {
				proxyList = JSON.parse(user.user_socks5);
			} else if (user.user_socks5 || user.user_proxy_ip) {
				proxyList = [user.user_socks5 || user.user_proxy_ip];
			} else {
				proxyList = [null];
			}
		} catch (e) {
			proxyList = [user.user_socks5 || user.user_proxy_ip];
		}
		if (!Array.isArray(proxyList) || proxyList.length === 0) proxyList = [];
		const allowDirect = user.enable_direct !== 0;
		if (allowDirect) {
			let hasDirect = proxyList.some(p => p === null || p === "");
			if (!hasDirect) proxyList.push(null);
		} else {
			proxyList = proxyList.filter(p => p !== null && p !== "");
		}
		if (proxyList.length === 0) proxyList = [null];
		let resolvedProxies = [];
		for (let locIdx = 0; locIdx < proxyList.length; locIdx++) {
			let proxyItem = proxyList[locIdx];
			let proxyStr = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.proxy : proxyItem;
			let countryCode = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.country : user.user_proxy_iata || "";
			if (!countryCode && proxyStr) {
				try {
					const payload = new TextEncoder().encode("GET /json/?fields=countryCode HTTP/1.1\r\nHost: ip-api.com\r\nConnection: close\r\n\r\n");
					const s = await connectProxy(proxyStr, "ip-api.com", 80, payload);
					const reader = s.readable.getReader();
					let resStr = "";
					const dec = new TextDecoder();
					const timeoutId = setTimeout(() => {
						try {
							s.close();
						} catch (e) { }
					}, 2000);
					try {
						while (true) {
							const res = await reader.read();
							if (res.done || !res.value) break;
							resStr += dec.decode(res.value, { stream: true });
							if (resStr.includes("countryCode")) break;
						}
					} finally {
						clearTimeout(timeoutId);
						try {
							s.close();
						} catch (e) { }
					}
					const jsonMatch = resStr.match(/\{[^}]*"countryCode"\s*:\s*"([^"]+)"[^}]*\}/);
					if (jsonMatch && jsonMatch[1]) countryCode = jsonMatch[1];
				} catch (e) { }
				if (!countryCode) {
					let ip = "";
					let cleanProxy = proxyStr.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
					let remain = cleanProxy;
					if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
					if (remain.startsWith("[")) {
						ip = remain.substring(1, remain.indexOf("]"));
					} else {
						const lastColon = remain.lastIndexOf(":");
						if (lastColon !== -1 && remain.indexOf(":") === lastColon) ip = remain.substring(0, lastColon);
						else ip = remain;
					}
					if (ip) {
						try {
							const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=countryCode`);
							const geoData = await geoRes.json();
							if (geoData && geoData.countryCode) countryCode = geoData.countryCode;
						} catch (e) { }
					}
				}
			}
			let flagEmoji = "🌐";
			if (countryCode) {
				const codePoints = countryCode
					.toUpperCase()
					.split("")
					.map((char) => 127397 + char.charCodeAt(0));
				try {
					flagEmoji = String.fromCodePoint(...codePoints);
				} catch (e) { }
			}
			const currentDynPath = encodeURIComponent(rawPath + (proxyItem !== null && proxyItem !== "" ? "/" + getLocationPathSegment(countryCode, locIdx) : inlineProxySegment));
			resolvedProxies.push({ flagEmoji, currentDynPath });
		}
		const connType = String(user.connection_type || "vless").toLowerCase();
		const enableVless = connType.includes("vless") || connType === "vl" + "e" + "ss" || (!connType.includes("trojan"));
		const enableTrojan = connType.includes("trojan");
		ips.forEach((ip) => {
			ports.forEach((portStr) => {
				resolvedProxies.forEach((proxy) => {
					const isTlsPort = TLS_PORTS.has(portStr);
					const tlsVal = isTlsPort ? "tls" : "none";
					let userFrag = "";
					if (user.frag_len && user.frag_int) userFrag += "&fragment=" + encodeURIComponent(user.frag_len + "," + user.frag_int + (isTlsPort ? ",tlshello" : ""));
					if (user.advanced_frag) userFrag += "&fm=" + encodeURIComponent(user.advanced_frag);
					if (isTlsPort && user.cipher_suites) userFrag += "&cs=" + encodeURIComponent(user.cipher_suites);
					if (user.tls_mask) userFrag += "&mask=" + encodeURIComponent(user.tls_mask);
						
					const tlsParams = isTlsPort ? ("&insecure=0&fp=" + fp + "&allowInsecure=0&sni=" + host) : "";

					if (enableVless) {
						const remark = proxy.flagEmoji;
						links.push("vl" + "e" + "ss://" + user.uuid + "@" + ip + ":" + portStr + "?path=" + proxy.currentDynPath + "&security=" + tlsVal + "&encryption=none&host=" + host + "&type=ws" + tlsParams + userFrag + "#" + encodeURIComponent(remark));
					}
					if (enableTrojan) {
						const trojanRemark = proxy.flagEmoji;
						links.push("trojan://" + user.uuid + "@" + ip + ":" + portStr + "?path=" + proxy.currentDynPath + "&security=" + tlsVal + "&host=" + host + "&type=ws" + tlsParams + userFrag + "#" + encodeURIComponent(trojanRemark));
					}
				});
			});
		});
		const otherCleanIps = subIpSettings.otherCleanIps;
		if (otherCleanIps.length > 0) {
			const otherPortStr = ports[0] || "443";
			const isTlsPort = TLS_PORTS.has(otherPortStr);
			const tlsVal = isTlsPort ? "tls" : "none";
			let userFrag = "";
			if (user.frag_len && user.frag_int) userFrag += "&fragment=" + encodeURIComponent(user.frag_len + "," + user.frag_int + (isTlsPort ? ",tlshello" : ""));
			if (user.advanced_frag) userFrag += "&fm=" + encodeURIComponent(user.advanced_frag);
			if (isTlsPort && user.cipher_suites) userFrag += "&cs=" + encodeURIComponent(user.cipher_suites);
			if (user.tls_mask) userFrag += "&mask=" + encodeURIComponent(user.tls_mask);
			const tlsParams = isTlsPort ? ("&insecure=0&fp=" + fp + "&allowInsecure=0&sni=" + host) : "";
			const otherDynPath = encodeURIComponent(rawPath + inlineProxySegment);
			otherCleanIps.forEach((otherIp, otherIdx) => {
				const remark = "🇩🇪 " + String(otherIdx + 1).padStart(2, "0");
				if (enableVless) {
					links.push("vl" + "e" + "ss://" + user.uuid + "@" + otherIp + ":" + otherPortStr + "?path=" + otherDynPath + "&security=" + tlsVal + "&encryption=none&host=" + host + "&type=ws" + tlsParams + userFrag + "#" + encodeURIComponent(remark));
				}
				if (enableTrojan) {
					links.push("trojan://" + user.uuid + "@" + otherIp + ":" + otherPortStr + "?path=" + otherDynPath + "&security=" + tlsVal + "&host=" + host + "&type=ws" + tlsParams + userFrag + "#" + encodeURIComponent(remark));
				}
			});
		}
		const noise = ["# System Update Feed: OK", "# Sync Code: " + Math.random().toString(36).slice(2, 10), "# Version: 2.2.0", "# Description: Secure Node Configurations", ""].join("\n");
		const plainContent = noise + links.join("\n");
		const subContent = btoa(unescape(encodeURIComponent(plainContent)));
		const downloadBytes = Math.floor((user.used_gb || 0) * 1073741824);
		const totalBytes = user.limit_gb ? Math.floor(user.limit_gb * 1073741824) : 0;
		let expireTimestamp = 0;
		if (user.expiry_days) {
			if (user.start_on_first_connect === 1) {
				if (user.first_connection_time) {
					expireTimestamp = Math.floor((user.first_connection_time + user.expiry_days * 86400000) / 1000);
				} else {
					expireTimestamp = Math.floor((Date.now() + user.expiry_days * 86400000) / 1000);
				}
			} else if (user.created_at) {
				expireTimestamp = Math.floor((new Date(user.created_at).getTime() + user.expiry_days * 86400000) / 1000);
			}
		}
		const subUserInfo = `upload=0; download=${downloadBytes}; total=${totalBytes}; expire=${expireTimestamp}`;
		return new Response(subContent, {
			headers: {
				"Content-Type": "text/plain; charset=utf-8",
				"Access-Control-Allow-Origin": "*",
				"Cache-Control": "no-store",
				"Subscription-Userinfo": subUserInfo,
			},
		});
	},
	async generateSingbox(user, host, env) {
		let ips = [host];
		if (user.auto_rotate_ip === 1) {
			const cachedIpsData = await getCachedIps();
			const randomIps = getRandomIps(cachedIpsData, user.ip_operator || "all", user.ip_count || 999999);
			if (randomIps.length > 0) ips = randomIps;
		}
		if (ips.length === 1 && ips[0] === host && user.ips) {
			const parsedIps = user.ips.split("\n").map((ip) => ip.trim()).filter((ip) => ip.length > 0);
			if (parsedIps.length > 0) ips = parsedIps;
		}
		const ports = String(user.port || "443").split(",").map((p) => p.trim()).filter((p) => p.length > 0);
		const fp = user.fingerprint || "chrome";
		const rawPath = "/XYZ";
		const subIpSettings = await getSubscriptionIpSettings(env);
		const inlineProxySegment = buildInlineProxyIpSegment(subIpSettings.inlineProxyIp);

		let proxyList = [];
		try {
			if (user.user_socks5 && user.user_socks5.trim().startsWith("[")) {
				proxyList = JSON.parse(user.user_socks5);
			} else if (user.user_socks5 || user.user_proxy_ip) {
				proxyList = [user.user_socks5 || user.user_proxy_ip];
			} else {
				proxyList = [null];
			}
		} catch (e) {
			proxyList = [user.user_socks5 || user.user_proxy_ip];
		}
		if (!Array.isArray(proxyList) || proxyList.length === 0) proxyList = [null];
		const allowDirect = user.enable_direct !== 0;
		if (allowDirect) {
			let hasDirect = proxyList.some(p => p === null || p === "");
			if (!hasDirect) proxyList.push(null);
		} else {
			proxyList = proxyList.filter(p => p !== null && p !== "");
		}
		if (proxyList.length === 0) proxyList = [null];

		const outbounds = [];
		const connType = String(user.connection_type || "vless").toLowerCase();
		const enableVless = connType.includes("vless") || connType === "vless" || (!connType.includes("trojan"));
		const enableTrojan = connType.includes("trojan");

		let locIdx = 0;
		for (let proxyItem of proxyList) {
			const countryCode = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.country : "";
			const currentDynPath = rawPath + (proxyItem !== null && proxyItem !== "" ? "/" + getLocationPathSegment(countryCode, locIdx) : inlineProxySegment);
			ips.forEach((ip) => {
				ports.forEach((portStr) => {
					const isTlsPort = TLS_PORTS.has(portStr);
					const sni = user.tls_mask || host;
					const safeFp = (fp === "unsafe") ? "chrome" : fp;
					
					if (enableVless) {
						let outbound = {
							type: "vless",
							tag: `ZEUS-VLESS-${ip}-${portStr}-loc${locIdx}`,
							server: ip,
							server_port: parseInt(portStr),
							uuid: user.uuid,
							packet_encoding: "xudp",
							transport: {
								type: "ws",
								path: currentDynPath,
								headers: { Host: host }
							}
						};
						
						if (isTlsPort) {
							outbound.tls = {
								enabled: true,
								server_name: sni,
								insecure: false,
								utls: { enabled: true, fingerprint: safeFp }
							};
						}
						outbounds.push(outbound);
					}
					if (enableTrojan) {
						let outbound = {
							type: "trojan",
							tag: `ZEUS-Trojan-${ip}-${portStr}-loc${locIdx}`,
							server: ip,
							server_port: parseInt(portStr),
							password: user.uuid,
							transport: {
								type: "ws",
								path: currentDynPath,
								headers: { Host: host }
							}
						};
						
						if (isTlsPort) {
							outbound.tls = {
								enabled: true,
								server_name: sni,
								insecure: false,
								utls: { enabled: true, fingerprint: safeFp }
							};
						}
						outbounds.push(outbound);
					}
				});
			});
			locIdx++;
		}

		const otherCleanIps = subIpSettings.otherCleanIps;
		if (otherCleanIps.length > 0) {
			const otherPortStr = ports[0] || "443";
			const isTlsPort = TLS_PORTS.has(otherPortStr);
			const sni = user.tls_mask || host;
			const safeFp = (fp === "unsafe") ? "chrome" : fp;
			const otherDynPath = rawPath + inlineProxySegment;
			otherCleanIps.forEach((otherIp, otherIdx) => {
				const flagTag = "🇩🇪 " + String(otherIdx + 1).padStart(2, "0");
				if (enableVless) {
					let outbound = {
						type: "vless",
						tag: flagTag + (enableTrojan ? " (VLESS)" : ""),
						server: otherIp,
						server_port: parseInt(otherPortStr),
						uuid: user.uuid,
						packet_encoding: "xudp",
						transport: { type: "ws", path: otherDynPath, headers: { Host: host } }
					};
					if (isTlsPort) {
						outbound.tls = { enabled: true, server_name: sni, insecure: false, utls: { enabled: true, fingerprint: safeFp } };
					}
					outbounds.push(outbound);
				}
				if (enableTrojan) {
					let outbound = {
						type: "trojan",
						tag: flagTag + (enableVless ? " (Trojan)" : ""),
						server: otherIp,
						server_port: parseInt(otherPortStr),
						password: user.uuid,
						transport: { type: "ws", path: otherDynPath, headers: { Host: host } }
					};
					if (isTlsPort) {
						outbound.tls = { enabled: true, server_name: sni, insecure: false, utls: { enabled: true, fingerprint: safeFp } };
					}
					outbounds.push(outbound);
				}
			});
		}

		const outboundsList = outbounds.map(o => o.tag);

		let targetDns = "udp://8.8.8.8";
		if (user.block_porn === 1 && user.block_ads === 1) {
			targetDns = "udp://94.140.14.15";
		} else if (user.block_porn === 1) {
			targetDns = "udp://1.1.1.3";
		} else if (user.block_ads === 1) {
			targetDns = "udp://94.140.14.14";
		}

		const config = {
			log: { disabled: false, level: "info" },
			dns: {
				servers: [
					{
						tag: "remote-dns",
						address: targetDns,
						detour: outboundsList.length > 0 ? "proxy" : "direct"
					}
				],
				final: "remote-dns",
				independent_cache: true
			},
			inbounds: [
				{
					type: "tun",
					tag: "tun-in",
					interface_name: "tun0",
					address: [
						"172.19.0.1/30",
						"fdfe:dcba:9876::1/126"
					],
					auto_route: true,
					strict_route: true,
					stack: "mixed"
				}
			],
			outbounds: [
				{
					type: "selector",
					tag: "proxy",
					outbounds: outboundsList.length > 0 ? outboundsList : ["direct"]
				},
				...outbounds,
				{ type: "direct", tag: "direct" },
				{ type: "block", tag: "block" }
			],
			route: {
				rules: [
					{ protocol: "dns", action: "hijack-dns" },
					{ port: 53, action: "hijack-dns" },
					{ protocol: "icmp", outbound: "direct" }
				],
				auto_detect_interface: true,
				final: outboundsList.length > 0 ? "proxy" : "direct"
			}
		};

		return new Response(JSON.stringify(config, null, 2), {
			headers: {
				"Content-Type": "application/json; charset=utf-8",
				"Access-Control-Allow-Origin": "*",
				"Cache-Control": "no-store"
			}
		});
	}
}
async function flushExpiredTraffic(env) {
	const now = Date.now();
	for (const [key, val] of DNS_CACHE.entries()) {
		if (now > val.expires) DNS_CACHE.delete(key);
	}
	for (const [ip, record] of LOGIN_ATTEMPTS.entries()) {
		if (now - record.lastAttempt > 900000) LOGIN_ATTEMPTS.delete(ip);
	}
	for (const [key, entry] of IP_BURST_BYTES.entries()) {
		if (now - entry.windowStart > DEVICE_CONFIRM_BURST_WINDOW_MS) IP_BURST_BYTES.delete(key);
	}
	const allUsers = new Set([...GLOBAL_TRAFFIC_CACHE.keys(), ...USER_REQ_CACHE.keys()]);
	// قبلاً به ازای هر کاربر یک UPDATE جدا + یک UPSERT جدای daily_traffic زده می‌شد، یعنی برای N
	// کاربرِ در انتظار، 2N رفت‌وبرگشت پشت‌سرهم به D1. حالا همه‌ی UPDATE ها جمع می‌شن و با یک
	// db.batch() در یک رفت‌وبرگشت اجرا می‌شن و مجموع مصرف با یک UPSERT واحد ثبت می‌شه.
	// تعداد ردیف‌های نوشته‌شده (هزینه‌ی write در D1) دقیقاً مثل قبله، فقط round-trip ها کم شده.
	const pendingFlush = [];
	const flushStmts = [];
	let batchDeltaGb = 0;
	for (const uname of allUsers) {
		const cachedBytes = GLOBAL_TRAFFIC_CACHE.get(uname) || 0;
		const cachedReqs = USER_REQ_CACHE.get(uname) || 0;
		const activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 0;
		if (cachedBytes <= 0 && cachedReqs <= 0) {
			GLOBAL_TRAFFIC_CACHE.delete(uname);
			USER_REQ_CACHE.delete(uname);
			if (activeCount <= 0) {
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname + "_hb");
			}
			continue;
		}
		if (GLOBAL_WRITE_LOCK.get(uname)) continue;
		const lastActive = GLOBAL_LAST_ACTIVE_WRITE.get(uname) || 0;
		if (activeCount <= 0 || now - lastActive > 60000) {
			GLOBAL_WRITE_LOCK.set(uname, true);
			GLOBAL_TRAFFIC_CACHE.set(uname, 0);
			USER_REQ_CACHE.set(uname, 0);
			const deltaGb = cachedBytes / (1024 * 1024 * 1024);
			batchDeltaGb += deltaGb;
			pendingFlush.push({ uname, cachedBytes, cachedReqs, activeCount });
			flushStmts.push(env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ?, last_active = ? WHERE username = ?").bind(deltaGb, deltaGb, cachedReqs, now, uname));
		}
	}
	if (flushStmts.length === 0) return;
	try {
		await env.DB.batch(flushStmts);
		await recordDailyTraffic(env, null, batchDeltaGb);
	} catch (e) {
		console.error(e.message);
		// برگردوندن مقدارهای commit-نشده به کش - دقیقاً همون کاری که مسیر اصلی نوشتن ترافیک
		// (writeTask داخل handlevIees) از قبل می‌کرد. بدون این، اگر نوشتن شکست می‌خورد (مثلاً
		// اتمام سهمیه‌ی روزانه‌ی D1) مصرفِ همون بازه برای همیشه پاک می‌شد، چون کش قبل از
		// نوشتن صفر شده بود.
		for (const p of pendingFlush) {
			GLOBAL_TRAFFIC_CACHE.set(p.uname, (GLOBAL_TRAFFIC_CACHE.get(p.uname) || 0) + p.cachedBytes);
			USER_REQ_CACHE.set(p.uname, (USER_REQ_CACHE.get(p.uname) || 0) + p.cachedReqs);
		}
	} finally {
		for (const p of pendingFlush) {
			GLOBAL_WRITE_LOCK.delete(p.uname);
			if (p.activeCount <= 0) {
				GLOBAL_LAST_ACTIVE_WRITE.delete(p.uname);
				GLOBAL_LAST_ACTIVE_WRITE.delete(p.uname + "_hb");
			}
		}
	}
}
// Decodes an optional trailing path segment shaped like base64(JSON), e.g. the
// segment after "/XYZ/" in ".../XYZ/eyJqdW5rIjoi...". The JSON looks like
// {"junk":"...","protocol":"vl","mode":"proxyip","panelIPs":["1.2.3.4"]}.
// This lets one specific config link carry its own ProxyIP fallback list
// inline, instead of relying only on this user's stored user_proxy_ip/user_socks5.
// Anything that isn't valid base64/JSON in this exact shape returns null, so
// ordinary paths ("/XYZ", "/XYZ/loc-3", "/XYZ/K-a-z", ...) are unaffected.
// Reuses the same private/reserved-address filter as the real destination check
// above, so this can't be used to make the worker connect out to an internal address.
const INLINE_PANEL_IP_BLOCKED_RE = /^(0\.|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|localhost$|::1|::ffff:|fd[0-9a-f]{2}:|fe80:)/i;
function decodeInlinePanelIPs(segment) {
	if (!segment || segment.length < 8) return null;
	try {
		const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
		const decoded = JSON.parse(atob(normalized));
		if (!decoded || typeof decoded !== "object" || decoded.mode !== "proxyip" || !Array.isArray(decoded.panelIPs)) {
			return null;
		}
		const ips = decoded.panelIPs
			.filter((ip) => typeof ip === "string" && ip.trim() && !INLINE_PANEL_IP_BLOCKED_RE.test(ip.trim()))
			.map((ip) => ip.trim());
		return ips.length ? ips : null;
	} catch (e) {
		return null;
	}
}
function getSelectedUserProxy(userSocks5, request) {
	if (!userSocks5) return "";
	let proxyList = [];
	try {
		if (userSocks5.trim().startsWith("[")) {
			proxyList = JSON.parse(userSocks5);
		} else {
			proxyList = [userSocks5];
		}
	} catch (e) {
		proxyList = [userSocks5];
	}
	if (!Array.isArray(proxyList) || proxyList.length === 0) return "";
	let idx = -1;
	if (request) {
		try {
			const url = new URL(request.url);
			// New format: last path segment is a path code for any ISO country
			// (see getLocationPathSegment/getCountryForPathSegment near the top
			// of the file) - map it back to the country, then find that
			// country's slot in this user's own proxy list. Falls back to the
			// legacy "/loc-N" suffix (or a "?loc=" query param) for any
			// already-issued link, or any segment that isn't a valid country path.
			const segments = url.pathname.split("/").filter(Boolean);
			const lastSeg = decodeURIComponent(segments[segments.length - 1] || "");
			const countryForCode = getCountryForPathSegment(lastSeg);
			if (countryForCode) {
				idx = proxyList.findIndex((p) => typeof p === "object" && p !== null && (p.country || "").toUpperCase() === countryForCode);
			} else {
				const pathMatch = url.pathname.match(/\/loc-(\d+)/);
				if (pathMatch) {
					idx = parseInt(pathMatch[1], 10);
				} else {
					const locParam = url.searchParams.get("loc");
					if (locParam !== null && !isNaN(Number(locParam))) {
						idx = parseInt(locParam, 10);
					}
				}
			}
		} catch (e) { }
	}
	if (idx === -1) return "";
	const selected = proxyList[idx] || proxyList[0];
	return typeof selected === "object" ? selected.proxy || "" : String(selected || "");
}
async function handlevIees(env, storedData = null, ctx = null, request = null) {
	let rawClientIP = request ? request.headers.get("CF-Connecting-IP") || "unknown" : "unknown";
	let clientIP = rawClientIP;
	if (rawClientIP !== "unknown") {
		if (rawClientIP.includes(":")) {
			const parts = rawClientIP.split(":");
			if (parts.length >= 4) {
				clientIP = parts.slice(0, 4).join(":") + "::/64";
			}
		} else if (rawClientIP.includes(".")) {
			const parts = rawClientIP.split(".");
			if (parts.length === 4) {
				clientIP = parts.slice(0, 3).join(".") + ".0/24";
			}
		}
	}
	const socketPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(socketPair);
	serverSock.accept();
	serverSock.binaryType = "arraybuffer";
	let username = null;
	let validUUID = null;
	let targetDns = "8.8.4.4";
	let targetDoh = "https://cloudflare-dns.com/dns-query";
	// «دیده‌شده/تأییدشده» (device seen/confirmed - نگاه کنید توضیح DEVICE_CONFIRM_* بالای
	// فایل): وضعیتِ محلیِ همین یک اتصال، بین addBytes/هیت‌بیت/بلاکِ پارسِ هدر مشترکه.
	// connectionStartTime همون لحظه‌ی accept شدنِ سوکته - معیار «حداقل ۱۰ ثانیه باز بمونه».
	const connectionStartTime = Date.now();
	let connectionBytesSoFar = 0;
	let deviceConfirmed = false;
	let deviceConfirmInFlight = false;
	function addBytes(bytes) {
		if (bytes <= 0) return;
		if (!username) {
			uncountedBytes += bytes;
			return;
		}
		if (uncountedBytes > 0) {
			bytes += uncountedBytes;
			uncountedBytes = 0;
		}
		connectionBytesSoFar += bytes;
		if (!deviceConfirmed && clientIP && clientIP !== "unknown") {
			recordBurstBytes(username + "|" + clientIP, bytes, Date.now());
			checkDeviceConfirmation();
		}
		let current = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
		GLOBAL_TRAFFIC_CACHE.set(username, current + bytes);
		GLOBAL_LAST_ACTIVE_WRITE.set(username, Date.now());
		if (GLOBAL_WRITE_LOCK.get(username)) return;
		let lastDbWrite = GLOBAL_LAST_DB_WRITE.get(username) || 0;
		let now = Date.now();
		let thresholdBytes = 500 * 1024 * 1024;
		if ((current >= thresholdBytes && now - lastDbWrite > 180000) || (current > 0 && now - lastDbWrite > 900000)) {
			GLOBAL_WRITE_LOCK.set(username, true);
			let toCommit = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
			let toCommitReq = USER_REQ_CACHE.get(username) || 0;
			if (toCommit <= 0 && toCommitReq <= 0) {
				GLOBAL_WRITE_LOCK.set(username, false);
				return;
			}
			GLOBAL_TRAFFIC_CACHE.set(username, (GLOBAL_TRAFFIC_CACHE.get(username) || 0) - toCommit);
			USER_REQ_CACHE.set(username, (USER_REQ_CACHE.get(username) || 0) - toCommitReq);
			GLOBAL_LAST_DB_WRITE.set(username, now);
			let deltaGb = toCommit / (1024 * 1024 * 1024);
			let writeTask = async () => {
				try {
					await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ?, last_active = ? WHERE username = ?").bind(deltaGb, deltaGb, toCommitReq, now, username).run();
					await recordDailyTraffic(env, ctx, deltaGb);
				} catch (e) {
					console.error(e.message);
					GLOBAL_TRAFFIC_CACHE.set(username, (GLOBAL_TRAFFIC_CACHE.get(username) || 0) + toCommit);
					USER_REQ_CACHE.set(username, (USER_REQ_CACHE.get(username) || 0) + toCommitReq);
				} finally {
					GLOBAL_WRITE_LOCK.set(username, false);
				}
			};
			if (ctx) ctx.waitUntil(writeTask());
			else writeTask();
		}
	}
	let isOfflineSet = false;
	let hasCountedAsActive = false;
	const setOffline = () => {
		if (isOfflineSet) return;
		isOfflineSet = true;
		const uname = username;
		if (!uname) return;
		let activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 0;
		if (hasCountedAsActive) {
			activeCount = Math.max(0, activeCount - 1);
		}
		if (activeCount <= 0) {
			ACTIVE_CONNECTIONS_COUNT.delete(uname);
			let cachedBytes = GLOBAL_TRAFFIC_CACHE.get(uname) || 0;
			let cachedReqs = USER_REQ_CACHE.get(uname) || 0;
			let nowOff = Date.now();
			let lastWrite = GLOBAL_LAST_DB_WRITE.get(uname) || 0;
			let shouldCommit = (cachedBytes >= 20 * 1024 * 1024) || (nowOff - lastWrite > 600000) || (cachedReqs >= 20);
			if (shouldCommit && (cachedBytes > 0 || cachedReqs > 0) && !GLOBAL_WRITE_LOCK.get(uname)) {
				GLOBAL_WRITE_LOCK.set(uname, true);
				GLOBAL_LAST_DB_WRITE.set(uname, nowOff);
				GLOBAL_TRAFFIC_CACHE.set(uname, (GLOBAL_TRAFFIC_CACHE.get(uname) || 0) - cachedBytes);
				USER_REQ_CACHE.set(uname, (USER_REQ_CACHE.get(uname) || 0) - cachedReqs);
				const deltaGb = cachedBytes / (1024 * 1024 * 1024);
				const writeTask = async () => {
					try {
						await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ?, last_active = ? WHERE username = ?").bind(deltaGb, deltaGb, cachedReqs, nowOff, uname).run();
						await recordDailyTraffic(env, ctx, deltaGb);
					} catch (e) {
						console.error(e.message);
						GLOBAL_TRAFFIC_CACHE.set(uname, (GLOBAL_TRAFFIC_CACHE.get(uname) || 0) + cachedBytes);
						USER_REQ_CACHE.set(uname, (USER_REQ_CACHE.get(uname) || 0) + cachedReqs);
					} finally {
						GLOBAL_WRITE_LOCK.delete(uname);
						GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
					}
				};
				if (ctx) {
					ctx.waitUntil(writeTask());
				} else {
					writeTask();
				}
			} else {
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
			}
		} else {
			ACTIVE_CONNECTIONS_COUNT.set(uname, activeCount);
		}
	};
	// «دیده‌شده/تأییدشده» (نگاه کنید توضیح DEVICE_CONFIRM_* بالای فایل): فقط تصمیم
	// می‌گیره که آیا شرایط تأیید (اتصال پایدار یا اتصال‌های کوتاهِ زیاد) رسیده یا نه -
	// از addBytes (هر بار دیتا رد بشه) و از هیت‌بیت (هر ~۲۰-۲۵ ثانیه، برای اتصال‌های
	// کم‌حجمی که addBytes به تنهایی زود بهشون نمی‌رسه) صدا زده می‌شه. تا وقتی شرط رد
	// نشده کاملاً بی‌اثره - نه D1 می‌خونه/می‌نویسه، نه چیزی رو کند می‌کنه. فقط وقتی
	// واقعاً رد بشه یک بار confirmActiveIp (تنها جایی که الان سقف ip_limit رو واقعاً
	// اعمال می‌کنه) صدا زده می‌شه.
	const checkDeviceConfirmation = () => {
		if (deviceConfirmed || deviceConfirmInFlight) return;
		if (!username || !validUUID || !clientIP || clientIP === "unknown") return;
		const nowT = Date.now();
		const stableOk = (nowT - connectionStartTime >= DEVICE_CONFIRM_MIN_DURATION_MS) && (connectionBytesSoFar >= DEVICE_CONFIRM_MIN_BYTES);
		const burstOk = getBurstBytes(username + "|" + clientIP, nowT) >= DEVICE_CONFIRM_BURST_BYTES;
		if (!stableOk && !burstOk) return;
		deviceConfirmInFlight = true;
		const task = (async () => {
			try {
				const admitted = await confirmActiveIp(env, ctx, validUUID, username, clientIP, nowT);
				if (admitted) {
					deviceConfirmed = true;
					// اگه تا وقتی D1 round-trip بالا تموم بشه همین اتصال از قبل بسته شده باشه
					// (setOffline زودتر اجرا شده)، شمارنده‌ی سوکت‌های زنده رو دست نمی‌زنیم -
					// وگرنه یه شمارشِ اضافه‌ی «شبح» می‌مونه که هیچ‌وقت کم نمی‌شه.
					if (!hasCountedAsActive && !isOfflineSet) {
						let activeCount = ACTIVE_CONNECTIONS_COUNT.get(username) || 0;
						ACTIVE_CONNECTIONS_COUNT.set(username, activeCount + 1);
						hasCountedAsActive = true;
					}
				} else {
					// سقف «محدودیت کاربر» پره - طبق سیاست، دقیقاً همین‌جا (لحظه‌ی تأیید) اعمال
					// می‌شه، نه موقع هندشیک؛ نتیجه: تست‌های پینگِ کوتاه هیچ‌وقت به اینجا نمی‌رسن
					// (رد نمی‌شن)، ولی استفاده‌ی واقعی‌ای که جا نداره همین‌جا قطع می‌شه.
					closeSocketQuietly(serverSock);
				}
			} catch (e) {
			} finally {
				deviceConfirmInFlight = false;
			}
		})();
		if (ctx) ctx.waitUntil(task);
	};
	let heartbeat;
	const runHeartbeat = async () => {
		if (serverSock.readyState === WebSocket.OPEN) {
			try {
				if (!validUUID || !username) {
					heartbeat = setTimeout(runHeartbeat, Math.floor(Math.random() * 5000) + 20000);
					return;
				}
				const nowTime = Date.now();
				const lastCheck = GLOBAL_LAST_ACTIVE_WRITE.get(username + "_hb") || 0;
				if (nowTime - lastCheck >= 180000) {
					GLOBAL_LAST_ACTIVE_WRITE.set(username + "_hb", nowTime);
					let user = await getCachedAuthUser("u", validUUID);
					if (user === undefined) {
						user = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(validUUID).first();
						putCachedAuthUser(ctx, "u", validUUID, user || null);
					}
					let isExpired = false;
					let isIpLimitExpired = false;
					let updatedActiveIps = null;
					if (!user || user.is_active === 0) {
						isExpired = true;
					} else {
						const liveGb = (user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(username) || 0) / (1024 * 1024 * 1024));
						if (user.limit_gb && liveGb >= user.limit_gb) isExpired = true;
						if (user.limit_req && user.used_req + (USER_REQ_CACHE.get(username) || 0) >= user.limit_req) isExpired = true;
						if (user.expiry_days) {
							if (user.start_on_first_connect === 1) {
								if (user.first_connection_time) {
									const expiryDate = new Date(user.first_connection_time + user.expiry_days * 86400000);
									if (nowTime > expiryDate.getTime()) isExpired = true;
								}
							} else if (user.created_at) {
								const expiryDate = new Date(new Date(user.created_at).getTime() + user.expiry_days * 86400000);
								if (nowTime > expiryDate.getTime()) isExpired = true;
							}
						}
						if (!isExpired && clientIP && clientIP !== "unknown") {
							if (!deviceConfirmed) {
								// «دیده‌شده/تأییدشده»: این اتصال هنوز تأیید نشده - این هیت‌بیت فقط یه
								// فرصت دیگه‌ست تا شرایط تأیید (DEVICE_CONFIRM_*) چک بشه، بدون اینکه
								// مستقیم چیزی توی activeIps نوشته بشه یا سقف اعمال بشه (اون کار فقط
								// با checkDeviceConfirmation/confirmActiveIp انجام می‌شه).
								checkDeviceConfirmation();
							} else {
								let activeIps = {};
								try {
									activeIps = JSON.parse(user.active_ips || "{}");
								} catch (e) { }
								let hasChanges = false;
								let needsDbUpdateForTimestamp = false;

								for (const [ip, data] of Object.entries(activeIps)) {
									const lastSeen = data && typeof data === "object" ? data.timestamp : data;
									if (nowTime - lastSeen > 180000 && ip !== clientIP) {
										delete activeIps[ip];
										hasChanges = true;
									}
								}
								if (!activeIps[clientIP]) {
									activeIps[clientIP] = { timestamp: nowTime, count: 1 };
									hasChanges = true;
								} else {
									const currentData = activeIps[clientIP];
									const lastSeen = typeof currentData === "object" ? currentData.timestamp : currentData;
									if (nowTime - lastSeen > 150000) {
										if (typeof activeIps[clientIP] === "object") {
											activeIps[clientIP].timestamp = nowTime;
										} else {
											activeIps[clientIP] = { timestamp: nowTime, count: 1 };
										}
										needsDbUpdateForTimestamp = true;
									}
								}
								// «سقف در لحظه‌ی تأیید، نه هندشیک/هیت‌بیت»: ip_limit دیگه اینجا (رفرشِ
								// یه دستگاهِ از قبل تأییدشده) چک نمی‌شه - فقط توی confirmActiveIp، یه
								// بار، موقع تأیید. نگاه کنید توضیح DEVICE_CONFIRM_* بالای فایل.
								if (hasChanges || needsDbUpdateForTimestamp) updatedActiveIps = true;
							}
						}
					}
					if (isExpired) {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(validUUID).run();
						await invalidateUserAuthCache(ctx, validUUID);
						clearTimeout(heartbeat);
						closeSocketQuietly(serverSock);
						return;
					}
					// محدودیت کل ریکوئست روزانه‌ی اکانت: بر خلاف بالا، عمداً هیچ فیلدی روی users نوشته
					// نمی‌شه (کاربر is_active می‌مونه) - فقط همین سوکت باز بسته می‌شه. با رد شدن تاریخ
					// UTC، isGlobalReqLimitReached خودش false برمی‌گرده و کاربر می‌تونه دوباره وصل بشه.
					if (await isGlobalReqLimitReached(env, ctx)) {
						clearTimeout(heartbeat);
						closeSocketQuietly(serverSock);
						return;
					}
					if (isIpLimitExpired) {
						/* Bypassed: clearTimeout(heartbeat); closeSocketQuietly(serverSock); return; */
					}
					if (updatedActiveIps) {
						GLOBAL_LAST_DB_WRITE.set(username, nowTime);
						GLOBAL_LAST_ACTIVE_WRITE.set(username, nowTime);
						await persistActiveIp(env, ctx, validUUID, username, clientIP, nowTime);
					} else if (nowTime - (GLOBAL_LAST_DB_WRITE.get(username) || 0) >= 900000) {
						GLOBAL_LAST_DB_WRITE.set(username, nowTime);
						await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(nowTime, username).run();
					}
				}
			} catch (e) { }
			heartbeat = setTimeout(runHeartbeat, Math.floor(Math.random() * 5000) + 20000);
		} else {
			clearTimeout(heartbeat);
		}
	};
	heartbeat = setTimeout(runHeartbeat, Math.floor(Math.random() * 5000) + 20000);
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let reqUUID = null;
	let inlinePanelIPs = null; // optional per-connection ProxyIP fallback list, decoded from the request path (see decodeInlinePanelIPs)
	let isHeaderParsed = false;
	let isHeaderParsing = false;
	let isDnsQuery = false;
	let isTrojanProto = false;
	let chunkBuffer = new Uint8Array(0);
	let uncountedBytes = 0;
	let wsChain = Promise.resolve();
	let wsStopped = false,
		wsFailed = false,
		wsFinished = false;
	let wsQueueBytes = 0,
		wsQueueItems = 0;
	let currentSocketWriter = null,
		activeRemoteWriter = null;
	const releaseRemoteWriter = () => {
		if (activeRemoteWriter) {
			try {
				activeRemoteWriter.releaseLock();
			} catch (e) { }
			activeRemoteWriter = null;
		}
		currentSocketWriter = null;
	};
	const getRemoteWriter = () => {
		const s = remoteConnWrapper.socket;
		if (!s) return null;
		if (s !== currentSocketWriter) {
			releaseRemoteWriter();
			currentSocketWriter = s;
			activeRemoteWriter = s.writable.getWriter();
		}
		return activeRemoteWriter;
	};
	const upstreamQueue = createUpstreamQueue({
		getWriter: getRemoteWriter,
		releaseWriter: releaseRemoteWriter,
		retryConnect: async () => {
			if (typeof remoteConnWrapper.retryConnect === "function") {
				await remoteConnWrapper.retryConnect();
			}
		},
		closeConnection: () => {
			try {
				remoteConnWrapper.socket?.close();
			} catch (e) { }
			closeSocketQuietly(serverSock);
		},
		name: "vIeesWSQueue",
	});
	const writeToRemote = async (chunk, allowRetry = true) => {
		return upstreamQueue.writeAndAwait(chunk, allowRetry);
	};
	const processWsMessage = async (chunk) => {
		const bytes = chunk.byteLength || 0;
		addBytes(bytes);
		if (isDnsQuery) {
			if (isTrojanProto) {
				await forwardTrojanUDP(chunk, serverSock, addBytes, targetDns);
			} else {
				await forwardvIeesUDP(chunk, serverSock, null, addBytes, targetDns);
			}
			return;
		}
		if (isHeaderParsed) {
			if (remoteConnWrapper.connectingPromise) {
				await remoteConnWrapper.connectingPromise;
			}
			await writeToRemote(chunk);
			return;
		}
		if (!isHeaderParsed) {
			chunkBuffer = concatBytes(chunkBuffer, chunk);
			
			let isTrojan = false;
			if (chunkBuffer.byteLength >= 58 && chunkBuffer[56] === 0x0D && chunkBuffer[57] === 0x0A) {
				const checkHex = TEXT_DECODER.decode(chunkBuffer.slice(0, 56)).toLowerCase();
				if (/^[0-9a-f]{56}$/.test(checkHex)) {
					isTrojan = true;
				}
			}
			let cmd = 0;
			let port = 0;
			let addrType = 0;
			let addr = "";
			let rawData = null;
			let respHeader = null;
			let userLookupKey = null;
			if (isTrojan) {
				if (chunkBuffer.byteLength < 60) return;
				const hexHash = TEXT_DECODER.decode(chunkBuffer.slice(0, 56)).toLowerCase();
				userLookupKey = hexHash;
				let offset = 58;
				cmd = chunkBuffer[offset++];
				addrType = chunkBuffer[offset++];
				if (addrType === 1) {
					if (chunkBuffer.byteLength < offset + 4 + 2 + 2) return;
					addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
				} else if (addrType === 3) {
					if (chunkBuffer.byteLength < offset + 1) return;
					const domainLen = chunkBuffer[offset++];
					if (chunkBuffer.byteLength < offset + domainLen + 2 + 2) return;
					addr = TEXT_DECODER.decode(chunkBuffer.slice(offset, offset + domainLen));
					offset += domainLen;
				} else if (addrType === 4) {
					if (chunkBuffer.byteLength < offset + 16 + 2 + 2) return;
					const v6 = [];
					for (let i = 0; i < 8; i++) {
						v6.push(((chunkBuffer[offset++] << 8) | chunkBuffer[offset++]).toString(16));
					}
					addr = v6.join(":");
				} else {
					serverSock.close();
					return;
				}
				port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
				if (chunkBuffer.byteLength < offset + 2) return;
				if (chunkBuffer[offset] !== 0x0D || chunkBuffer[offset + 1] !== 0x0A) {
					serverSock.close();
					return;
				}
				offset += 2;
				rawData = chunkBuffer.slice(offset);
				respHeader = null;
			} else {
				if (chunkBuffer.byteLength < 24) return;
				let optLen = chunkBuffer[17];
				let requiredLen = 18 + optLen + 4;
				if (chunkBuffer.byteLength < requiredLen) return;
				addrType = chunkBuffer[18 + optLen + 3];
				if (addrType === 1) {
					requiredLen += 4;
				} else if (addrType === 2) {
					requiredLen += 1;
					if (chunkBuffer.byteLength < requiredLen) return;
					requiredLen += chunkBuffer[18 + optLen + 4];
				} else if (addrType === 3) {
					requiredLen += 16;
				} else {
					serverSock.close();
					return;
				}
				if (chunkBuffer.byteLength < requiredLen) return;
				reqUUID = extractUUIDFromvIees(chunkBuffer);
				if (!reqUUID) {
					serverSock.close();
					return;
				}
				userLookupKey = reqUUID;
				let offset = 17;
				optLen = chunkBuffer[offset++];
				offset += optLen;
				cmd = chunkBuffer[offset++];
				port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
				addrType = chunkBuffer[offset++];
				if (addrType === 1) {
					addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
				} else if (addrType === 2) {
					const domainLen = chunkBuffer[offset++];
					addr = TEXT_DECODER.decode(chunkBuffer.slice(offset, offset + domainLen));
					offset += domainLen;
				} else if (addrType === 3) {
					const v6 = [];
					for (let i = 0; i < 8; i++) {
						v6.push(((chunkBuffer[offset++] << 8) | chunkBuffer[offset++]).toString(16));
					}
					addr = v6.join(":");
				}
				rawData = chunkBuffer.slice(offset);
				respHeader = new Uint8Array([chunkBuffer[0], 0]);
			}
			if (isHeaderParsing) return;
			isHeaderParsing = true;
			isTrojanProto = isTrojan;
			let user = null;
			try {
				const authCacheKind = isTrojan ? "t" : "u";
				const cachedAuthUser = await getCachedAuthUser(authCacheKind, userLookupKey);
				if (cachedAuthUser !== undefined) {
					user = cachedAuthUser; // may be null - a cached "no such user" (negative cache)
				} else {
					if (isTrojan) {
						user = await env.DB.prepare("SELECT * FROM users WHERE trojan_hash = ? OR uuid = ?").bind(userLookupKey, userLookupKey).first();
						if (!user) {
							const { results } = await env.DB.prepare("SELECT * FROM users WHERE is_active = 1").all();
							if (results) {
								user = results.find(u => u.uuid && sha224Pure(u.uuid) === userLookupKey) || null;
							}
						}
					} else {
						user = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(userLookupKey).first();
					}
					putCachedAuthUser(ctx, authCacheKind, userLookupKey, user || null);
				}
			} catch (e) { }
			if (!user) {
				serverSock.close();
				return;
			}
			const userConn = String(user.connection_type || "vless").toLowerCase();
			if (isTrojan) {
				if (!userConn.includes("trojan")) {
					serverSock.close();
					return;
				}
			} else {
				if (!userConn.includes("vless") && userConn !== "vl" + "e" + "ss") {
					serverSock.close();
					return;
				}
			}
			reqUUID = user.uuid;
			if (request) {
				const reqUrl = new URL(request.url);
				if (!reqUrl.pathname.startsWith("/XYZ")) {
					serverSock.close();
					return;
				}
				const pathSegments = reqUrl.pathname.split("/").filter(Boolean);
				const lastPathSeg = decodeURIComponent(pathSegments[pathSegments.length - 1] || "");
				inlinePanelIPs = decodeInlinePanelIPs(lastPathSeg);
			}
			username = user.username;
			validUUID = reqUUID;
			let currentReqs = USER_REQ_CACHE.get(username) || 0;
			USER_REQ_CACHE.set(username, currentReqs + 1);
			if (!GLOBAL_TRAFFIC_CACHE.has(username)) {
				GLOBAL_TRAFFIC_CACHE.set(username, 0);
			}
			if (isOfflineSet || serverSock.readyState !== WebSocket.OPEN) {
				return;
			}
			if (user.is_active === 0) {
				serverSock.close();
				return;
			}
			const liveGb = (user.used_gb || 0) + ((GLOBAL_TRAFFIC_CACHE.get(username) || 0) / (1024 * 1024 * 1024));
			if (user.limit_gb && liveGb >= user.limit_gb) {
				serverSock.close();
				return;
			}
			if (user.limit_req && user.used_req + (USER_REQ_CACHE.get(username) || 0) > user.limit_req) {
				serverSock.close();
				return;
			}
			if (await isGlobalReqLimitReached(env, ctx)) {
				serverSock.close();
				return;
			}
			if (user.start_on_first_connect === 1 && !user.first_connection_time && !GLOBAL_WRITE_LOCK.get(reqUUID + "_first_conn")) {
				GLOBAL_WRITE_LOCK.set(reqUUID + "_first_conn", true);
				const firstConnectNow = Date.now();
				user.first_connection_time = firstConnectNow;
				const updateFirstTask = async () => {
					try {
						// Guard with "AND first_connection_time IS NULL" so a genuinely concurrent
						// request (a race within this isolate, or - more likely, given the 10s auth
						// cache TTL - a different isolate that hasn't seen this write yet) can never
						// overwrite an already-stamped first_connection_time with a later timestamp.
						await env.DB.prepare("UPDATE users SET first_connection_time = ? WHERE uuid = ? AND first_connection_time IS NULL").bind(firstConnectNow, reqUUID).run();
						// BUGFIX: this write previously did not invalidate the auth cache entry, so
						// any connection from the same user in the next up-to-10s (same isolate is
						// covered by GLOBAL_WRITE_LOCK above, but a different isolate is not) could
						// still read the stale cached row with first_connection_time still null,
						// re-enter this block, and (before the IS NULL guard above) push the user's
						// real expiry date later. Every other write to a cached/auth-relevant field
						// in this file calls invalidateUserAuthCache() right after - this was the one
						// path that didn't.
						await invalidateUserAuthCache(ctx, reqUUID, user.trojan_hash);
					} catch (e) {
						GLOBAL_WRITE_LOCK.delete(reqUUID + "_first_conn");
					}
				};
				if (ctx) ctx.waitUntil(updateFirstTask());
				else updateFirstTask();
			}
			if (user.expiry_days) {
				let isTimeExpired = false;
				if (user.start_on_first_connect === 1) {
					if (user.first_connection_time) {
						const expiryDate = new Date(user.first_connection_time + user.expiry_days * 24 * 60 * 60 * 1000);
						if (new Date() > expiryDate) isTimeExpired = true;
					}
				} else if (user.created_at) {
					const created = new Date(user.created_at);
					const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
					if (new Date() > expiryDate) isTimeExpired = true;
				}
				if (isTimeExpired) {
					try {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(reqUUID).run();
						await invalidateUserAuthCache(ctx, reqUUID);
					} catch (e) { }
					serverSock.close();
					return;
				}
			}
			if (user.block_porn === 1 && user.block_ads === 1) {
				targetDns = "94.140.14.15";
				targetDoh = "https://family.adguard-dns.com/dns-query";
			} else if (user.block_porn === 1) {
				targetDns = "1.1.1.3";
				targetDoh = "https://family.cloudflare-dns.com/dns-query";
			} else if (user.block_ads === 1) {
				targetDns = "94.140.14.14";
				targetDoh = "https://dns.adguard-dns.com/dns-query";
			}
			if (clientIP && clientIP !== "unknown") {
				// «دیده‌شده/تأییدشده» (نگاه کنید توضیح DEVICE_CONFIRM_* بالای فایل): این IP فقط
				// وقتی همین‌جا فوری «تأییدشده» حساب می‌شه که از قبل توی active_ips کاربر باشه و
				// هنوز تازه باشه - یعنی همین دستگاه از قبل یه اتصال دیگه داشته و این یکی صرفاً
				// reconnect/تب جدیدشه؛ دقیقاً همون رفتار قبلی، بدون تأخیر، تا سرعت یا اتصال
				// دستگاه‌های از قبل متصل عوض نشه. اگه IP تازه باشه، هیچی اینجا روی D1 نوشته
				// نمی‌شه و سقف «محدودیت کاربر»/ip_limit هم اینجا چک نمی‌شه؛ تصمیم می‌مونه برای
				// checkDeviceConfirmation() (تعریف‌شده بالاتر، از addBytes/هیت‌بیت صدا زده می‌شه).
				let activeIps = {};
				try {
					activeIps = JSON.parse(user.active_ips || "{}");
				} catch (e) { }
				const now = Date.now();
				for (const [ip, data] of Object.entries(activeIps)) {
					const lastSeen = data && typeof data === "object" ? data.timestamp : data;
					if (now - lastSeen > 180000) delete activeIps[ip];
				}
				if (activeIps[clientIP]) {
					deviceConfirmed = true;
					if (typeof activeIps[clientIP] === "object") {
						activeIps[clientIP].timestamp = now;
						activeIps[clientIP].count = (activeIps[clientIP].count || 0) + 1;
					} else {
						activeIps[clientIP] = { timestamp: now, count: 1 };
					}
					let lastDbW = GLOBAL_LAST_DB_WRITE.get(username) || 0;
					if (now - lastDbW > 900000) {
						GLOBAL_LAST_ACTIVE_WRITE.set(username, now);
						GLOBAL_LAST_DB_WRITE.set(username, now);
						persistActiveIp(env, ctx, reqUUID, username, clientIP, now);
					}
				}
			}
			isHeaderParsed = true;
			if (deviceConfirmed) {
				let activeCount = ACTIVE_CONNECTIONS_COUNT.get(username) || 0;
				ACTIVE_CONNECTIONS_COUNT.set(username, activeCount + 1);
				hasCountedAsActive = true;
			}
			try {
				let isDomainAddress = (isTrojanProto && addrType === 3) || (!isTrojanProto && addrType === 2);
				let isIpAddress = (isTrojanProto && (addrType === 1 || addrType === 4)) || (!isTrojanProto && (addrType === 1 || addrType === 3));
				let sniffedDomain = null;
				if (isIpAddress && port === 443 && rawData && rawData.byteLength > 43) {
					try {
						let pos = 43;
						if (rawData[0] === 0x16 && rawData[5] === 0x01) {
							const sessionIdLen = rawData[pos];
							pos += 1 + sessionIdLen;
							const cipherSuitesLen = (rawData[pos] << 8) | rawData[pos + 1];
							pos += 2 + cipherSuitesLen;
							const compMethodsLen = rawData[pos];
							pos += 1 + compMethodsLen;
							const extensionsLen = (rawData[pos] << 8) | rawData[pos + 1];
							pos += 2;
							const endPos = Math.min(pos + extensionsLen, rawData.byteLength);
							while (pos + 4 <= endPos) {
								const extType = (rawData[pos] << 8) | rawData[pos + 1];
								const extLen = (rawData[pos + 2] << 8) | rawData[pos + 3];
								pos += 4;
								if (extType === 0x0000) {
									let sniListLen = (rawData[pos] << 8) | rawData[pos + 1];
									let sniPos = pos + 2;
									if (rawData[sniPos] === 0x00) {
										let sniLen = (rawData[sniPos + 1] << 8) | rawData[sniPos + 2];
										sniffedDomain = new TextDecoder().decode(rawData.slice(sniPos + 3, sniPos + 3 + sniLen));
										break;
									}
								}
								pos += extLen;
							}
						}
					} catch (e) {}
				}
				if (user.block_porn === 1 || user.block_ads === 1) {
					const dohIps = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220", "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001"];
					if (port === 443 && isIpAddress && dohIps.includes(addr)) {
						serverSock.close();
						return;
					}
				}
				let checkDomain = isDomainAddress ? addr : sniffedDomain;
				if ((user.block_ads === 1 || user.block_porn === 1) && checkDomain && port !== 53) {
					try {
						const dnsCheck = await dohQuery(checkDomain, "A", targetDoh);
						const isBlocked = dnsCheck.some((r) => r.data === "0.0.0.0" || r.data === "::" || r.data === "176.103.130.130");
						if (isBlocked) {
							serverSock.close();
							return;
						}
						if (user.block_porn === 1 && dnsCheck.length > 0) {
							const isSearchEngine = /(google\.|bing\.com|yandex\.|yahoo\.|duckduckgo\.com|youtube\.)/i.test(checkDomain);
							if (isSearchEngine) {
								const validIpRecord = dnsCheck.find(r => r.type === 1 || r.type === 28);
								if (validIpRecord) {
									const safeIp = validIpRecord.data;
									if (safeIp && safeIp !== "0.0.0.0" && safeIp !== "::") {
										addr = safeIp;
									}
								}
							}
						}
					} catch (e) { }
				}
				if ((isTrojanProto && cmd === 3) || (!isTrojanProto && cmd === 2)) {
					if (port === 53) {
						isDnsQuery = true;
						if (isTrojanProto) {
							await forwardTrojanUDP(rawData, serverSock, addBytes, targetDns);
						} else {
							await forwardvIeesUDP(rawData, serverSock, respHeader, addBytes, targetDns);
						}
						return;
					}
					if (!isTrojanProto && respHeader) {
						try { serverSock.send(respHeader); } catch(e) {}
					}
					if (port === 443) {
						setTimeout(() => {
							try { serverSock.close(); } catch(e) {}
						}, 100);
						return;
					}
					return;
				}
				if (port === 25 || /^(0\.|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|localhost$|::1|::ffff:|fd[0-9a-f]{2}:|fe80:)/i.test(addr)) {
					serverSock.close();
					return;
				}
				const connectTCP = async (dataPayload = null, useFallback = true) => {
					if (remoteConnWrapper.connectingPromise) {
						await remoteConnWrapper.connectingPromise;
						return;
					}
					const task = (async () => {
						let s = null;
						const socks5 = getSelectedUserProxy(user?.user_socks5, request);
						if (socks5) {
							try {
								s = await connectProxy(socks5, addr, port, dataPayload);
							} catch (proxyErr) {
								if (user.auto_rotate_user_proxy === 1) {
									const replaceTask = replaceBrokenProxy(user.username, env, socks5);
									if (ctx) ctx.waitUntil(replaceTask);
									else replaceTask.catch(() => { });
								}
								throw proxyErr;
							}
						} else {
							try {
								s = await connectDirect(addr, port, dataPayload, targetDoh);
							} catch (directErr) {
								if (useFallback) {
									let fallbackSuccess = false;
									if (inlinePanelIPs && inlinePanelIPs.length) {
										for (const panelIP of inlinePanelIPs) {
											try {
												s = await connectDirect(panelIP, port, dataPayload, targetDoh);
												fallbackSuccess = true;
												break;
											} catch (inlineErr) { }
										}
									}
									if (!fallbackSuccess) {
										const IATA_LIST = ["FRA", "AMS", "LHR", "CDG", "VIE", "HEL", "CPH", "MAD", "BCN", "MXP", "FCO", "ZRH", "WAW", "PRG", "DUB", "SNN", "MAN", "GVA", "BRU", "LIS", "ATH", "SOF", "OTP", "TLL", "RIX", "VNO", "BUD", "BEG", "ZAG", "MUC", "HAM", "SIN", "NRT", "HKG", "TPE", "ICN", "DXB", "BOM", "DEL", "YYZ", "YUL", "YVR", "JFK", "EWR", "LAX", "SFO", "ORD", "MIA", "DFW", "SEA", "IAD", "ATL"];
										const shuffledIatas = IATA_LIST.slice().sort(() => 0.5 - Math.random());
										const maxAttempts = 3;
										for (let i = 0; i < maxAttempts && i < shuffledIatas.length; i++) {
											const fallbackHost = shuffledIatas[i].toLowerCase() + ".proxyip.cmliussss.net";
											try {
												s = await connectDirect(fallbackHost, port, dataPayload, targetDoh);
												fallbackSuccess = true;
												break;
											} catch (fallbackErr) { }
										}
									}
									if (!fallbackSuccess) throw directErr;
								} else {
							throw directErr;
						}
					}
				}
				remoteConnWrapper.socket = s;
				connectStreams(s, serverSock, respHeader, null, addBytes).finally(() => closeSocketQuietly(serverSock));
			})();
			remoteConnWrapper.connectingPromise = task;
					try {
						await task;
					} finally {
						if (remoteConnWrapper.connectingPromise === task) {
							remoteConnWrapper.connectingPromise = null;
						}
					}
				};
				remoteConnWrapper.retryConnect = async () => connectTCP(null, false);
				await connectTCP(rawData, true);
			} catch (e) {
				serverSock.close();
			}
		}
	};
	const handleWsError = (err) => {
		if (wsFailed) return;
		wsFailed = true;
		wsStopped = true;
		clearTimeout(heartbeat);
		wsQueueBytes = 0;
		wsQueueItems = 0;
		upstreamQueue.clear();
		releaseRemoteWriter();
		closeSocketQuietly(serverSock);
		setOffline();
	};
	const pushToChain = (task) => {
		wsChain = wsChain.then(task).catch(handleWsError);
	};
	serverSock.addEventListener("message", (event) => {
		if (wsStopped || wsFailed) return;
		if (typeof event.data === "string") return;
		const size = event.data.byteLength || 0;
		const nextBytes = wsQueueBytes + size;
		const nextItems = wsQueueItems + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			handleWsError(new Error("ws queue overflow"));
			return;
		}
		wsQueueBytes = nextBytes;
		wsQueueItems = nextItems;
		pushToChain(async () => {
			wsQueueBytes = Math.max(0, wsQueueBytes - size);
			wsQueueItems = Math.max(0, wsQueueItems - 1);
			if (wsFailed) return;
			await processWsMessage(event.data);
		});
	});
	serverSock.addEventListener("close", () => {
		clearTimeout(heartbeat);
		closeSocketQuietly(serverSock);
		setOffline();
		if (wsFinished) return;
		wsFinished = true;
		wsStopped = true;
		pushToChain(async () => {
			if (wsFailed) return;
			await upstreamQueue.awaitEmpty();
			releaseRemoteWriter();
		});
	});
	serverSock.addEventListener("error", (err) => {
		handleWsError(err);
	});
	// Early Data (?ed=): وقتی path کانفیگ ed داشته باشد، کلاینت بایت‌های اول اتصال (هدر VLESS/Trojan + اولین دیتا)
	// را به‌جای پیام WebSocket، داخل هدر Sec-WebSocket-Protocol و به‌صورت base64url می‌فرستد. اینجا همان
	// بایت‌ها را دیکد می‌کنیم و قبل از هر پیام واقعی وارد همان زنجیره‌ی processWsMessage می‌کنیم (پارس هدر
	// دست‌نخورده می‌ماند). هدر همین مقدار در پاسخ ۱۰۱ هم echo می‌شود. اگر کلاینت این هدر را نفرستد
	// (لینک بدون ed) هیچ فرقی با قبل نمی‌کند؛ وابسته به فلگ دیتابیس هم نیست.
	const earlyDataToken = request ? (request.headers.get("Sec-WebSocket-Protocol") || "").split(",")[0].trim() : "";
	let earlyDataAccepted = false;
	if (earlyDataToken && /^[A-Za-z0-9_-]+$/.test(earlyDataToken)) {
		try {
			let b64 = earlyDataToken.replace(/-/g, "+").replace(/_/g, "/");
			b64 += "=".repeat((4 - (b64.length % 4)) % 4);
			const bin = atob(b64);
			const earlyBytes = new Uint8Array(bin.length);
			for (let i = 0; i < bin.length; i++) earlyBytes[i] = bin.charCodeAt(i);
			if (earlyBytes.byteLength > 0) {
				earlyDataAccepted = true;
				pushToChain(async () => {
					if (wsFailed) return;
					await processWsMessage(earlyBytes.buffer);
				});
			}
		} catch (e) { }
	}
	return new Response(null, {
		status: 101,
		webSocket: clientSock,
		headers: earlyDataAccepted ? { "Sec-WebSocket-Protocol": earlyDataToken } : undefined,
	});
}
let CF_USAGE_CACHE = null;
let CF_USAGE_LAST_FETCH = 0;
let CF_USAGE_CACHE_DATE = ""; 

async function getCfUsage(env) {
	if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return { today: 0, total: 0, d1Reads: 0, d1Writes: 0 };
	const nowTime = Date.now();
	const todayStr = new Date().toISOString().split("T")[0];
	
	if (CF_USAGE_CACHE && (nowTime - CF_USAGE_LAST_FETCH < 60000) && CF_USAGE_CACHE_DATE === todayStr) {
		return CF_USAGE_CACHE;
	}
	try {
		const now = new Date();
		const startOfDay = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())).toISOString();
		const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
		const q = `query {
	  viewer {
		accounts(filter: {accountTag: "${env.CF_ACCOUNT_ID}"}) {
		  today: workersInvocationsAdaptive(limit: 10, filter: {datetime_geq: "${startOfDay}"}) {
			sum { requests }
		  }
		  total: workersInvocationsAdaptive(limit: 10, filter: {datetime_geq: "${thirtyDaysAgo}"}) {
			sum { requests }
		  }
		  d1: d1AnalyticsAdaptiveGroups(limit: 10, filter: {date_geq: "${todayStr}"}) {
			sum { rowsRead rowsWritten }
		  }
		}
	  }
	}`;
		const res = await fetch("https://api.cloudflare.com/client/v4/graphql", {
			method: "POST",
			headers: { Authorization: "Bearer " + env.CF_API_TOKEN, "Content-Type": "application/json" },
			body: JSON.stringify({ query: q }),
			cache: "no-store" 
		});
		const j = await res.json();
		const acc = j?.data?.viewer?.accounts?.[0];
		const todayReqs = acc?.today?.[0]?.sum?.requests || 0;
		const totalReqs = acc?.total?.[0]?.sum?.requests || todayReqs;
		const d1Reads = acc?.d1?.[0]?.sum?.rowsRead || 0;
		const d1Writes = acc?.d1?.[0]?.sum?.rowsWritten || 0;
		
		CF_USAGE_CACHE = { today: todayReqs, total: totalReqs, d1Reads, d1Writes };
		CF_USAGE_LAST_FETCH = nowTime;
		CF_USAGE_CACHE_DATE = todayStr;
		return CF_USAGE_CACHE;
	} catch (e) {
		return CF_USAGE_CACHE || { today: 0, total: 0, d1Reads: 0, d1Writes: 0 };
	}
}
function isIPv4(value) {
	const parts = String(value || "").split(".");
	return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
function convertToUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}
function concatBytes(...chunkList) {
	if (chunkList.length === 2) {
		const a = convertToUint8Array(chunkList[0]);
		const b = convertToUint8Array(chunkList[1]);
		if (!a.byteLength) return b;
		if (!b.byteLength) return a;
		const merged = new Uint8Array(a.byteLength + b.byteLength);
		merged.set(a, 0);
		merged.set(b, a.byteLength);
		return merged;
	}
	const chunks = chunkList.map(convertToUint8Array);
	let total = 0;
	for (const c of chunks) total += c.byteLength;
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) {
		result.set(c, offset);
		offset += c.byteLength;
	}
	return result;
}
function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (e) { }
}
async function dohQuery(domain, recordType, targetDoh = DOH_RESOLVER) {
	const cacheKey = `${domain}:${recordType}:${targetDoh}`;
	if (DNS_CACHE.has(cacheKey)) {
		const cached = DNS_CACHE.get(cacheKey);
		if (Date.now() < cached.expires) return cached.data;
		DNS_CACHE.delete(cacheKey);
	}
	try {
		const typeMap = { A: 1, AAAA: 28 };
		const qtype = typeMap[recordType.toUpperCase()] || 1;
		const encodeDomain = (name) => {
			const parts = name.endsWith(".") ? name.slice(0, -1).split(".") : name.split(".");
			const bufs = [];
			for (const label of parts) {
				const enc = TEXT_ENCODER.encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			return concatBytes(...bufs);
		};
		const qname = encodeDomain(domain);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
		qview.setUint16(2, 0x0100);
		qview.setUint16(4, 1);
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1);
		const response = await fetch(targetDoh, {
			method: "POST",
			headers: {
				"Content-Type": "application/dns-message",
				Accept: "application/dns-message",
			},
			body: query,
		});
		if (!response.ok) return [];
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		const parseName = (pos) => {
			const labels = [];
			let p = pos,
				jumped = false,
				endPos = -1,
				safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) {
					if (!jumped) endPos = p + 1;
					break;
				}
				if ((len & 0xc0) === 0xc0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3f) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(TEXT_DECODER.decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join("."), endPos];
		};
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = parseName(offset);
			offset = Number(end) + 4;
		}
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = parseName(offset);
			offset = Number(nameEnd);
			const type = dv.getUint16(offset);
			offset += 2;
			offset += 2;
			const ttl = dv.getUint32(offset);
			offset += 4;
			const rdlen = dv.getUint16(offset);
			offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;
			let data;
			if (type === 1 && rdlen === 4) {
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(":");
			} else {
				data = Array.from(rdata)
					.map((b) => b.toString(16).padStart(2, "0"))
					.join("");
			}
			answers.push({ name, type, TTL: ttl, data });
		}
		if (DNS_CACHE.size >= DNS_CACHE_MAX_ENTRIES) {
			const oldestKey = DNS_CACHE.keys().next().value;
			if (oldestKey !== undefined) DNS_CACHE.delete(oldestKey);
		}
		DNS_CACHE.set(cacheKey, { data: answers, expires: Date.now() + DNS_CACHE_TTL });
		return answers;
	} catch (e) {
		return [];
	}
}
function createUpstreamQueue({ getWriter, releaseWriter, retryConnect, closeConnection, name = "UpstreamQueue" }) {
	let chunks = [];
	let head = 0;
	let queuedBytes = 0;
	let draining = false;
	let closed = false;
	let bundleBuffer = null;
	let idleResolvers = [];
	let activeCompletions = null;
	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const comp of completions) {
			if (comp) {
				if (err) comp.reject(err);
				else comp.resolve();
			}
		}
	};
	const rejectQueued = (err) => {
		for (let i = head; i < chunks.length; i++) {
			const item = chunks[i];
			if (item && item.completions) settleCompletions(item.completions, err);
		}
	};
	const compact = () => {
		if (head > 32 && head * 2 >= chunks.length) {
			chunks = chunks.slice(head);
			head = 0;
		}
	};
	const resolveIdle = () => {
		if (queuedBytes || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};
	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${name}: queue closed`) : null);
		if (closeErr) {
			rejectQueued(closeErr);
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		}
		chunks = [];
		head = 0;
		queuedBytes = 0;
		resolveIdle();
	};
	const shift = () => {
		if (head >= chunks.length) return null;
		const item = chunks[head];
		chunks[head++] = undefined;
		queuedBytes -= item.chunk.byteLength;
		compact();
		return item;
	};
	const bundle = () => {
		const first = shift();
		if (!first) return null;
		if (head >= chunks.length || first.chunk.byteLength >= UPSTREAM_BUNDLE_TARGET_BYTES) return first;
		let byteLength = first.chunk.byteLength;
		let end = head;
		let allowRetry = first.allowRetry;
		let completions = first.completions || null;
		while (end < chunks.length) {
			const next = chunks[end];
			const nextLength = byteLength + next.chunk.byteLength;
			if (nextLength > UPSTREAM_BUNDLE_TARGET_BYTES) break;
			byteLength = nextLength;
			allowRetry = allowRetry && next.allowRetry;
			if (next.completions) completions = completions ? completions.concat(next.completions) : next.completions;
			end++;
		}
		if (end === head) return first;
		const output = (bundleBuffer ||= new Uint8Array(UPSTREAM_BUNDLE_TARGET_BYTES));
		output.set(first.chunk);
		let offset = first.chunk.byteLength;
		while (head < end) {
			const next = chunks[head];
			chunks[head++] = undefined;
			queuedBytes -= next.chunk.byteLength;
			output.set(next.chunk, offset);
			offset += next.chunk.byteLength;
		}
		compact();
		return { chunk: output.subarray(0, byteLength), allowRetry, completions };
	};
	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			let batchCount = 0;
			for (; ;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				let writer = getWriter();
				if (!writer) throw new Error(`${name}: remote writer unavailable`);
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					try {
						await writer.write(item.chunk);
					} catch (err) {
						releaseWriter?.();
						if (!item.allowRetry || typeof retryConnect !== "function") throw err;
						await retryConnect();
						writer = getWriter();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
				batchCount++;
				if (batchCount >= 16) {
					await Promise.resolve();
					batchCount = 0;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			try {
				closeConnection?.(err);
			} catch (_) { }
		} finally {
			draining = false;
			if (!closed && head < chunks.length) queueMicrotask(drain);
			else resolveIdle();
		}
	};
	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		if (!getWriter()) return false;
		const chunk = convertToUint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = queuedBytes + chunk.byteLength;
		const nextItems = chunks.length - head + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			closed = true;
			const err = Object.assign(new Error(`${name}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clear(err);
			try {
				closeConnection?.(err);
			} catch (_) { }
			throw err;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		chunks.push({ chunk, allowRetry, completions });
		queuedBytes = nextBytes;
		if (!draining) queueMicrotask(drain);
		return waitForFlush ? completionPromise.then(() => true) : true;
	};
	return {
		writeAndAwait(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async awaitEmpty() {
			if (!queuedBytes && !draining) return;
			await new Promise((resolve) => idleResolvers.push(resolve));
		},
		clear() {
			closed = true;
			clear();
		},
	};
}
function createDownstreamSender(webSocket, headerData = null) {
	const MAX_CAP = 256 * 1024;
	const MIN_CAP = 16 * 1024;
	let currentPacketCap = 128 * 1024;
	const tailBytes = 512;
	let header = headerData;
	let pendingBuffer = null;
	let pendingBytes = 0;
	let flushPromise = null;
	let microtaskQueued = false;
	const adjustSmartBuffer = () => {
		const buffered = webSocket.bufferedAmount || 0;
		if (buffered > 256 * 1024) {
			currentPacketCap = Math.max(MIN_CAP, Math.floor(currentPacketCap / 2));
		} else if (buffered < 32 * 1024) {
			currentPacketCap = Math.min(MAX_CAP, currentPacketCap * 2);
		}
	};
	const sendRawChunk = async (chunk) => {
		if (webSocket.readyState !== 1) throw new Error("ws.readyState is not open");
		webSocket.send(chunk);
	};
	const attachResponseHeader = (chunk) => {
		if (!header) return chunk;
		const merged = new Uint8Array(header.length + chunk.byteLength);
		merged.set(header, 0);
		merged.set(chunk, header.length);
		header = null;
		return merged;
	};
	const flush = async () => {
		microtaskQueued = false;
		while (flushPromise) await flushPromise;
		if (!pendingBytes) return;
		const output = pendingBuffer.slice(0, pendingBytes);
		adjustSmartBuffer();
		pendingBytes = 0;
		flushPromise = sendRawChunk(output).finally(() => {
			flushPromise = null;
		});
		return flushPromise;
	};
	return {
		async sendDirect(data) {
			let chunk = convertToUint8Array(data);
			if (!chunk.byteLength) return;
			chunk = attachResponseHeader(chunk);
			await sendRawChunk(chunk);
		},
		async send(data) {
			let chunk = convertToUint8Array(data);
			if (!chunk.byteLength) return;
			chunk = attachResponseHeader(chunk);
			let offset = 0;
			const totalBytes = chunk.byteLength;
			while (offset < totalBytes) {
				if (!pendingBytes && totalBytes - offset >= currentPacketCap) {
					const sendBytes = Math.min(currentPacketCap, totalBytes - offset);
					const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
					await sendRawChunk(view);
					offset += sendBytes;
					adjustSmartBuffer();
					continue;
				}
				const copyBytes = Math.min(currentPacketCap - pendingBytes, totalBytes - offset);
				if (!pendingBuffer) pendingBuffer = new Uint8Array(MAX_CAP);
				pendingBuffer.set(chunk.subarray(offset, offset + copyBytes), pendingBytes);
				pendingBytes += copyBytes;
				offset += copyBytes;
				if (pendingBytes >= currentPacketCap || currentPacketCap - pendingBytes < tailBytes) {
					await flush();
				} else if (!microtaskQueued) {
					microtaskQueued = true;
					queueMicrotask(() => {
						if (pendingBytes) flush().catch(() => closeSocketQuietly(webSocket));
					});
				}
			}
		},
		flush,
	};
}
async function waitForBackpressure(ws) {
	if (typeof ws.bufferedAmount === "number") {
		while (ws.bufferedAmount > 1024 * 1024) {
			if (ws.readyState !== 1) break;
			await new Promise((r) => setTimeout(r, 20));
		}
	}
}
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, onBytes) {
	let header = headerData,
		hasData = false;
	const downstreamSender = createDownstreamSender(webSocket, header);
	header = null;
	try {
		let reader = remoteSocket.readable.getReader({ mode: "byob" });
		let useBYOB = true;
		reader.releaseLock();
		if (useBYOB) {
			const transformStream = new TransformStream({
				transform(chunk, controller) {
					hasData = true;
					if (typeof onBytes === "function") onBytes(chunk.byteLength);
					controller.enqueue(chunk);
				}
			});
			const writePromise = transformStream.readable.pipeTo(new WritableStream({
				async write(chunk) {
					await downstreamSender.send(chunk);
				}
			}));
			await remoteSocket.readable.pipeTo(transformStream.writable);
			await writePromise;
		}
	} catch (e) {
		let reader = remoteSocket.readable.getReader();
		try {
			while (true) {
				if (webSocket.bufferedAmount > 1024 * 1024) await waitForBackpressure(webSocket);
				const { done, value } = await reader.read();
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (typeof onBytes === "function") onBytes(value.byteLength);
				await downstreamSender.send(value);
			}
		} finally {
			try { reader.cancel(); } catch (err) {}
			try { reader.releaseLock(); } catch (err) {}
		}
	} finally {
		await downstreamSender.flush();
		closeSocketQuietly(webSocket);
	}
	if (!hasData && retryFunc) await retryFunc();
}
function bracketIPv6(host) {
	return typeof host === "string" && host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}
async function waitSocketOpened(socket, ms = 5000) {
	let timer;
	try {
		await Promise.race([
			socket.opened,
			new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("timeout")), ms); })
		]);
	} catch (e) {
		try { socket.close(); } catch (_) {}
		throw e;
	} finally {
		clearTimeout(timer);
	}
}
async function connectDirect(address, port, initialData = null, targetDoh = "https://cloudflare-dns.com/dns-query") {
	const socket = connect({ hostname: bracketIPv6(address), port: port });
	await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000))]);
	if (initialData && initialData.byteLength > 0) {
		const w = socket.writable.getWriter();
		await w.write(convertToUint8Array(initialData));
		w.releaseLock();
	}
	return socket;
}
function sha224Pure(message) {
	function rotateRight(n, x) { return (x >>> n) | (x << (32 - n)); }
	function choice(x, y, z) { return (x & y) ^ (~x & z); }
	function majority(x, y, z) { return (x & y) ^ (x & z) ^ (y & z); }
	function sigma0(x) { return rotateRight(2, x) ^ rotateRight(13, x) ^ rotateRight(22, x); }
	function sigma1(x) { return rotateRight(6, x) ^ rotateRight(11, x) ^ rotateRight(25, x); }
	function gamma0(x) { return rotateRight(7, x) ^ rotateRight(18, x) ^ (x >>> 3); }
	function gamma1(x) { return rotateRight(17, x) ^ rotateRight(19, x) ^ (x >>> 10); }
	const K = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	];
	let H = [
		0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
		0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
	];
	const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
	const bitLen = msgBytes.length * 8;
	const newLen = (((msgBytes.length + 8) >> 6) + 1) << 6;
	const padded = new Uint8Array(newLen);
	padded.set(msgBytes);
	padded[msgBytes.length] = 0x80;
	const view = new DataView(padded.buffer);
	view.setUint32(newLen - 4, bitLen, false);
	const W = new Uint32Array(64);
	for (let i = 0; i < newLen; i += 64) {
		for (let t = 0; t < 16; t++) {
			W[t] = view.getUint32(i + t * 4, false);
		}
		for (let t = 16; t < 64; t++) {
			W[t] = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) >>> 0;
		}
		let [a, b, c, d, e, f, g, h] = H;
		for (let t = 0; t < 64; t++) {
			const T1 = (h + sigma1(e) + choice(e, f, g) + K[t] + W[t]) >>> 0;
			const T2 = (sigma0(a) + majority(a, b, c)) >>> 0;
			h = g;
			g = f;
			f = e;
			e = (d + T1) >>> 0;
			d = c;
			c = b;
			b = a;
			a = (T1 + T2) >>> 0;
		}
		H[0] = (H[0] + a) >>> 0;
		H[1] = (H[1] + b) >>> 0;
		H[2] = (H[2] + c) >>> 0;
		H[3] = (H[3] + d) >>> 0;
		H[4] = (H[4] + e) >>> 0;
		H[5] = (H[5] + f) >>> 0;
		H[6] = (H[6] + g) >>> 0;
		H[7] = (H[7] + h) >>> 0;
	}
	return H.slice(0, 7).map(w => w.toString(16).padStart(8, '0')).join('');
}
async function forwardTrojanUDP(udpChunk, webSocket, onBytes, dnsServer = "8.8.4.4") {
	try {
		let targetDoh = "https://cloudflare-dns.com/dns-query";
		if (dnsServer === "94.140.14.15") targetDoh = "https://family.adguard-dns.com/dns-query";
		else if (dnsServer === "1.1.1.3") targetDoh = "https://family.cloudflare-dns.com/dns-query";
		else if (dnsServer === "94.140.14.14") targetDoh = "https://dns.adguard-dns.com/dns-query";
		const data = convertToUint8Array(udpChunk);
		if (data.byteLength < 7) return;
		let offset = 0;
		const addrType = data[offset++];
		let headerAddrBytes = [];
		
		if (addrType === 1) {
			if (data.byteLength < offset + 4) return;
			headerAddrBytes = [addrType, data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
			offset += 4;
		} else if (addrType === 3) {
			if (data.byteLength < offset + 1) return;
			const domainLen = data[offset++];
			if (data.byteLength < offset + domainLen) return;
			headerAddrBytes = [addrType, domainLen, ...data.slice(offset, offset + domainLen)];
			offset += domainLen;
		} else if (addrType === 4) {
			if (data.byteLength < offset + 16) return;
			headerAddrBytes = [addrType, ...data.slice(offset, offset + 16)];
			offset += 16;
		} else {
			return;
		}
		
		if (data.byteLength < offset + 4) return;
		const port = (data[offset++] << 8) | data[offset++];
		const length = (data[offset++] << 8) | data[offset++];
		offset += 2; 
		if (data.byteLength < offset + length) return;
		
		const dnsPayload = data.slice(offset, offset + length);
		const response = await fetch(targetDoh, {
			method: 'POST',
			headers: {
				'Accept': 'application/dns-message',
				'Content-Type': 'application/dns-message'
			},
			body: dnsPayload
		});
		if (!response.ok) return;
		const rawResponse = new Uint8Array(await response.arrayBuffer());
		if (typeof onBytes === "function") onBytes(rawResponse.byteLength);
		if (webSocket.readyState !== WebSocket.OPEN) return;
		const resLen = rawResponse.byteLength;
		const udpHeader = new Uint8Array(headerAddrBytes.length + 2 + 2 + 2);
		let hOff = 0;
		for (let b of headerAddrBytes) udpHeader[hOff++] = b;
		udpHeader[hOff++] = (port >> 8) & 0xff;
		udpHeader[hOff++] = port & 0xff;
		udpHeader[hOff++] = (resLen >> 8) & 0xff;
		udpHeader[hOff++] = resLen & 0xff;
		udpHeader[hOff++] = 0x0D;
		udpHeader[hOff++] = 0x0A;
		const merged = new Uint8Array(udpHeader.length + resLen);
		merged.set(udpHeader, 0);
		merged.set(rawResponse, udpHeader.length);
		webSocket.send(merged.buffer);
	} catch (e) { }
}
async function forwardvIeesUDP(udpChunk, webSocket, respHeader, onBytes, dnsServer = "8.8.4.4") {
	try {
		let targetDoh = "https://cloudflare-dns.com/dns-query";
		if (dnsServer === "94.140.14.15") targetDoh = "https://family.adguard-dns.com/dns-query";
		else if (dnsServer === "1.1.1.3") targetDoh = "https://family.cloudflare-dns.com/dns-query";
		else if (dnsServer === "94.140.14.14") targetDoh = "https://dns.adguard-dns.com/dns-query";
		const data = convertToUint8Array(udpChunk);
		if (data.byteLength < 2) return;
		const length = (data[0] << 8) | data[1];
		if (data.byteLength < 2 + length) return;
		
		const dnsPayload = data.slice(2, 2 + length);
		
		const response = await fetch(targetDoh, {
			method: 'POST',
			headers: {
				'Accept': 'application/dns-message',
				'Content-Type': 'application/dns-message'
			},
			body: dnsPayload
		});
		if (!response.ok) return;
		const rawResponse = new Uint8Array(await response.arrayBuffer());
		if (typeof onBytes === "function") onBytes(rawResponse.byteLength);
		if (webSocket.readyState !== WebSocket.OPEN) return;
		const resLen = rawResponse.byteLength;
		const udpPacket = new Uint8Array(2 + resLen);
		udpPacket[0] = (resLen >> 8) & 0xff;
		udpPacket[1] = resLen & 0xff;
		udpPacket.set(rawResponse, 2);
		const header = respHeader || new Uint8Array(0);
		const merged = new Uint8Array(header.length + udpPacket.byteLength);
		merged.set(header, 0);
		merged.set(udpPacket, header.length);
		webSocket.send(merged.buffer);
	} catch (e) { }
}
function extractUUIDFromvIees(data) {
	if (data.byteLength < 17) return null;
	const hex = [...data.slice(1, 17)].map((b) => b.toString(16).padStart(2, "0")).join("");
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}
function trackRequest(env, ctx) {
	GLOBAL_REQ_COUNT++;
	const now = Date.now();
	if ((now - GLOBAL_LAST_REQ_WRITE > 900000 || GLOBAL_REQ_COUNT > 5000) && GLOBAL_REQ_COUNT > 0) {
		GLOBAL_LAST_REQ_WRITE = now;
		const countToSave = GLOBAL_REQ_COUNT;
		GLOBAL_REQ_COUNT = 0;
		const task = async () => {
			try {
				const today = new Date().toISOString().split("T")[0];
				await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_total', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
				const lastDateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_last_date'").first();
				if (!lastDateRow || lastDateRow.value !== today) {
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(today, today).run();
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(countToSave), String(countToSave)).run();
				} else {
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
				}
				// این یکی جدا از today/req_today بالاست: اون‌ها مخصوص ریست global_req_limit سر هر روز
				// تقویمی UTC هستن (منطقشون عمداً دست نخورده)، این یکی جدول تاریخچه‌ی 7/30 روزه‌ست که حالا
				// روی کلید ساعتی ذخیره می‌شه تا بازه‌های رولینگ دقیق‌تری قابل محاسبه باشن (به utcHourKey نگاه کنید).
				const hourKey = utcHourKey(Date.now());
				await env.DB.prepare("INSERT INTO daily_requests (date, count) VALUES (?, ?) ON CONFLICT(date) DO UPDATE SET count = count + excluded.count").bind(hourKey, countToSave).run();
				try {
					const cutoffDateStr = new Date(Date.now() - 30 * 86400000).toISOString().split("T")[0];
					await env.DB.prepare("DELETE FROM daily_requests WHERE date < ?").bind(cutoffDateStr).run();
				} catch (e) { }
			} catch (e) { }
		};
		if (ctx) ctx.waitUntil(task());
		else task();
	}
}
async function connectProxy(proxyStr, destAddr, destPort, initialData) {
	let normalized = proxyStr;
	if (proxyStr.includes("t.me/socks") || proxyStr.includes("tg://socks")) {
		const server = proxyStr.match(/server=([^&]+)/)?.[1];
		const port = proxyStr.match(/port=([^&]+)/)?.[1];
		const user = proxyStr.match(/user=([^&]+)/)?.[1];
		const pass = proxyStr.match(/pass=([^&]+)/)?.[1];
		if (server && port) {
			normalized = user && pass ? `socks5://${user}:${pass}@${server}:${port}` : `socks5://${server}:${port}`;
		}
	}
	const hasProtocol = /^(socks4|socks5|socks|http|https):\/\//i.test(normalized);
	const isHttp = normalized.toLowerCase().startsWith("http://") || normalized.toLowerCase().startsWith("https://");
	const isSocks4 = normalized.toLowerCase().startsWith("socks4://");
	let cleanStr = normalized.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
	if (isHttp) {
		return await connectHttp(cleanStr, destAddr, destPort, initialData);
	}
	if (isSocks4) {
		return await connectSocks4(cleanStr, destAddr, destPort, initialData);
	}
	if (hasProtocol) {
		return await connectSocks5(cleanStr, destAddr, destPort, initialData);
	}
	return await Promise.any([
		connectSocks5(cleanStr, destAddr, destPort, initialData),
		connectHttp(cleanStr, destAddr, destPort, initialData)
	]);
}
async function connectSocks4(proxyStr, destAddr, destPort, initialData) {
	const { user, pass, host, port, auth } = parseProxyConfig(proxyStr, 1080);
	const socket = connect({ hostname: bracketIPv6(host), port: port });
	await waitSocketOpened(socket, 5000);
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();
	// همون رفع باگ «یک read ممکنه نصفه‌نیمه برسه» که در connectSocks5 اعمال شد، اینجا هم لازمه.
	const readAtLeast = async (r, minBytes, ms) => {
		let chunks = [];
		let total = 0;
		const deadline = Date.now() + ms;
		while (total < minBytes) {
			const remaining = deadline - Date.now();
			if (remaining <= 0) throw new Error("timeout");
			const res = await Promise.race([
				r.read(),
				new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), remaining))
			]);
			if (res.done || !res.value) throw new Error("proxy_closed");
			chunks.push(res.value);
			total += res.value.byteLength;
		}
		if (chunks.length === 1) return chunks[0];
		const merged = new Uint8Array(total);
		let offset = 0;
		for (const c of chunks) { merged.set(c, offset); offset += c.byteLength; }
		return merged;
	};
	try {
		const portHigh = (destPort >> 8) & 0xff;
		const portLow = destPort & 0xff;
		let req;
		if (isIPv4(destAddr)) {
			const ipBytes = destAddr.split(".").map(Number);
			req = new Uint8Array([0x04, 0x01, portHigh, portLow, ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3], 0x00]);
		} else {
			const hostBytes = new TextEncoder().encode(destAddr);
			req = new Uint8Array(9 + hostBytes.length + 1);
			req[0] = 0x04;
			req[1] = 0x01;
			req[2] = portHigh;
			req[3] = portLow;
			req[4] = 0x00;
			req[5] = 0x00;
			req[6] = 0x00;
			req[7] = 0x01;
			req[8] = 0x00;
			req.set(hostBytes, 9);
			req[9 + hostBytes.length] = 0x00;
		}
		await writer.write(req);
		let res = await readAtLeast(reader, 2, 4000);
		if (res[0] !== 0x00 || res[1] !== 0x5a) {
			throw new Error("پـروکـسـی SOCKS4 وصل نشد یا اتصال را رد کرد");
		}
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try { writer.releaseLock(); } catch (err) { }
		try { reader.releaseLock(); } catch (err) { }
		try { socket.close(); } catch (err) { }
		throw e;
	}
}
function parseProxyConfig(proxyStr, defaultPort) {
	let user = "",
		pass = "",
		host = "",
		port = defaultPort;
	let auth = false,
		remain = proxyStr;
	if (remain.includes("@")) {
		const atIdx = remain.lastIndexOf("@");
		const authPart = remain.substring(0, atIdx);
		remain = remain.substring(atIdx + 1);
		const colonIdx = authPart.indexOf(":");
		if (colonIdx !== -1) {
			user = authPart.substring(0, colonIdx);
			pass = authPart.substring(colonIdx + 1);
		} else {
			user = authPart;
		}
		auth = true;
	}
	if (remain.startsWith("[")) {
		const closeIdx = remain.indexOf("]");
		if (closeIdx !== -1) {
			host = remain.substring(1, closeIdx);
			if (remain.length > closeIdx + 1 && remain[closeIdx + 1] === ":") port = parseInt(remain.substring(closeIdx + 2)) || defaultPort;
		}
	} else {
		const lastColon = remain.lastIndexOf(":");
		if (lastColon !== -1 && remain.indexOf(":") === lastColon) {
			host = remain.substring(0, lastColon);
			port = parseInt(remain.substring(lastColon + 1)) || defaultPort;
		} else {
			host = remain;
		}
	}
	return { user, pass, host, port, auth };
}
async function connectSocks5(socksStr, destAddr, destPort, initialData) {
	const { user, pass, host, port, auth } = parseProxyConfig(socksStr, 1080);
	const socket = connect({ hostname: bracketIPv6(host), port: port });
	await waitSocketOpened(socket, 5000);
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();
	// بعضی پـروکـسـی‌ها پاسخ SOCKS5 رو توی چند بسته‌ی جدا (چند تا TCP read) می‌فرستن.
	// یک read تنها ممکنه فقط ۱ بایت برگردونه؛ چک کردن ایندکس ۱ روی همچین آرایه‌ای
	// همیشه false می‌شه و باعث خطای الکی «وصل شد ولی دسترسی نداره» می‌شه با اینکه
	// اتصال واقعاً سالمه و فقط باید صبر کرد بقیه‌ی بایت‌ها هم برسن. این تابع به‌جای
	// یک read، تا وقتی حداقل تعداد بایت لازم برسه (یا تایم‌اوت بشه) صبر می‌کنه.
	const readAtLeast = async (r, minBytes, ms) => {
		let chunks = [];
		let total = 0;
		const deadline = Date.now() + ms;
		while (total < minBytes) {
			const remaining = deadline - Date.now();
			if (remaining <= 0) throw new Error("timeout");
			const res = await Promise.race([
				r.read(),
				new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), remaining))
			]);
			if (res.done || !res.value) throw new Error("proxy_closed");
			chunks.push(res.value);
			total += res.value.byteLength;
		}
		if (chunks.length === 1) return chunks[0];
		const merged = new Uint8Array(total);
		let offset = 0;
		for (const c of chunks) { merged.set(c, offset); offset += c.byteLength; }
		return merged;
	};
	try {
		if (auth) {
			await writer.write(new Uint8Array([0x05, 0x02, 0x00, 0x02]));
		} else {
			await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
		}
		let res = await readAtLeast(reader, 2, 4000);
		if (res[0] !== 0x05) throw new Error("پاسخ نامعتبر از سرور (پـروکـسـی SOCKS5 نیست یا خاموش است)");
		const method = res[1];
		if (method === 0x02) {
			const uEnc = new TextEncoder().encode(user);
			const pEnc = new TextEncoder().encode(pass);
			const authReq = new Uint8Array(1 + 1 + uEnc.length + 1 + pEnc.length);
			authReq[0] = 0x01;
			authReq[1] = uEnc.length;
			authReq.set(uEnc, 2);
			authReq[2 + uEnc.length] = pEnc.length;
			authReq.set(pEnc, 3 + uEnc.length);
			await writer.write(authReq);
			let authRes = await readAtLeast(reader, 2, 4000);
			if (authRes[1] !== 0x00) throw new Error("نام کاربری یا رمز عبور پـروکـسـی اشتباه است");
		}
		let addrType = 0x03;
		let addrBytes;
		if (isIPv4(destAddr)) {
			addrType = 0x01;
			addrBytes = new Uint8Array(destAddr.split(".").map(Number));
		} else if (destAddr.includes(":")) {
			addrType = 0x04;
			addrBytes = new Uint8Array(16);
			const blocks = destAddr.split(":");
			for (let i = 0; i < 8; i++) {
				const val = parseInt(blocks[i] || "0", 16);
				addrBytes[i * 2] = (val >> 8) & 0xff;
				addrBytes[i * 2 + 1] = val & 0xff;
			}
		} else {
			const enc = new TextEncoder().encode(destAddr);
			addrBytes = new Uint8Array(1 + enc.length);
			addrBytes[0] = enc.length;
			addrBytes.set(enc, 1);
		}
		const req = new Uint8Array(4 + addrBytes.length + 2);
		req[0] = 0x05;
		req[1] = 0x01;
		req[2] = 0x00;
		req[3] = addrType;
		req.set(addrBytes, 4);
		const portOffset = 4 + addrBytes.length;
		req[portOffset] = (destPort >> 8) & 0xff;
		req[portOffset + 1] = destPort & 0xff;
		await writer.write(req);
		let connRes = await readAtLeast(reader, 2, 4000);
		if (connRes[1] !== 0x00) throw new Error("پـروکـسـی وصل شد اما دسترسی به اینترنت آزاد ندارد");
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try { writer.releaseLock(); } catch (err) { }
		try { reader.releaseLock(); } catch (err) { }
		try { socket.close(); } catch (err) { }
		throw e;
	}
}
async function connectHttp(proxyStr, destAddr, destPort, initialData) {
	const { user, pass, host, port, auth } = parseProxyConfig(proxyStr, 80);
	const socket = connect({ hostname: bracketIPv6(host), port: port });
	await waitSocketOpened(socket, 5000);
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();
	const readWithTimeout = (r, ms) => Promise.race([
		r.read(),
		new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms))
	]);
	try {
		const safeDest = destAddr.includes(":") ? `[${destAddr}]` : destAddr;
		let req = `CONNECT ${safeDest}:${destPort} HTTP/1.1\r\nHost: ${safeDest}:${destPort}\r\n`;
		if (auth) {
			const authBase64 = btoa(`${user}:${pass}`);
			req += `Proxy-Authorization: Basic ${authBase64}\r\n`;
		}
		req += "\r\n";
		await writer.write(new TextEncoder().encode(req));
		let resStr = "";
		const dec = new TextDecoder();
		while (true) {
			const res = await readWithTimeout(reader, 4000);
			if (res.done || !res.value) throw new Error("proxy_closed");
			resStr += dec.decode(res.value, { stream: true });
			if (resStr.includes("\r\n\r\n")) {
				const match = resStr.match(/^HTTP\/\d\.\d\s+(\d+)/);
				if (match && match[1] === "200") {
					break;
				} else {
					throw new Error("proxy_error_" + (match ? match[1] : "unknown"));
				}
			}
		}
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try { writer.releaseLock(); } catch (err) { }
		try { reader.releaseLock(); } catch (err) { }
		try { socket.close(); } catch (err) { }
		throw e;
	}
}
const COMMON_HEAD = `
	<script>
		if (localStorage.getItem('color-theme') === 'light' && window.location.pathname === '/ppannell') {
			document.documentElement.classList.remove('dark');
		} else {
			document.documentElement.classList.add('dark');
		}
		try { localStorage.removeItem('proxy_flag_cache'); } catch(e) {}
	</script>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/sortablejs@1.15.2/Sortable.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/qr-code-styling@1.5.0/lib/qr-code-styling.js"></script>
	<link rel="manifest" href="/manifest.json">
	<link rel="icon" type="image/svg+xml" href="/icon.svg">
	<link rel="apple-touch-icon" href="/icon.svg">
	<meta name="theme-color" content="#0a0f1c">
	<meta name="mobile-web-app-capable" content="yes">
	<meta name="apple-mobile-web-app-capable" content="yes">
	<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
	<meta name="apple-mobile-web-app-title" content="ZEUS Panel">
	<link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
	<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.3.2/css/flag-icons.min.css">
	<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@600;700&display=swap" rel="stylesheet">
<script>
	tailwind.config = {
		darkMode: 'class',
		theme: {
			extend: {
				fontFamily: { sans: ['Vazirmatn', 'sans-serif'] },
				colors: {
					amoled: { bg: '#0a0f1c', card: '#111a2e', input: '#16213a', border: '#25324a' },
					navy: { 50: '#eef2f8', 100: '#d7e0ef', 400: '#7089b3', 500: '#3f5a86', 600: '#2f486d', 700: '#243a58', 800: '#1a2b42', 900: '#111c2c' }
				}
			}
		}
	}
</script>
`;
const COMMON_TOAST_HTML = `<div id="toast-container" class="fixed top-5 left-1/2 -translate-x-1/2 z-[9999] flex flex-col gap-2 pointer-events-none"></div>`;
const COMMON_TOAST_JS = `
		function showToast(message, type = 'success') {
			const container = document.getElementById('toast-container');
			const toast = document.createElement('div');
			const colors = type === 'error' 
				? 'bg-red-50 dark:bg-red-900/40 border-red-200 dark:border-red-800 text-red-600 dark:text-red-400' 
				: 'bg-green-50 dark:bg-green-900/40 border-green-200 dark:border-green-800 text-green-700 dark:text-green-500';
			toast.className = 'px-4 py-3 border rounded-md shadow-lg font-bold text-sm transform transition-all duration-300 -translate-y-full opacity-0 ' + colors;
			toast.innerText = message;
			container.appendChild(toast);
			requestAnimationFrame(() => {
				toast.classList.remove('-translate-y-full', 'opacity-0');
			});
			setTimeout(() => {
				toast.classList.add('-translate-y-full', 'opacity-0');
				setTimeout(() => toast.remove(), 300);
			}, 3000);
		}
		window.alert = function(message) {
			let msgStr = message ? message.toString() : '';
			if (msgStr.toLowerCase().includes('d1') && (msgStr.toLowerCase().includes('limit') || msgStr.toLowerCase().includes('exceeded') || msgStr.toLowerCase().includes('daily row'))) {
				msgStr = '❌ سهمیه دیتابیس (D1) شما تمام شده و ساعت 3:30 درست میشه';
			}
			if (msgStr.includes('خطا') || msgStr.includes('⚠️') || msgStr.includes('❌')) {
				showToast(msgStr, 'error');
			} else {
				showToast(msgStr, 'success');
			}
		};
`;
const HTML_TEMPLATES = {
	nginx: `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`,
	setup: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>تعریف رمز عبور پـنـل</title>
	${COMMON_HEAD}
</head>
<body class="bg-gray-100 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex items-center justify-center p-4">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-lg shadow-lg p-8 relative z-10">
		<div class="flex items-center justify-center mb-5">
			<div class="w-11 h-11 rounded-md bg-navy-700 dark:bg-navy-600 flex items-center justify-center">
				<svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
			</div>
		</div>
		<h2 class="text-lg font-bold mb-1.5 text-center text-gray-900 dark:text-zinc-100">تنظیم رمز عبور جدید</h2>
		<p class="text-sm text-gray-500 dark:text-zinc-400 text-center mb-7 leading-relaxed">این اولین ورود شما به پـنـل مدیریت است. لطفاً رمز عبور خود را تعیین کنید.</p>
		<form onsubmit="handleSetup(event)" class="space-y-4">
			<div>
				<label class="block text-xs font-semibold text-gray-600 dark:text-zinc-400 mb-1.5">رمز عبور</label>
				<input type="password" id="password" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-navy-500 focus:border-navy-500 text-sm text-center font-mono" required minlength="4">
			</div>
			<div>
				<label class="block text-xs font-semibold text-gray-600 dark:text-zinc-400 mb-1.5">تکرار رمز عبور</label>
				<input type="password" id="confirm-password" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-navy-500 focus:border-navy-500 text-sm text-center font-mono" required minlength="4">
			</div>
			<button type="submit" id="submit-btn" class="w-full py-2.5 bg-navy-700 hover:bg-navy-800 dark:bg-navy-600 dark:hover:bg-navy-700 text-white font-semibold rounded-md text-sm transition">ثبت و ورود</button>
		</form>
	</div>
	${COMMON_TOAST_HTML}
	<script>
		${COMMON_TOAST_JS};
		async function handleSetup(event) {
			event.preventDefault();
			const password = document.getElementById('password').value.trim();
			const confirmPassword = document.getElementById('confirm-password').value.trim();
			const btn = document.getElementById('submit-btn');
			if (password !== confirmPassword) {
				alert('⚠️ رمز عبور و تکرار آن مطابقت ندارند!');
				return;
			}
			btn.disabled = true;
			btn.innerText = 'در حال ثبت...';
			try {
				const res = await fetch('/api/setup-password', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ password })
				});
				const data = await res.json();
				if (res.ok && data.success) {
					alert('✅ رمز عبور با موفقیت تنظیم شد. در حال ورود...');
					setTimeout(() => {
						window.location.reload();
					}, 1500);
				} else {
					alert('خطا: ' + (data.error || 'عملیات ناموفق بود'));
				}
			} catch (err) {
				alert('خطا در ارتباط با سرور');
			} finally {
				btn.disabled = false;
				btn.innerText = 'ثبت و ورود';
			}
		}
	</script>
</body>
</html>`,
	login: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>ورود به پــنــل مدیریت</title>
	${COMMON_HEAD}
</head>
<body class="bg-gray-100 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex items-center justify-center p-4">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-lg shadow-lg p-8 relative z-10">
		<div id="login-section">
			<div class="flex items-center justify-center mb-5">
				<div class="w-11 h-11 rounded-md bg-navy-700 dark:bg-navy-600 flex items-center justify-center">
					<svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
				</div>
			</div>
			<h2 class="text-lg font-bold mb-6 text-center text-gray-900 dark:text-zinc-100">ورود به پـنـل مدیریت</h2>
			<form onsubmit="handleLogin(event)" class="space-y-4">
				<div>
					<label class="block text-xs font-semibold text-gray-600 dark:text-zinc-400 mb-1.5">رمز عبور</label>
					<input type="password" id="password" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-navy-500 focus:border-navy-500 text-sm text-center font-mono" required>
				</div>
				<button type="submit" id="submit-btn" class="w-full py-2.5 bg-navy-700 hover:bg-navy-800 dark:bg-navy-600 dark:hover:bg-navy-700 text-white font-semibold rounded-md text-sm transition">ورود</button>
			</form>
			<div class="mt-5 text-center">
				<button onclick="toggleRecovery(true)" class="text-xs text-navy-600 dark:text-navy-400 hover:underline font-medium">بازیابی رمز پـنـل</button>
			</div>
		</div>
		<div id="recovery-section" class="hidden">
			<h2 class="text-lg font-bold mb-4 text-center text-gray-900 dark:text-zinc-100">بازیابی رمز پـنـل</h2>
			<div class="mb-5 p-3.5 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900/60 rounded-md text-xs leading-relaxed text-amber-800 dark:text-amber-300">
				برای احراز هویت و اثبات مالکیت پـنـل، از طریق دکمه زیر وارد کلودفلر شوید و توکن دریافتی را کپی کرده و در کادر زیر وارد کنید.
				<a href="https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22workers_subdomain%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_analytics%22%2C%22type%22%3A%22read%22%7D%5D&accountId=*&zoneId=all&name=Zeus-Deployer-Token" target="_blank" class="mt-3 w-full flex items-center justify-center gap-2 py-2 bg-white dark:bg-amoled-input border border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-300 hover:bg-amber-50 dark:hover:bg-amber-950/50 rounded-md font-semibold transition">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
					دریافت توکن
				</a>
			</div>
			<form onsubmit="handleRecovery(event)" class="space-y-4">
				<div>
					<input type="password" id="api-token" placeholder="توکن را وارد کنید" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-amber-500 focus:border-amber-500 text-xs text-center font-mono" required>
				</div>
				<div class="flex gap-2 pt-2">
					<button type="button" onclick="toggleRecovery(false)" class="w-1/3 py-2.5 bg-white dark:bg-transparent border border-gray-300 dark:border-amoled-border text-gray-600 dark:text-zinc-300 hover:bg-gray-50 dark:hover:bg-amoled-input font-semibold rounded-md text-sm transition">انصراف</button>
					<button type="submit" id="recover-btn" class="w-2/3 py-2.5 bg-navy-700 hover:bg-navy-800 dark:bg-navy-600 dark:hover:bg-navy-700 text-white font-semibold rounded-md text-sm transition">بازیابی رمز پـنـل</button>
				</div>
			</form>
		</div>
	</div>
	${COMMON_TOAST_HTML}
	<script>
		${COMMON_TOAST_JS}
		async function handleLogin(event) {
			event.preventDefault();
			const password = document.getElementById('password').value.trim();
			const btn = document.getElementById('submit-btn');
			btn.disabled = true;
			try {
				const res = await fetch('/api/login', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ password })
				});
				const data = await res.json();
				if (res.ok && data.success) {
					window.location.reload();
				} else {
					alert(data.error || '❌ رمز عبور اشتباه است');
				}
			} catch (err) {
				alert('خطا در ارتباط با سرور');
			} finally {
				btn.disabled = false;
			}
		}
		function toggleRecovery(show) {
			document.getElementById('login-section').classList.toggle('hidden', show);
			document.getElementById('recovery-section').classList.toggle('hidden', !show);
		}
		async function handleRecovery(event) {
			event.preventDefault();
			const apiToken = document.getElementById('api-token').value;
			const btn = document.getElementById('recover-btn');
			btn.disabled = true;
			btn.innerText = 'در حال بررسی...';
			try {
				const res = await fetch('/api/recover', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ api_token: apiToken })
				});
				const data = await res.json();
				if (res.ok && data.success) {
					alert('✅ رمز عبور با موفقیت حذف شد. در حال انتقال به صفحه تنظیمات اولیه...');
					setTimeout(() => {
						window.location.reload();
					}, 1500);
				} else {
					alert('❌ ' + (data.error || 'خطا در تایید اطلاعات'));
				}
			} catch (err) {
				alert('خطا در ارتباط با سرور');
			} finally {
				btn.disabled = false;
				btn.innerText = 'بازیابی رمز پـنـل';
			}
		}
	</script>
</body>
</html>`,
	panel: `
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Z Y X</title>
	<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚡</text></svg>">
	<script>
		const originalWarn = console.warn;
		console.warn = (...args) => {
			if (typeof args[0] === 'string' && args[0].includes('cdn.tailwindcss.com')) return;
			originalWarn(...args);
		};
	</script>
	${COMMON_HEAD}
	<link href="https://fonts.googleapis.com/css2?family=Poppins:ital,wght@0,500;0,600;0,700;1,500;1,600&display=swap" rel="stylesheet">
	<style>
		body { font-family: 'Vazirmatn', sans-serif; }
		/* درخشش ملایم و پیوسته‌ی جعبه‌ی آیکون لوگو (کنار متن Z Y X در هدر) */
		@keyframes logoGlow {
			0%, 100% { box-shadow: 0 0 5px 1px rgba(59,130,246,0.55), 0 0 0 0 rgba(96,165,250,0); }
			50% { box-shadow: 0 0 13px 4px rgba(96,165,250,0.9), 0 0 20px 6px rgba(59,130,246,0.35); }
		}
		.logo-glow {
			animation: logoGlow 2.6s ease-in-out infinite;
		}
		/* فونت و استایل شیک‌تر برای متن برند Z Y X کنار لوگو */
		.brand-logo-text {
			font-family: 'Orbitron', 'Vazirmatn', sans-serif;
			font-weight: 700;
			letter-spacing: 0.14em;
			background: linear-gradient(90deg, #60a5fa 0%, #38bdf8 45%, #93c5fd 55%, #60a5fa 100%);
			-webkit-background-clip: text;
			background-clip: text;
			color: transparent !important;
		}
		/* فونت کوچیک‌تر و شیک‌تر برای بج ورژن کنار Z Y X */
		.panel-version-badge {
			font-family: 'Poppins', 'Vazirmatn', sans-serif;
			font-weight: 600;
			font-style: italic;
			letter-spacing: 0.03em;
			opacity: 0.9;
		}
		.zeus-flag {
			display: inline-block;
			width: 1.35em;
			height: 1em;
			vertical-align: -0.15em;
			border-radius: 2px;
			background-size: cover;
			background-position: 50%;
			background-repeat: no-repeat;
		}
		.zeus-flag-globe {
			font-size: 1.1em;
			line-height: 1;
			vertical-align: -0.05em;
		}
		body:not(.selection-mode-active) input[name="select-user"] {
			display: none !important;
		}
		body:not(.reorder-mode-active) .drag-handle {
			display: none !important;
		}
		input[type="checkbox"] {
			accent-color: #16a34a;
		}
		.dark input[type="checkbox"] {
			filter: none;
		}
		::-webkit-scrollbar {
			width: 6px;
			height: 6px;
		}
		::-webkit-scrollbar-track {
			background: #f3f4f6; 
			border-radius: 4px;
		}
		::-webkit-scrollbar-thumb {
			background: #d1d5db; 
			border-radius: 4px;
		}
		::-webkit-scrollbar-thumb:hover {
			background: #9ca3af;
		}
		html.dark::-webkit-scrollbar-track,
		.dark *::-webkit-scrollbar-track {
			background: #0a0f1c !important;
		}
		html.dark::-webkit-scrollbar-thumb,
		.dark *::-webkit-scrollbar-thumb {
			background: #25324a !important;
		}
		html.dark::-webkit-scrollbar-thumb:hover,
		.dark *::-webkit-scrollbar-thumb:hover {
			background: #354968 !important;
		}
		html, * {
			scrollbar-width: thin;
			scrollbar-color: #d1d5db #f3f4f6;
		}
		
		html.dark, .dark * {
			scrollbar-color: #25324a #0a0f1c !important;
		}
		@media (min-width: 769px) {
			header, main { zoom: 1.25; }
		}
		@media (max-width: 768px) {
			header, main { zoom: 0.90; }
		}
		input[type="number"]::-webkit-outer-spin-button,
		input[type="number"]::-webkit-inner-spin-button {
			-webkit-appearance: none;
			margin: 0;
		}
		input[type="number"] {
			-moz-appearance: textfield;
		}
		@keyframes violentShake {
			0%, 100% { transform: translateX(0); }
			10%, 30%, 50%, 70%, 90% { transform: translateX(-4px) rotate(-3deg); }
			20%, 40%, 60%, 80% { transform: translateX(4px) rotate(3deg); }
		}
		.animate-violent-shake {
			animation: violentShake 0.4s cubic-bezier(.36,.07,.19,.97) infinite;
		}
		@keyframes symBounce {
			0%, 100% { transform: translateY(-2px); }
			50% { transform: translateY(2px); }
		}
		.animate-sym-bounce {
			animation: symBounce 2s ease-in-out infinite;
		}
		/* نبض کوتاه یک لحظه‌ای، شبیه نبض نشانگر Live، درست قبل از تغییر عدد مصرف */
		@keyframes liveValuePulse {
			0% { transform: scale(1); filter: brightness(1); }
			35% { transform: scale(1.35); filter: brightness(1.35); }
			100% { transform: scale(1); filter: brightness(1); }
		}
		.live-value-pulse {
			display: inline-block;
			animation: liveValuePulse 0.55s ease-out;
		}
		/* نور نئون با یک درخشش ملایم و ثابت دور هر کارت + یک جرقه‌ی نور که به آرامی
		   دور لبه‌ی کارت سر می‌خورد (نه یک گوه‌ی درشت که کل کارت دور خودش بچرخد). */
		@keyframes neonOrbitTravel {
			0% { background-position: 0% 0%; }
			100% { background-position: 400% 0%; }
		}
		@keyframes neonOrbitGlow {
			0%, 100% { opacity: 0.25; }
			50% { opacity: 0.5; }
		}
		.neon-orbit {
			position: relative;
			isolation: isolate;
		}
		/* حلقه‌ی نئون با دو لایه ساخته می‌شود، نه با mask: چون این پنل روی header/main یک
		   zoom غیر-۱ (۱.۲۵ دسکتاپ / ۰.۹ موبایل، چند خط پایین‌تر) می‌گذارد و mask چندلایه‌ی
		   ترکیبی (content-box + composite:exclude) زیر zoom در کرومیوم درست کامپوزیت نمی‌شود.
		   این روش mask را کنار می‌گذارد: ::before نور را کامل زیر کارت می‌کشد، ::after با
		   همون رنگ پس‌زمینه‌ی خود کارت (روشن/تاریک) همه‌جا به‌جز یک حلقه‌ی ۲ پیکسلی را می‌پوشاند -
		   نتیجه یک حلقه‌ی نازک دور کارت، بدون هیچ کامپوزیت مسک‌ای. */
		.neon-orbit::before {
			content: '';
			position: absolute;
			inset: 0;
			z-index: 0;
			border-radius: inherit;
			pointer-events: none;
			background-size: 400% 100%;
			animation: neonOrbitTravel 18s linear infinite, neonOrbitGlow 6s ease-in-out infinite;
		}
		.neon-orbit::after {
			content: '';
			position: absolute;
			inset: 2px;
			z-index: 0;
			border-radius: inherit;
			pointer-events: none;
			background: #ffffff;
		}
		.dark .neon-orbit::after {
			background: #111a2e;
		}
		.neon-orbit > * {
			position: relative;
			z-index: 1;
		}
		.neon-orbit-1::before {
			background-image: linear-gradient(90deg, transparent 0%, #fb923c 8%, transparent 20%, transparent 75%, #fb923c 87%, transparent 100%);
			animation-duration: 16s, 6s;
		}
		.neon-orbit-2::before {
			background-image: linear-gradient(90deg, transparent 0%, #c084fc 8%, transparent 20%, transparent 75%, #c084fc 87%, transparent 100%);
			animation-duration: 21s, 6.6s;
			animation-direction: reverse, normal;
		}
		.neon-orbit-3::before {
			background-image: linear-gradient(90deg, transparent 0%, #60a5fa 8%, transparent 20%, transparent 75%, #60a5fa 87%, transparent 100%);
			animation-duration: 18.5s, 7.2s;
		}

		/* ============================================================
		   بازطراحی کامل کارت کاربران (کلاس‌های uc- = user-card)
		   ============================================================ */
		.uc-card {
			position: relative;
			overflow: hidden;
			border-radius: 16px;
			padding: 9px;
			display: flex;
			flex-direction: column;
			gap: 8px;
			background: linear-gradient(160deg, #ffffff, #f4f6fb);
			border: 1px solid rgba(148,163,184,0.28);
			box-shadow: 0 1px 2px rgba(15,23,42,0.05), 0 10px 22px -16px rgba(15,23,42,0.35);
			transition: transform 0.22s ease, box-shadow 0.22s ease;
		}
		.dark .uc-card {
			background: linear-gradient(160deg, #121b30, #0b1120);
			border-color: rgba(51,65,85,0.55);
			box-shadow: 0 1px 2px rgba(0,0,0,0.35), 0 12px 26px -16px rgba(0,0,0,0.65);
		}
		.uc-card:hover { transform: translateY(-2px); }
		.uc-top { display: flex; align-items: center; gap: 6px; width: 100%; }
		.uc-checkbox { width: 17px; height: 17px; border-radius: 6px; border: 1.5px solid #cbd5e1; flex-shrink: 0; cursor: pointer; }
		.uc-drag { cursor: grab; color: #94a3b8; font-size: 15px; flex-shrink: 0; user-select: none; line-height: 1; }
		.uc-drag:active { cursor: grabbing; }
		.uc-avatar {
			position: relative;
			width: 33px; height: 33px; border-radius: 11px; flex-shrink: 0;
			display: flex; align-items: center; justify-content: center;
			color: #fff; font-weight: 700; font-size: 13.5px;
			font-family: 'Poppins', 'Vazirmatn', sans-serif;
			box-shadow: inset 0 0 0 1px rgba(255,255,255,0.3);
		}
		@keyframes ucAvatarAlarm {
			0%, 100% { background-color: #dc2626; box-shadow: inset 0 0 0 1px rgba(255,255,255,0.3), 0 0 0 0 rgba(220,38,38,0.65); }
			50% { background-color: #7f1d1d; box-shadow: inset 0 0 0 1px rgba(255,255,255,0.3), 0 0 0 5px rgba(220,38,38,0); }
		}
		.uc-avatar-alarm { animation: ucAvatarAlarm 1s ease-in-out infinite; }
		.uc-online-dot {
			position: absolute; bottom: -2px; right: -2px;
			width: 10px; height: 10px; border-radius: 50%;
			border: 2px solid #ffffff;
		}
		.dark .uc-online-dot { border-color: #0f1729; }
		.uc-identity { min-width: 0; flex: 1; display: flex; flex-direction: column; gap: 2px; }
		.uc-username {
			font-family: 'Poppins', 'Vazirmatn', sans-serif;
			font-weight: 600; font-size: 13.5px; color: #0f172a;
			white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
		}
		.dark .uc-username { color: #f1f5f9; }
		.uc-subline { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }
		.uc-chip {
			display: inline-flex; align-items: center; gap: 2px;
			padding: 1px 6px; border-radius: 999px;
			font-weight: 700; font-size: 9px; white-space: nowrap;
		}
		.uc-chip-infinite { color: #2563eb; }
		.dark .uc-chip-infinite { color: #60a5fa; }
		.uc-more-btn {
			width: 27px; height: 27px; border-radius: 9px; flex-shrink: 0; padding: 0; border: 1px solid rgba(100,116,139,0.18);
			display: flex; align-items: center; justify-content: center;
			background: rgba(100,116,139,0.1); color: #475569;
			transition: background 0.2s ease, transform 0.15s ease;
		}
		.uc-more-btn:hover { background: rgba(100,116,139,0.2); }
		.uc-more-btn:active { transform: scale(0.9); }
		.dark .uc-more-btn { color: #cbd5e1; background: rgba(148,163,184,0.12); border-color: rgba(148,163,184,0.22); }
		.uc-stats { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; width: 100%; }
		.uc-actions-overlay {
			position: absolute; inset: 0; z-index: 30;
			display: flex; align-items: center; justify-content: center;
			background: rgba(255,255,255,0.98);
			border-radius: 16px; padding: 8px;
			opacity: 0; pointer-events: none; transform: scale(0.95);
			transition: opacity 0.16s ease, transform 0.16s ease;
		}
		.dark .uc-actions-overlay { background: rgba(9,14,27,0.98); }
		.uc-actions-overlay.uc-actions-open { opacity: 1; pointer-events: auto; transform: scale(1); }
		.uc-actions-inner { width: 100%; max-height: 100%; overflow-y: auto; display: flex; flex-direction: column; gap: 4px; }
		.uc-actions-header { display: flex; justify-content: flex-start; }
		.uc-action-close {
			width: 20px; height: 20px; border-radius: 7px; padding: 0; border: none;
			display: flex; align-items: center; justify-content: center;
			font-size: 11px; color: #94a3b8; background: rgba(100,116,139,0.12);
		}
		.uc-actions-grid { display: flex; flex-wrap: wrap; justify-content: center; gap: 7px; padding: 2px 0; }
		.uc-action-btn {
			width: 34px; height: 34px; border-radius: 10px; padding: 0; border: none;
			display: flex; align-items: center; justify-content: center;
			transition: transform 0.15s ease;
		}
		.uc-action-btn:active { transform: scale(0.88); }
		.cf-ring-svg { transform: rotate(-90deg); }
		.cf-ring-track { stroke: currentColor; }
		.cf-ring-bar {
			stroke-linecap: round;
			animation: cfRingReach 2.2s ease-in-out infinite;
		}
		@keyframes cfRingReach {
			0%, 100% { stroke-dashoffset: var(--cf-offset); filter: drop-shadow(0 0 0 transparent); }
			50% { stroke-dashoffset: var(--cf-offset-reach); filter: drop-shadow(0 0 3px currentColor); }
		}
		/* ============================================================
		   تم شیشه‌ای (Glass) - هم حالت تاریک (برگرفته از Sample.html) و هم حالت روشن
		   بکگراند: سه orb محو و متحرک روی زمینه (تاریک: رنگ‌های عمیق / روشن: رنگ‌های پاستلی)
		   کارت: بلور + saturate + خط نور
		   ============================================================ */
		.ambient {
			position: fixed;
			inset: 0;
			z-index: -1;
			background: #f2f5fc;
			overflow: hidden;
			pointer-events: none;
		}
		.ambient .orb {
			position: absolute;
			border-radius: 50%;
			filter: blur(90px);
			opacity: 0.7;
			animation: zyxAmbientFloat 20s ease-in-out infinite alternate;
		}
		.ambient .o1 { width: 85vmin; height: 85vmin; top: -25%; right: -30%; background: #93c5fd; }
		.ambient .o2 { width: 70vmin; height: 70vmin; bottom: 10%; left: -35%; background: #c4b5fd; animation-delay: -8s; }
		.ambient .o3 { width: 50vmin; height: 50vmin; top: 40%; left: 20%; background: #67e8f9; opacity: 0.45; animation-delay: -4s; }
		.dark .ambient { background: #050508; }
		.dark .ambient .o1 { background: #1e3a8a; opacity: 0.65; }
		.dark .ambient .o2 { background: #5b21b6; opacity: 0.65; }
		.dark .ambient .o3 { background: #0e7490; opacity: 0.35; }
		@keyframes zyxAmbientFloat { to { transform: translate(4%, 6%) scale(1.08); } }
		@media (prefers-reduced-motion: reduce) {
			.ambient .orb { animation: none; }
		}
		/* ---- کارت‌های شیشه‌ای: حالت روشن ---- */
		#card-cf-requests,
		#card-traffic,
		#card-d1-usage,
		#users-toolbar,
		.uc-card {
			background: linear-gradient(145deg, rgba(255,255,255,0.82) 0%, rgba(255,255,255,0.42) 100%);
			-webkit-backdrop-filter: blur(40px) saturate(180%);
			backdrop-filter: blur(40px) saturate(180%);
			border: 1px solid rgba(255,255,255,0.8);
			box-shadow: 0 12px 32px -14px rgba(51,65,130,0.32), 0 0 0 0.5px rgba(100,116,139,0.14), inset 0 1px 0 rgba(255,255,255,0.95);
		}
		.uc-card {
			-webkit-backdrop-filter: blur(24px) saturate(180%);
			backdrop-filter: blur(24px) saturate(180%);
		}
		#card-cf-requests:hover { border-color: rgba(251,146,60,0.6); }
		#card-traffic:hover { border-color: rgba(96,165,250,0.6); }
		#card-d1-usage:hover { border-color: rgba(192,132,252,0.6); }
		/* حلقه‌ی نئون روی کارت شیشه‌ای: لایه‌ی ::after مات حذف می‌شود و حلقه‌ی ۲ پیکسلی فقط با clip-path
		   (بدون mask) از همان ::before بریده می‌شود؛ پس شفافیت شیشه حفظ می‌شود. */
		.neon-orbit::after { display: none; }
		.neon-orbit::before {
			clip-path: polygon(evenodd, 0 0, 100% 0, 100% 100%, 0 100%, 0 0, 2px 2px, 2px calc(100% - 2px), calc(100% - 2px) calc(100% - 2px), calc(100% - 2px) 2px, 2px 2px);
		}
		header.z-10 {
			background: linear-gradient(180deg, rgba(255,255,255,0.7), rgba(255,255,255,0.45));
			-webkit-backdrop-filter: blur(40px) saturate(180%);
			backdrop-filter: blur(40px) saturate(180%);
			border-color: rgba(255,255,255,0.8);
		}
		#users-toolbar input,
		#users-toolbar select {
			background: rgba(255,255,255,0.6);
			border-color: rgba(148,163,184,0.35);
		}
		/* ---- کارت‌های شیشه‌ای: حالت تاریک ---- */
		.dark {
			--glass-stroke: rgba(255, 255, 255, 0.15);
			--glass-stroke-soft: rgba(255, 255, 255, 0.06);
			--glass-specular: rgba(255, 255, 255, 0.28);
			--glass-fill: rgba(255, 255, 255, 0.045);
			--glass-shadow: 0 14px 36px rgba(0, 0, 0, 0.4);
		}
		.dark #card-cf-requests,
		.dark #card-traffic,
		.dark #card-d1-usage,
		.dark #users-toolbar,
		.dark .uc-card {
			background: linear-gradient(145deg, rgba(255,255,255,0.1) 0%, transparent 38%);
			-webkit-backdrop-filter: blur(40px) saturate(200%) brightness(0.96);
			backdrop-filter: blur(40px) saturate(200%) brightness(0.96);
			border: 0.5px solid var(--glass-stroke);
			box-shadow: var(--glass-shadow), inset 0 1px 0 var(--glass-specular), inset 0 -1px 0 rgba(255,255,255,0.04);
		}
		/* کارت کاربران تعدادشان زیاد می‌شود؛ بلور سبک‌تر برای روان‌ماندن اسکرول */
		.dark .uc-card {
			-webkit-backdrop-filter: blur(24px) saturate(200%) brightness(0.96);
			backdrop-filter: blur(24px) saturate(200%) brightness(0.96);
		}
		.dark #card-cf-requests:hover { border-color: rgba(251,146,60,0.5); }
		.dark #card-traffic:hover { border-color: rgba(96,165,250,0.5); }
		.dark #card-d1-usage:hover { border-color: rgba(192,132,252,0.5); }
		.dark header.z-10 {
			background: var(--glass-fill);
			-webkit-backdrop-filter: blur(40px) saturate(200%) brightness(0.96);
			backdrop-filter: blur(40px) saturate(200%) brightness(0.96);
			border-color: var(--glass-stroke-soft);
		}
		.dark #users-toolbar input,
		.dark #users-toolbar select {
			background: var(--glass-fill);
			border-color: var(--glass-stroke-soft);
		}
		.dark #users-toolbar select option { background: #0b0f1a; color: #e4e4e7; }
		.dark svg.cf-ring-svg .cf-ring-track { color: rgba(255,255,255,0.12); }
		.dark .uc-actions-overlay { background: rgba(6,8,14,0.94); }

		/* ============================================================
		   دُک (Dock) پنج‌آیکون بالای صفحه: یک کپسول شیشه‌ای با کاشی‌های رنگی و آیکون‌های دوتونه
		   ============================================================ */
		.zdock {
			display: inline-flex;
			align-items: center;
			gap: 5.1px;
			padding: 5.1px;
			border-radius: 18.7px;
			background: linear-gradient(160deg, rgba(255,255,255,0.85), rgba(255,255,255,0.5));
			border: 1px solid rgba(255,255,255,0.9);
			box-shadow: 0 14px 32px -14px rgba(67,56,202,0.45), 0 0 0 0.5px rgba(100,116,139,0.14), inset 0 1px 0 rgba(255,255,255,1);
			-webkit-backdrop-filter: blur(24px) saturate(180%);
			backdrop-filter: blur(24px) saturate(180%);
		}
		.dark .zdock {
			background: rgba(255,255,255,0.05);
			border: 0.5px solid rgba(255,255,255,0.16);
			box-shadow: 0 14px 34px rgba(0,0,0,0.45), inset 0 1px 0 rgba(255,255,255,0.28);
		}
		.zdock-sep {
			width: 1px;
			height: 20.4px;
			border-radius: 1px;
			background: rgba(100,116,139,0.32);
			margin: 0 1px;
		}
		.dark .zdock-sep { background: rgba(255,255,255,0.16); }
		.zdock-btn {
			--c: 79, 70, 229;
			position: relative;
			width: 34px;
			height: 34px;
			padding: 0;
			border-radius: 11.9px;
			display: inline-flex;
			align-items: center;
			justify-content: center;
			cursor: pointer;
			color: rgb(var(--c));
			background: linear-gradient(160deg, rgba(var(--c), 0.2), rgba(var(--c), 0.06));
			border: 1px solid rgba(var(--c), 0.28);
			transition: transform 0.2s cubic-bezier(0.3, 1.5, 0.5, 1), box-shadow 0.2s ease, background 0.2s ease;
		}
		.zdock-btn:hover {
			transform: translateY(-3px) scale(1.1);
			background: linear-gradient(160deg, rgba(var(--c), 0.34), rgba(var(--c), 0.12));
			box-shadow: 0 10px 18px -8px rgba(var(--c), 0.75);
		}
		.zdock-btn:active { transform: scale(0.92); }
		.zdock-btn:focus-visible { outline: 2px solid rgba(var(--c), 0.8); outline-offset: 2px; }
		.zdock-btn:disabled { opacity: 0.55; cursor: wait; transform: none; box-shadow: none; }
		.zdock-btn svg { width: 17.85px; height: 17.85px; }
		.zb-logout { --c: 225, 29, 72; }
		.zb-settings { --c: 2, 132, 199; }
		.zb-theme { --c: 217, 119, 6; }
		.zb-update { --c: 124, 58, 237; }
		.zb-import { --c: 5, 150, 105; }
		.dark .zb-logout { --c: 251, 113, 133; }
		.dark .zb-settings { --c: 56, 189, 248; }
		.dark .zb-theme { --c: 251, 191, 36; }
		.dark .zb-update { --c: 167, 139, 250; }
		.dark .zb-import { --c: 52, 211, 153; }
	</style>
</head>
<body class="bg-gray-100 dark:bg-amoled-bg text-gray-900 dark:text-zinc-100 min-h-screen transition-colors duration-200">
	<div class="ambient" aria-hidden="true">
		<div class="orb o1"></div>
		<div class="orb o2"></div>
		<div class="orb o3"></div>
	</div>
	<header class="border-b border-gray-200 dark:border-amoled-border bg-gray-50/95 dark:bg-amoled-card/95 px-4 py-4 relative z-10">
		<div class="max-w-6xl mx-auto flex flex-col md:flex-row justify-between items-center gap-2 md:gap-4">
			<div class="flex items-center justify-center w-full md:w-auto mt-3 md:mt-0">
				<div class="zdock">
					<button onclick="logoutAdmin()" class="zdock-btn zb-logout" title="خروج">
						<svg fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="12" cy="13" r="8" fill="currentColor" fill-opacity="0.18" stroke="none"></circle><path d="M12 3.5v8"></path><path d="M7 7.2a7.6 7.6 0 1 0 10 0"></path></svg>
					</button>
					<span class="zdock-sep"></span>
					<button onclick="toggleSettingsModal(true)" class="zdock-btn zb-settings" title="تنظیمات">
						<svg fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M4 6.5h16M4 12h16M4 17.5h16" stroke-opacity="0.4"></path><circle cx="9" cy="6.5" r="2.4" fill="currentColor"></circle><circle cx="15.5" cy="12" r="2.4" fill="currentColor"></circle><circle cx="8" cy="17.5" r="2.4" fill="currentColor"></circle></svg>
					</button>
					<button id="theme-toggle" class="zdock-btn zb-theme" title="تغییر تم">
						<svg id="sun-icon" class="hidden dark:block" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4.2" fill="currentColor" fill-opacity="0.25"></circle><path d="M12 2.8v2.4M12 18.8v2.4M2.8 12h2.4M18.8 12h2.4M5.5 5.5l1.7 1.7M16.8 16.8l1.7 1.7M5.5 18.5l1.7-1.7M16.8 7.2l1.7-1.7"></path></svg>
						<svg id="moon-icon" class="block dark:hidden" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" fill="currentColor" fill-opacity="0.25"></path><path d="M17 3.5v3M15.5 5h3"></path></svg>
					</button>
					<button id="github-update-toggle" onclick="applyGithubUpdate()" class="zdock-btn zb-update" title="Update">
						<svg fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3.2" fill="currentColor" fill-opacity="0.25" stroke="none"></circle><path d="M23 4v6h-6M1 20v-6h6"></path><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
					</button>
					<button onclick="toggleImportModal(true)" class="zdock-btn zb-import" title="ایمپورت کاربران">
						<svg fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="10" cy="8" r="3.6" fill="currentColor" fill-opacity="0.25"></circle><path d="M3.5 20.5a6.5 6.5 0 0 1 13 0"></path><path d="M19.5 7.5v6M16.5 10.5h6"></path></svg>
					</button>
				</div>
			</div>
			<div id="global-location-badges" class="hidden flex-1 flex flex-col items-center justify-center gap-1 w-full md:w-auto"></div>
			<div class="flex flex-row flex-wrap justify-center items-center gap-3 w-full md:w-auto">
				<h1 class="text-lg font-bold flex items-center gap-2.5" dir="ltr">
					<span class="tracking-wide brand-logo-text">Z Y X</span>
					<span id="panel-version" class="panel-version-badge text-[8.5px] px-1.5 py-0.5 bg-navy-100 text-navy-700 dark:bg-navy-900/40 dark:text-navy-400 rounded-full"></span>
				</h1>
			</div>
		</div>
	</header>
	<main class="max-w-6xl mx-auto px-4 pt-4 pb-56 md:pb-32 relative z-10">
<div class="flex flex-col lg:flex-row gap-3 mb-4 items-start">
<div class="w-full lg:w-64 shrink-0 flex flex-col gap-3">
	<div id="card-cf-requests" onclick="openUsageChart('requests')" class="neon-orbit neon-orbit-1 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md p-2.5 shadow-sm flex flex-col justify-center gap-1 hover:shadow-md hover:border-orange-400 dark:hover:border-orange-500/50 transition duration-300 relative overflow-hidden group min-h-[64px] cursor-pointer">
		<div class="flex items-center justify-center gap-1.5 relative z-10">
			<span class="text-[11px] sm:text-xs font-semibold text-gray-500 dark:text-zinc-400 whitespace-nowrap text-center">Request</span>
			<div class="p-1 bg-orange-50 dark:bg-orange-950/30 text-orange-600 dark:text-orange-400 rounded-md flex-shrink-0">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z"></path></svg>
			</div>
		</div>
		<div class="relative z-10 min-w-0 flex-1 w-full mt-1">
			<div class="grid grid-cols-3 gap-1 w-full mb-1.5">
				<div class="flex flex-col items-center justify-center">
					<div class="flex items-baseline gap-1" dir="ltr">
						<span class="text-xs font-black text-orange-600 dark:text-orange-400 transition-all leading-none whitespace-nowrap" id="stat-cf-requests">0</span>
						<span class="text-[9px] font-bold text-gray-400 leading-none">/ 100k</span>
						<button id="cf-warning-btn" onclick="event.stopPropagation(); openUsageWarning()" class="hidden items-center justify-center w-3 h-3 bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 rounded-full font-bold text-[9px] animate-bounce shadow-sm border border-red-300 dark:border-red-700 leading-none">!</button>
					</div>
					<span class="text-[8px] font-medium text-gray-500 dark:text-zinc-400 mt-1 whitespace-nowrap" dir="ltr">24h</span>
				</div>
				<div class="flex flex-col items-center justify-center border-x border-gray-100 dark:border-zinc-800">
					<span class="text-xs font-black text-orange-600 dark:text-orange-400 transition-all leading-none whitespace-nowrap" id="stat-cf-requests-7d">0</span>
					<span class="text-[8px] font-medium text-gray-500 dark:text-zinc-400 mt-1 whitespace-nowrap" dir="ltr">7d</span>
				</div>
				<div class="flex flex-col items-center justify-center">
					<span class="text-xs font-black text-orange-600 dark:text-orange-400 transition-all leading-none whitespace-nowrap" id="stat-cf-requests-30d">0</span>
					<span class="text-[8px] font-medium text-gray-500 dark:text-zinc-400 mt-1 whitespace-nowrap" dir="ltr">30d</span>
				</div>
			</div>
			<div class="flex items-center justify-center mt-1.5">
				<div class="relative w-[52.8px] h-[52.8px] shrink-0">
					<svg class="cf-ring-svg w-[52.8px] h-[52.8px]" viewBox="0 0 40 40">
						<circle class="cf-ring-track text-gray-200 dark:text-zinc-800" cx="20" cy="20" r="16" fill="none" stroke-width="3.5"></circle>
						<circle id="stat-cf-progress" class="cf-ring-bar" cx="20" cy="20" r="16" fill="none" stroke-width="3.5" stroke-dasharray="100.53" style="--cf-offset:100.53; --cf-offset-reach:100.53; stroke-dashoffset:100.53;"></circle>
					</svg>
					<span id="stat-cf-progress-pct" class="absolute inset-0 flex items-center justify-center text-[10.8px] font-bold text-gray-800 dark:text-zinc-200">۰٪</span>
				</div>
			</div>
		</div>
	</div>
	<div id="card-traffic" onclick="openUsageChart('traffic')" class="neon-orbit neon-orbit-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-sm hover:shadow-md hover:border-blue-400 dark:hover:border-blue-500/50 transition duration-300 relative overflow-hidden group min-h-[128px] cursor-pointer">
		<div id="traffic-card-chart" class="absolute inset-[2px] rounded-[6px] overflow-hidden pointer-events-none"></div>
		<div class="absolute inset-[2px] rounded-[6px] flex flex-col justify-between p-2.5 bg-gradient-to-b from-white/90 via-white/60 to-white/10 dark:from-black/30 dark:via-black/15 dark:to-transparent">
			<div class="flex items-center justify-center gap-1.5">
				<span class="text-[11px] sm:text-xs font-semibold text-gray-500 dark:text-zinc-400 whitespace-nowrap text-center">Traffic</span>
				<div class="p-1 bg-blue-50 dark:bg-blue-950/30 text-blue-600 dark:text-blue-400 rounded-md flex-shrink-0">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
				</div>
			</div>
			<div class="grid grid-cols-3 gap-1 w-full">
				<div class="flex flex-col items-center justify-center">
					<span class="text-xs font-black text-blue-600 dark:text-blue-400 transition-all leading-none whitespace-nowrap" dir="ltr" id="stat-usage-daily">0 GB</span>
					<span class="text-[8px] font-medium text-gray-500 dark:text-zinc-400 mt-1 whitespace-nowrap" dir="ltr">24h</span>
				</div>
				<div class="flex flex-col items-center justify-center border-x border-gray-100 dark:border-zinc-800">
					<span class="text-xs font-black text-blue-600 dark:text-blue-400 transition-all leading-none whitespace-nowrap" dir="ltr" id="stat-usage-7d">0 GB</span>
					<span class="text-[8px] font-medium text-gray-500 dark:text-zinc-400 mt-1 whitespace-nowrap" dir="ltr">7d</span>
				</div>
				<div class="flex flex-col items-center justify-center">
					<span class="text-xs font-black text-blue-600 dark:text-blue-400 transition-all leading-none whitespace-nowrap" dir="ltr" id="stat-usage-30d">0 GB</span>
					<span class="text-[8px] font-medium text-gray-500 dark:text-zinc-400 mt-1 whitespace-nowrap" dir="ltr">30d</span>
				</div>
			</div>
		</div>
	</div>
	<div id="card-d1-usage" class="neon-orbit neon-orbit-2 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md p-2.5 shadow-sm flex flex-col justify-center gap-1 hover:shadow-md hover:border-purple-400 dark:hover:border-purple-500/50 transition duration-300 relative overflow-hidden group min-h-[64px]">
		<div class="flex items-center justify-center gap-1.5 relative z-10">
			<span class="text-[11px] sm:text-xs font-semibold text-gray-500 dark:text-zinc-400 whitespace-nowrap text-center">D1</span>
			<div class="p-1 bg-purple-50 dark:bg-purple-950/30 text-purple-600 dark:text-purple-400 rounded-md flex-shrink-0">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"></path></svg>
			</div>
		</div>
		<div class="relative z-10 min-w-0 flex-1 w-full mt-1">
			<div class="grid grid-cols-2 gap-2 w-full mb-1.5">
				<div class="flex flex-col items-start justify-center">
					<div class="flex items-baseline gap-1" dir="ltr">
						<span class="text-sm font-black text-purple-600 dark:text-purple-400 transition-all leading-none" id="stat-d1-writes">0</span>
						<span class="text-[9px] font-bold text-gray-400 leading-none">/ 100k</span>
					</div>
					<span class="text-[9px] font-medium text-gray-500 dark:text-zinc-400 mt-1">Write</span>
				</div>
				<div class="flex flex-col items-end justify-center border-r border-gray-100 dark:border-zinc-800 pr-2">
					<div class="flex items-baseline gap-1" dir="ltr">
						<span class="text-sm font-black text-purple-600 dark:text-purple-400 transition-all leading-none" id="stat-d1-reads">0</span>
						<span class="text-[9px] font-bold text-gray-400 leading-none">/ 5M</span>
					</div>
					<span class="text-[9px] font-medium text-gray-500 dark:text-zinc-400 mt-1">Read</span>
				</div>
			</div>
			<div class="w-full bg-gray-100 dark:bg-zinc-800 rounded-full h-1 mt-1">
				<div id="stat-d1-progress" class="bg-purple-500 h-1 rounded-full transition-all duration-500 min-w-[6px]" style="width: 0%"></div>
			</div>
		</div>
	</div>
</div>
<div class="flex-1 w-full min-w-0">
		<div id="loading-state" class="text-center py-12">
			<span class="text-gray-500 dark:text-gray-400">در حال بارگذاری کاربران...</span>
		</div>
		<div id="add-user-only-bar" class="hidden mb-4">
			<button onclick="openCreateModal()" title="افزودن کاربر" class="scale-[0.4] p-2 rounded-full bg-green-50 dark:bg-green-950/30 border-2 border-green-600 dark:border-green-700/60 hover:bg-green-100 dark:hover:bg-green-900/50 transition-all duration-300 text-green-700 dark:text-green-400 shadow-sm hover:shadow hover:scale-[0.44] cursor-pointer inline-flex items-center justify-center shrink-0">
				<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"></path></svg>
			</button>
		</div>
		<div id="users-toolbar" class="mb-4 flex flex-col md:flex-row gap-2 justify-between items-center bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md p-2 shadow-sm">
			<div class="flex items-center gap-2 shrink-0">
				<button onclick="openCreateModal()" title="افزودن کاربر" class="scale-[0.7] p-2 rounded-full bg-green-50 dark:bg-green-950/30 border-2 border-green-600 dark:border-green-700/60 hover:bg-green-100 dark:hover:bg-green-900/50 transition-all duration-300 text-green-700 dark:text-green-400 shadow-sm hover:shadow hover:scale-[0.77] cursor-pointer inline-flex items-center justify-center shrink-0">
					<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"></path></svg>
				</button>
				<label class="scale-[0.7] flex items-center gap-1.5 cursor-pointer select-none whitespace-nowrap text-xs font-bold text-gray-700 dark:text-gray-300 shrink-0">
					<input type="checkbox" id="select-all-users" onchange="toggleSelectAllUsers(this)" class="w-5 h-5 rounded-md border-2 border-gray-300 dark:border-zinc-700 text-green-600 bg-white dark:bg-zinc-900 checked:bg-green-600 checked:border-green-600 focus:ring-green-500/50 focus:ring-offset-0 transition-all duration-200 cursor-pointer hover:scale-105 active:scale-95" style="filter: none !important; accent-color: #16a34a !important;">
					<span>انتخاب همه</span>
				</label>
				<button type="button" id="toggle-select-mode-btn" onclick="toggleSelectionMode()" class="scale-[0.7] px-2.5 py-1.5 rounded-md border-2 border-gray-300 dark:border-zinc-700 text-xs font-bold text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-zinc-800 transition-all shrink-0">انتخاب</button>
				<button type="button" id="toggle-reorder-mode-btn" onclick="toggleReorderMode()" class="scale-[0.7] px-2.5 py-1.5 rounded-md border-2 border-gray-300 dark:border-zinc-700 text-xs font-bold text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-zinc-800 transition-all shrink-0">جابجایی</button>
				<button type="button" id="apply-reorder-btn" onclick="applyReorderMode()" class="hidden scale-[0.7] px-2.5 py-1.5 rounded-md border-2 border-green-600 bg-green-50 dark:bg-green-950/30 text-xs font-bold text-green-700 dark:text-green-400 hover:bg-green-100 dark:hover:bg-green-900/50 transition-all shrink-0">اعمال</button>
			</div>
			<div class="relative w-full md:w-[17.5rem] shrink-0">
				<input type="text" id="search-input" oninput="filterAndRenderUsers()" placeholder="جستجوی نام کاربری یا UUID..." class="w-full pl-3 pr-8 py-1.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs">
				<div class="absolute inset-y-0 right-0 flex items-center pr-2.5 pointer-events-none text-gray-400">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
				</div>
			</div>
			<div class="grid grid-cols-1 md:grid-cols-2 gap-2 w-full md:w-auto">
				<select id="filter-status" onchange="filterAndRenderUsers()" class="w-full min-w-0 px-2 py-1.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-300 cursor-pointer">
					<option value="all">🔍 همه</option>
					<option value="active">✅ فعال</option>
					<option value="inactive">❌ غیرفعال</option>
					<option value="online">⚡ آنلاین</option>
					<option value="offline">💤 آفلاین</option>
					<option value="expired">⏳ منقضی</option>
				</select>
				<select id="sort-users" onchange="filterAndRenderUsers()" class="w-full min-w-0 px-2 py-1.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-300 cursor-pointer">
					<option value="newest">📅 جدیدترین</option>
					<option value="name">🔤 نام کاربری (الفبا)</option>
					<option value="usage-desc" selected>📊 بیشترین مصرف</option>
					<option value="usage-asc">📈 کمترین مصرف</option>
					<option value="expiry-asc">⏳ کمترین زمان باقی‌مانده</option>
				</select>
			</div>
		</div>
		<div id="users-table-container" class="hidden pb-4 px-1">
			<div id="users-tbody" class="grid grid-cols-2 gap-3 text-sm"></div>
		</div>
		<div id="empty-state" class="hidden p-8 border-2 border-dashed border-red-500/60 dark:border-red-500/50 bg-red-50 dark:bg-red-900/10 rounded-md text-center animate-pulse shadow-sm">
			<p class="text-red-600 dark:text-red-400 font-bold text-lg flex items-center justify-center flex-wrap gap-2 leading-loose">
				<span>کاربری وجود ندارد. برای ساخت کاربر روی</span>
				<span class="inline-flex items-center justify-center p-1.5 rounded-full bg-green-50 dark:bg-green-950/30 border border-green-600 dark:border-green-700/60 text-green-700 dark:text-green-400 shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"></path></svg></span>
				<span>کلیک کنید یا از دکمه‌های</span>
				<span class="inline-flex items-center justify-center p-1.5 rounded-full bg-orange-50 dark:bg-orange-950/40 border border-orange-500 text-orange-600 dark:text-orange-400 shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"></path><path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"></path><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"></path><path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"></path></svg></span>
				<span>و</span>
				<span class="inline-flex items-center justify-center p-1.5 rounded-full bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-500 text-indigo-600 dark:text-indigo-400 shadow-sm"><svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></span>
				<span>برای ایجاد سریع استفاده کنید.</span>
			</p>
		</div>
</div>
</div>
	</main>
<div id="pwa-install-modal" class="fixed inset-0 z-[120] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
	<div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-green-500/40 rounded-2xl shadow-2xl p-6 transform transition-all scale-95 opacity-0 duration-200 text-center relative overflow-hidden">
		
		
		<div class="flex justify-between items-center mb-4 relative z-10">
			<h3 class="text-sm font-black text-gray-900 dark:text-white flex items-center gap-2">
				<span class="text-lg">📲</span>
				<span id="pwa-modal-title">راهنمای نصب اپلیکیشن زئوس</span>
			</h3>
			<button onclick="togglePwaModal(false)" class="p-1 rounded-md text-gray-400 hover:text-red-500 cursor-pointer transition">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		
		<div class="flex items-center gap-3 p-3 bg-green-50/50 dark:bg-green-900/10 rounded-xl border border-green-200/70 dark:border-green-800/50 mb-4 text-right">
			<div class="w-11 h-11 rounded-xl bg-green-50 dark:bg-green-950/60 border-2 border-green-500 flex items-center justify-center text-green-600 dark:text-green-400 flex-shrink-0 shadow-md">
				<svg class="w-6 h-6 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
			</div>
			<div>
				<h4 class="text-xs font-black text-gray-900 dark:text-white">پنل زئوس</h4>
				<span class="text-[10px] text-gray-500 dark:text-zinc-400 block">اپلیکیشن پیشرفته و مستقل وب (PWA)</span>
			</div>
		</div>
		
		<div id="pwa-instructions-list" class="space-y-2.5 text-right text-xs text-gray-700 dark:text-zinc-300 font-medium leading-relaxed select-none mb-5 max-h-48 overflow-y-auto pr-1">
		</div>
		
		<button onclick="togglePwaModal(false)" class="w-full py-2.5 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-bold rounded-xl text-xs transition shadow-sm cursor-pointer active:scale-95">متوجه شدم</button>
	</div>
</div>
<div id="info-modal" class="fixed inset-0 z-[80] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-purple-500/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col">
		
		<div class="inline-flex items-center justify-center w-14 h-14 rounded-full bg-purple-100 dark:bg-purple-900/30 text-purple-500 mb-3 shadow-inner mx-auto flex-shrink-0">
			<svg class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
			</svg>
		</div>
		
		<h3 class="font-black text-lg text-gray-900 dark:text-white mb-3">اطلاعیه مهم امنیتی و وضعیت پروژه</h3>
		
		<div class="text-xs text-gray-600 dark:text-gray-300 mb-4 leading-relaxed font-medium text-justify space-y-2">
			<p>
				همراهان گرامی؛ با وجود مسدود شدن مکرر مخازن گیت‌هاب زئوس بر اثر گزارش‌های کذب و مغرضانه <strong>فروشندگان کانفیگ</strong>، ما مخزن جدیدی را برای دسترسی شما ایجاد کرده‌ایم؛ هرچند متاسفانه احتمال مسدود شدن مجدد آن همچنان وجود دارد.
			</p>
			<p>
				این افراد سودجو با انتشار شایعات بی‌اساس مبنی بر ناامن بودن پنل، در تلاشند تا این پروژه کاملاً رایگان را تخریب کنند و منافع مالی خود را نجات دهند. اما ما تسلیم این کارشکنی‌ها نخواهیم شد.
			</p>
			<p>
				پروژه ما همواره بر پایه شفافیت مطلق بنا شده است. سورس‌کد کامل در اختیار شماست تا بتوانید مستقلاً و حتی به کمک ابزارهای هوش مصنوعی آن را بررسی کرده و از سلامت و امنیت قطعی پروژه اطمینان حاصل کنید.
			</p>
			<p class="text-amber-600 dark:text-amber-400 font-bold text-center mt-2 border-t border-gray-100 dark:border-zinc-800/50 pt-2.5">
				ادامه این مسیر پرفراز و نشیب و مقابله با این تخریب‌های سازمان‌یافته، بدون همراهی شما دشوار است. حمایت‌های شما، تنها پشتوانه ما برای زنده نگه داشتن زئوس است.
			</p>
		</div>
		
		<div class="flex flex-col gap-2 mt-auto">
			<div class="flex flex-col sm:flex-row gap-2 w-full">
				<button onclick="downloadZeusSource()" class="flex-1 py-2 bg-blue-700 hover:bg-blue-800 dark:bg-blue-600 dark:hover:bg-blue-700 text-white font-bold rounded-md text-[11px] transition duration-300 shadow-sm flex items-center justify-center gap-1.5">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>
					دریافت سورس‌کد
				</button>
				
				<button onclick="window.open('https://donatonion.ir-netlify.workers.dev/', '_blank')" class="flex-1 py-2 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-bold rounded-md text-[11px] transition duration-300 shadow-sm flex items-center justify-center gap-1.5">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z"></path></svg>
					حمایت از پروژه
				</button>
			</div>
			
			<button onclick="toggleInfoModal(false)" class="w-full py-2.5 bg-purple-700 hover:bg-purple-800 dark:bg-purple-600 dark:hover:bg-purple-700 text-white font-black rounded-md text-sm transition duration-300 shadow-sm">
				متوجه شدم
			</button>
		</div>
		
	</div>
</div>
<div id="usage-warning-modal" class="fixed inset-0 z-[80] flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-orange-500/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
		<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-orange-100 dark:bg-orange-900/30 text-orange-500 mb-4 shadow-inner">
			<svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
		</div>
		<h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">هشدار محدودیت درخواست روزانه</h3>
		<p class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
			درخواست‌های روزانه کلودفلر شما از ۹۰,۰۰۰ عبور کرده است. در صورت عبور از محدودیت رایگان ۱۰۰,۰۰۰ درخواست، دسترسی به پـنـل و اتصالات تا ساعت ۳:۳۰ بامداد (به وقت ایران) قطع خواهد شد.
		</p>
		<button onclick="closeUsageWarning()" class="w-full py-3.5 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-black rounded-md text-sm transition duration-300 shadow-lg">
			متوجه شدم
		</button>
	</div>
</div>
<div id="usage-chart-modal" class="fixed inset-0 z-[92] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-[864px] bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-2xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col max-h-[92vh]">
		<div class="flex items-center justify-between gap-3 p-[21px] sm:p-6 border-b border-gray-100 dark:border-zinc-800 shrink-0">
			<div class="flex items-center gap-2.5 min-w-0">
				<div id="usage-chart-icon-wrap" class="p-[9px] rounded-lg bg-orange-50 dark:bg-orange-950/30 text-orange-600 dark:text-orange-400 shrink-0">
					<svg id="usage-chart-icon" class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z"></path></svg>
				</div>
				<div class="flex flex-col min-w-0">
					<h3 id="usage-chart-title" class="font-black text-gray-900 dark:text-zinc-100 text-[21px] truncate">روند مصرف</h3>
					<span class="text-[15px] text-gray-400 dark:text-zinc-500 font-medium">۳۰ روز گذشته &middot; روزانه</span>
				</div>
			</div>
			<button type="button" onclick="closeUsageChart()" class="p-3 rounded-lg bg-red-700 hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-700 text-white transition-all duration-200 shadow-sm shrink-0" title="بستن">
				<svg class="w-[21px] h-[21px]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div id="usage-chart-summary" class="grid grid-cols-3 gap-[9px] px-[21px] sm:px-6 pt-[21px] shrink-0"></div>
		<div class="p-[21px] sm:p-6 pt-3 overflow-y-auto">
			<div id="usage-chart-body" class="relative"></div>
		</div>
	</div>
</div>
<div id="online-counter-warning-modal" class="fixed inset-0 z-[87] flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-red-500/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
		<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-100 dark:bg-red-900/30 text-red-500 mb-4 shadow-inner">
			<svg class="w-8 h-8 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
		</div>
		<h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">هشدار شمارنده آنلاین</h3>
		<p class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
			به دلیل ساختار کلودفلر، آمار شمارنده کاربران آنلاین دقیق نمی باشد؛ همچنین تست پینگ یا آپدیت لینک های ساب توسط کلاینت ممکن است به صورت موقت منجر به نمایش افزایش کاذب تعداد کاربران فعال گردد. </p>
		<button onclick="closeOnlineCounterWarning()" class="w-full py-3.5 bg-red-700 hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-700 text-white font-black rounded-md text-sm transition duration-300 shadow-lg">
			متوجه شدم
		</button>
	</div>
</div>
<div id="pattng-info-modal" class="fixed inset-0 z-[115] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-[#0f9d68]/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
		<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-[#0f9d68]/10 text-[#0f9d68] mb-4">
			<svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
		</div>
		<h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">توجه: پیش‌نیاز بهینه‌سازی</h3>
		<p class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
			قابلیت‌های <b>Patterniha</b> در حال حاضر منحصراً روی اپلیکیشن‌های <span class="text-[#0f9d68] font-bold">PattNG (اندروید)</span> و <span class="text-[#0f9d68] font-bold">PattN (ویندوز)</span> پشتیبانی می‌شود. لطفاً برای استفاده از این قابلیت، نرم‌افزار مربوطه را نصب کنید.
		</p>
		<div class="flex flex-col gap-3">
			<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
				<a href="https://github.com/patterniha/PattNG/releases/latest" target="_blank" class="w-full py-3 bg-[#0f9d68]/10 hover:bg-[#0f9d68]/20 text-[#0f9d68] border border-[#0f9d68]/50 font-black rounded-md text-xs transition duration-300 flex items-center justify-center gap-1.5">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
					اندروید (PattNG)
				</a>
				<a href="https://github.com/patterniha/PattN/releases/latest/download/PattN-windows-64.zip" target="_blank" class="w-full py-3 bg-[#0f9d68]/10 hover:bg-[#0f9d68]/20 text-[#0f9d68] border border-[#0f9d68]/50 font-black rounded-md text-xs transition duration-300 flex items-center justify-center gap-1.5">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
					ویندوز (PattN)
				</a>
			</div>
			<button onclick="togglePattNgModal(false)" class="w-full py-3.5 bg-transparent border-2 border-gray-500 text-gray-600 hover:bg-gray-100 dark:border-gray-600 dark:text-gray-400 dark:hover:bg-zinc-800 font-bold rounded-md text-sm transition duration-300 mt-1">
				فهمیدم
			</button>
		</div>
	</div>
</div>
	<div id="user-modal" class="fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4 bg-black/75 backdrop-blur-sm opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
		<div id="user-modal-card" class="w-full max-w-5xl bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-2xl overflow-hidden transition-[opacity,transform] duration-200 opacity-0 scale-95 ease-out flex flex-col max-h-[92vh] transform-gpu">
			<div class="px-5 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50/70 dark:bg-amoled-bg/60">
				<div class="flex items-center gap-3">
					<div class="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-600 dark:text-blue-400 flex items-center justify-center font-bold">
						<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>
					</div>
					<div>
						<h3 id="modal-title" class="font-black text-gray-900 dark:text-zinc-100 text-sm sm:text-base tracking-tight">ایجاد کاربر جدید</h3>
						<p class="text-[11px] text-gray-500 dark:text-zinc-400 font-medium">مشخصات، دسترسی‌ها و پروتکل‌های اتصال کاربر</p>
					</div>
				</div>
				<button type="button" onclick="toggleModal(false)" class="p-2 rounded-lg bg-red-700 hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-700 text-white transition-all duration-200 shadow-sm" title="بستن">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
				</button>
			</div>
			<form id="create-user-form" class="flex flex-col flex-1 min-h-0 overflow-hidden" onsubmit="handleFormSubmit(event)">
				<input type="hidden" id="hidden-auto-rotate" value="0">
				<input type="hidden" id="hidden-rotate-time" value="">
				<input type="hidden" id="hidden-ip-operator" value="all">
				<input type="hidden" id="hidden-ip-count" value="20">
				<div class="flex flex-col md:flex-row flex-1 min-h-0 overflow-hidden">
					<div class="w-full md:w-64 bg-gray-50/90 dark:bg-amoled-bg/80 border-b md:border-b-0 md:border-l border-gray-200 dark:border-amoled-border p-3 md:p-4 flex flex-row md:flex-col gap-2 flex-shrink-0 overflow-x-auto md:overflow-x-visible md:justify-between">
						<div class="flex flex-row md:flex-col gap-2 w-full">
							<button type="button" onclick="switchUserTab('tab-user-info')" id="tab-btn-user-info" class="user-modal-tab-btn active flex-1 md:flex-initial flex flex-col sm:flex-row items-center justify-center sm:justify-start gap-1 sm:gap-3 p-1.5 sm:p-3 rounded-xl transition text-center sm:text-right cursor-pointer select-none bg-blue-600/10 dark:bg-blue-500/15 border border-blue-500/30 text-blue-600 dark:text-blue-400 font-bold shadow-sm">
								<div class="flex-shrink-0 w-4 h-4 sm:w-8 sm:h-8 rounded sm:rounded-lg flex items-center justify-center bg-blue-500/15 dark:bg-blue-400/20 text-blue-600 dark:text-blue-300">
									<svg class="w-3 h-3 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>
								</div>
								<div class="hidden sm:block text-right">
									<div class="text-xs font-black">نام کاربری و مشخصات</div>
									<div class="text-[10px] opacity-75 font-normal">حجم، زمان، محدودیت و تمدید</div>
								</div>
								<span class="sm:hidden text-[10px] sm:text-xs font-bold whitespace-nowrap">مشخصات</span>
							</button>
							<button type="button" onclick="switchUserTab('tab-ports-network')" id="tab-btn-ports-network" class="user-modal-tab-btn flex-1 md:flex-initial flex flex-col sm:flex-row items-center justify-center sm:justify-start gap-1 sm:gap-3 p-1.5 sm:p-3 rounded-xl transition text-center sm:text-right cursor-pointer select-none bg-transparent hover:bg-gray-100 dark:hover:bg-amoled-input/50 border border-transparent text-gray-600 dark:text-zinc-400 font-medium">
								<div class="flex-shrink-0 w-4 h-4 sm:w-8 sm:h-8 rounded sm:rounded-lg flex items-center justify-center bg-gray-200/60 dark:bg-slate-900 text-gray-500 dark:text-zinc-400">
									<svg class="w-3 h-3 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path></svg>
								</div>
								<div class="hidden sm:block text-right">
									<div class="text-xs font-black">پورت‌های اتصال و شبکه</div>
									<div class="text-[10px] opacity-75 font-normal">پورت‌ها، آی‌پی تمیز و فرگمنت</div>
								</div>
								<span class="sm:hidden text-[10px] sm:text-xs font-bold whitespace-nowrap">پورت و IP</span>
							</button>
							<button type="button" onclick="switchUserTab('tab-proxy-settings')" id="tab-btn-proxy-settings" class="user-modal-tab-btn flex-1 md:flex-initial flex flex-col sm:flex-row items-center justify-center sm:justify-start gap-1 sm:gap-3 p-1.5 sm:p-3 rounded-xl transition text-center sm:text-right cursor-pointer select-none bg-transparent hover:bg-gray-100 dark:hover:bg-amoled-input/50 border border-transparent text-gray-600 dark:text-zinc-400 font-medium">
								<div class="flex-shrink-0 w-4 h-4 sm:w-8 sm:h-8 rounded sm:rounded-lg flex items-center justify-center bg-gray-200/60 dark:bg-slate-900 text-gray-500 dark:text-zinc-400">
									<svg class="w-3 h-3 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
								</div>
								<div class="hidden sm:block text-right">
									<div class="text-xs font-black">تنظیم پروکسی و کشور</div>
									<div class="text-[10px] opacity-75 font-normal">آی‌پی ثابت و زنجیره اتصال</div>
								</div>
								<span class="sm:hidden text-[10px] sm:text-xs font-bold whitespace-nowrap">پروکسی</span>
							</button>
						</div>
						
						<div class="hidden md:flex flex-col gap-2 mt-auto pt-4 border-t border-gray-200 dark:border-amoled-border w-full">
							<button type="submit" id="submit-btn-desktop" class="w-full py-2.5 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-black rounded-xl text-sm transition shadow-lg flex items-center justify-center gap-1.5 cursor-pointer">
								<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
								<span>ایجاد کاربر</span>
							</button>
							<button type="button" onclick="toggleModal(false)" class="w-full py-2 bg-red-700 hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-700 text-white font-bold rounded-xl text-xs transition shadow-sm">
								انصراف
							</button>
						</div>
					</div>
					<div class="flex-1 p-4 sm:p-6 overflow-y-auto max-h-[72vh] space-y-4 custom-scrollbar overscroll-contain">
						
						<div id="tab-user-info" class="user-tab-panel space-y-4">
							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
								<div class="flex items-center justify-between">
									<label class="block text-xs font-black text-gray-700 dark:text-zinc-200 uppercase tracking-wider flex items-center gap-1.5">
										<span class="w-2 h-2 rounded-full bg-indigo-500"></span>
										<span>پروتکل‌های اتصال (انتخاب حداقل یک مورد الزامی است)</span>
									</label>
								</div>
								<div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
									<label class="flex items-center justify-between p-3 bg-white dark:bg-slate-900 border border-gray-200/80 dark:border-amoled-border rounded-xl cursor-pointer hover:border-blue-500 dark:hover:border-blue-500 transition select-none">
										<div class="flex items-center gap-2.5">
											<div class="w-8 h-8 rounded-lg bg-blue-500/10 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 flex items-center justify-center font-black text-xs">
												<svg class="w-5 h-5 -ml-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"></path></svg>
											</div>
											<div>
												<span class="text-xs font-black text-gray-800 dark:text-zinc-200 block">پروتکل VLESS</span>
												<span class="text-[10px] text-gray-500 dark:text-zinc-400 block font-normal">پروتکل سبک و پرسرعت WebSocket</span>
											</div>
										</div>
										<input type="checkbox" id="input-proto-vless" checked onchange="handleProtocolChange(this)" class="w-4 h-4 rounded focus:ring-green-500/50 bg-white dark:bg-amoled-input border-gray-300 dark:border-amoled-border cursor-pointer text-green-600" style="filter: none !important; accent-color: #16a34a !important;">
									</label>
									<label class="flex items-center justify-between p-3 bg-white dark:bg-slate-900 border border-gray-200/80 dark:border-amoled-border rounded-xl cursor-pointer hover:border-purple-500 dark:hover:border-purple-500 transition select-none">
										<div class="flex items-center gap-2.5">
											<div class="w-8 h-8 rounded-lg bg-purple-500/10 dark:bg-purple-500/20 text-purple-600 dark:text-purple-400 flex items-center justify-center font-black text-xs">
												<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M12 11a2 2 0 100-4 2 2 0 000 4z"></path><path d="M12 11v3"></path></svg>
											</div>
											<div>
												<span class="text-xs font-black text-gray-800 dark:text-zinc-200 block">پروتکل Trojan</span>
												<span class="text-[10px] text-gray-500 dark:text-zinc-400 block font-normal">پروتکل امنیتی پیشرفته WebSocket</span>
											</div>
										</div>
										<input type="checkbox" id="input-proto-trojan" onchange="handleProtocolChange(this)" class="w-4 h-4 rounded focus:ring-green-500/50 bg-white dark:bg-amoled-input border-gray-300 dark:border-amoled-border cursor-pointer text-green-600" style="filter: none !important; accent-color: #16a34a !important;">
									</label>
								</div>
							</div>
							
							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
								<div class="flex items-center justify-between">
									<label class="block text-xs font-black text-gray-700 dark:text-zinc-200 uppercase tracking-wider flex items-center gap-1.5">
										<span class="w-2 h-2 rounded-full bg-blue-500"></span>
										<span>نام کاربری (الزامی)</span>
									</label>
									<button type="button" onclick="generateRandomUsername()" class="px-2.5 py-1 bg-blue-700 hover:bg-blue-800 dark:bg-blue-600 dark:hover:bg-blue-700 text-white rounded-md text-[11px] font-bold transition flex items-center gap-1">
										<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
										<span>نام تصادفی</span>
									</button>
								</div>
								<div class="relative">
									<span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
										<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>
									</span>
									<input type="text" id="input-name" placeholder="zeus" dir="ltr" class="w-full pl-3 pr-9 py-2.5 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition shadow-sm">
								</div>
							</div>

							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
								<div class="flex items-center justify-between">
									<label class="block text-xs font-black text-gray-700 dark:text-zinc-200 uppercase tracking-wider flex items-center gap-1.5">
										<span class="w-2 h-2 rounded-full bg-purple-500"></span>
										<span>UUID (اختیاری)</span>
									</label>
									<button type="button" onclick="generateRandomUuid()" class="px-2.5 py-1 bg-purple-700 hover:bg-purple-800 dark:bg-purple-600 dark:hover:bg-purple-700 text-white rounded-md text-[11px] font-bold transition flex items-center gap-1">
										<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
										<span>UUID تصادفی</span>
									</button>
								</div>
								<div class="relative">
									<input type="text" id="input-uuid" placeholder="خالی بگذارید تا خودکار ساخته شود" dir="ltr" class="w-full px-3 py-2.5 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500/50 text-xs font-mono text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition shadow-sm">
								</div>
								<p class="text-[10px] text-amber-600 dark:text-amber-500 font-bold leading-relaxed">⚠️ تغییر UUID یک کاربر موجود، تمام کانفیگ‌ها و ساب‌لینک‌های قبلی او را نامعتبر می‌کند؛ باید لینک جدید دریافت کند.</p>
							</div>

							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-4">
								<div class="space-y-3">
									<h4 class="text-xs font-black text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
										<span class="w-2 h-2 rounded-full bg-emerald-500"></span>
										<span>اعتبار حجمی و زمانی</span>
									</h4>
									<div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
										<div>
											<label class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">حجم مجاز (گیگابایت)</label>
											<div class="relative">
												<span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
													<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"></path></svg>
												</span>
												<input type="number" id="input-limit" step="0.1" min="0" placeholder="نامحدود" class="w-full pl-3 pr-9 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition shadow-sm">
											</div>
											<div class="flex items-center gap-1 mt-1.5 flex-wrap">
												<span class="text-[9px] text-gray-400 dark:text-zinc-500 font-bold ml-1">انتخاب سریع:</span>
												<button type="button" onclick="setQuickVol(10)" class="px-2 py-0.5 rounded bg-transparent border border-blue-500 text-blue-600 dark:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 text-[10px] font-bold transition cursor-pointer">۱۰ گیگ</button>
												<button type="button" onclick="setQuickVol(50)" class="px-2 py-0.5 rounded bg-transparent border border-blue-500 text-blue-600 dark:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 text-[10px] font-bold transition cursor-pointer">۵۰ گیگ</button>
												<button type="button" onclick="setQuickVol(100)" class="px-2 py-0.5 rounded bg-transparent border border-blue-500 text-blue-600 dark:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 text-[10px] font-bold transition cursor-pointer">۱۰۰ گیگ</button>
												<button type="button" onclick="setQuickVol('')" class="px-2 py-0.5 rounded bg-transparent border border-gray-500 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-amoled-input text-[10px] font-bold transition cursor-pointer">نامحدود</button>
											</div>
										</div>
										<div>
											<label class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">مدت زمان اعتبار (روز)</label>
											<div class="relative">
												<span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
													<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>
												</span>
												<input type="number" id="input-expiry" min="1" placeholder="نامحدود" class="w-full pl-3 pr-9 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition shadow-sm">
											</div>
											<div class="flex items-center gap-1 mt-1.5 flex-wrap">
												<span class="text-[9px] text-gray-400 dark:text-zinc-500 font-bold ml-1">انتخاب سریع:</span>
												<button type="button" onclick="setQuickExp(30)" class="px-2 py-0.5 rounded bg-transparent border border-blue-500 text-blue-600 dark:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 text-[10px] font-bold transition cursor-pointer">۱ ماه</button>
												<button type="button" onclick="setQuickExp(60)" class="px-2 py-0.5 rounded bg-transparent border border-blue-500 text-blue-600 dark:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 text-[10px] font-bold transition cursor-pointer">۲ ماه</button>
												<button type="button" onclick="setQuickExp(90)" class="px-2 py-0.5 rounded bg-transparent border border-blue-500 text-blue-600 dark:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/20 text-[10px] font-bold transition cursor-pointer">۳ ماه</button>
												<button type="button" onclick="setQuickExp('')" class="px-2 py-0.5 rounded bg-transparent border border-gray-500 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-amoled-input text-[10px] font-bold transition cursor-pointer">نامحدود</button>
											</div>
										</div>
									</div>
									<div class="flex items-center justify-between p-3 bg-white dark:bg-slate-900 border border-gray-200/80 dark:border-amoled-border rounded-lg">
										<div class="flex items-center gap-2">
											<svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
											<span class="text-xs font-bold text-gray-700 dark:text-zinc-300">شروع محاسبه زمان از اولین اتصال کاربر</span>
										</div>
										<label class="relative inline-flex items-center cursor-pointer select-none">
											<input type="checkbox" id="input-start-on-first-connect" class="sr-only peer">
											<div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-blue-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
										</label>
									</div>
								</div>
								
								<div class="border-t border-gray-200/70 dark:border-amoled-border"></div>
								
								<div class="space-y-3">
									<h4 class="text-xs font-black text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
										<span class="w-2 h-2 rounded-full bg-purple-500"></span>
										<span>محدودیت‌های اتصال و امنیت</span>
									</h4>
									<div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
										<div>
											<label class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">تعداد درخواست (ریکوئست)</label>
											<div class="relative">
												<span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
													<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
												</span>
												<input type="number" id="input-req-limit" min="0" placeholder="نامحدود" class="w-full pl-3 pr-9 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition shadow-sm">
											</div>
										</div>
										<div>
											<label class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1 flex items-center gap-1.5">
												<span>محدودیت کاربر</span>
												<button type="button" onclick="openOnlineCounterWarning();" class="text-red-500 hover:text-red-400 cursor-pointer inline-flex items-center animate-sym-bounce hover:animate-none transition-transform hover:scale-125" title="هشدار مهم">
													<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
												</button>
											</label>
											<div class="relative">
												<span class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none text-gray-400">
													<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
												</span>
												<input type="number" id="input-ip-limit" min="0" placeholder="نامحدود" class="w-full pl-3 pr-9 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition shadow-sm">
											</div>
										</div>
										<div>
											<label class="block text-[11px] font-bold text-gray-500 dark:text-zinc-400 mb-1">فینگرپرینت TLS</label>
											<div class="relative">
												<select id="fingerprint-select" class="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-semibold text-gray-700 dark:text-zinc-300 cursor-pointer appearance-none shadow-sm">
													<option value="chrome">🌐 Chrome</option>
													<option value="firefox">🦊 Firefox</option>
													<option value="safari">🧭 Safari</option>
													<option value="ios">📱 iOS</option>
													<option value="android">🤖 Android</option>
													<option value="edge">🌀 Edge</option>
													<option value="360">🔒 360 Browser</option>
													<option value="qq">💬 QQ Browser</option>
													<option value="random">🎲 Random</option>
													<option value="randomized">🎭 Dynamic</option>
													<option value="unsafe" selected>🚀 Unsafe (پیشنهادی)</option>
												</select>
												<div class="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-2 text-gray-500">
													<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
												</div>
											</div>
										</div>
									</div>
								</div>
							</div>
							
							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
								<div class="flex items-center justify-between">
									<div class="flex items-center gap-2">
										<svg class="w-4 h-4 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
										<div>
											<span class="text-xs font-black text-gray-800 dark:text-zinc-200">تمدید خودکار ترافیک</span>
											<span class="text-[10px] text-gray-400 block font-normal">ریست اتوماتیک در ساعت ۳:۳۰ بامداد</span>
										</div>
									</div>
									<label class="relative inline-flex items-center cursor-pointer select-none">
										<input type="checkbox" id="input-auto-reset-toggle" onchange="toggleAutoResetInputs(this.checked)" class="sr-only peer">
										<div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-emerald-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
									</label>
								</div>
								<div id="auto-reset-inputs-container" class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-gray-200/60 dark:border-amoled-border opacity-50 pointer-events-none transition-all duration-200">
									<div>
										<label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1">دوره تمدید حجم (روز)</label>
										<input type="number" id="input-auto-reset-vol" min="1" placeholder="خالی = بدون تمدید" class="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-center text-gray-800 dark:text-zinc-100 transition" dir="ltr" disabled>
									</div>
									<div>
										<label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1">دوره تمدید ریکوئست (روز)</label>
										<input type="number" id="input-auto-reset-req" min="1" placeholder="خالی = بدون تمدید" class="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-center text-gray-800 dark:text-zinc-100 transition" dir="ltr" disabled>
									</div>
								</div>
							</div>
							
							<div>
								<div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
									<div class="flex items-center justify-between p-3.5 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl">
										<div class="flex items-center gap-2">
											<span class="text-base">🔞</span>
											<span class="text-xs font-bold text-gray-700 dark:text-zinc-300">مسدودسازی سایت‌های غیراخلاقی</span>
										</div>
										<label class="relative inline-flex items-center cursor-pointer select-none">
											<input type="checkbox" id="input-block-porn" class="sr-only peer">
											<div class="w-8 h-4 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-red-500 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-3 after:w-3 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
										</label>
									</div>
									<div class="flex items-center justify-between p-3.5 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl">
										<div class="flex items-center gap-2">
											<span class="text-base">🚫</span>
											<span class="text-xs font-bold text-gray-700 dark:text-zinc-300">مسدودسازی تبلیغات اینترنتی</span>
										</div>
										<label class="relative inline-flex items-center cursor-pointer select-none">
											<input type="checkbox" id="input-block-ads" class="sr-only peer">
											<div class="w-8 h-4 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-amber-500 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-3 after:w-3 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
										</label>
									</div>
								</div>
								<div class="mt-2.5 p-2 bg-red-50/80 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 rounded-lg flex items-start gap-2 shadow-sm">
									<svg class="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
									<span class="text-[10px] font-bold text-red-700 dark:text-red-400 leading-relaxed text-justify">هشدار: در صورت روشن بودن فرگمنت (Fragment) گزینه های مسدودسازی عملاً کار نخواهند کرد.</span>
								</div>
							</div>
						</div>
						
						<div id="tab-ports-network" class="user-tab-panel hidden space-y-4">
							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
								<h4 class="text-xs font-black text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
									<span class="w-2 h-2 rounded-full bg-blue-500"></span>
									<span>پورت‌های اتصال VLESS</span>
								</h4>
								<div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
									<div class="p-3 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg flex flex-col">
										<div class="flex items-center gap-1.5 mb-2 pb-1.5 border-b border-gray-100 dark:border-amoled-border">
											<span class="w-2 h-2 rounded-full bg-blue-500"></span>
											<span class="text-[11px] font-bold text-blue-600 dark:text-blue-400">TLS PORT (رمزنگاری شده)</span>
										</div>
										<div class="grid grid-cols-3 gap-1.5 flex-1 content-start" id="tls-ports-list"></div>
									</div>
									<div class="p-3 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg flex flex-col">
										<div class="flex items-center gap-1.5 mb-2 pb-1.5 border-b border-gray-100 dark:border-amoled-border">
											<span class="w-2 h-2 rounded-full bg-amber-500"></span>
											<span class="text-[11px] font-bold text-amber-600 dark:text-amber-400">Non-TLS PORT (بدون رمزنگاری)</span>
										</div>
										<div class="grid grid-cols-3 gap-1.5 flex-1 content-start" id="nontls-ports-list"></div>
									</div>
								</div>
								<div class="p-3 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg space-y-1.5">
									<label class="block text-[11px] font-bold text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
										<span class="w-2 h-2 rounded-full bg-emerald-500"></span>
										<span>پورت‌های دلخواه و سفارشی (با فاصله جدا کنید)</span>
									</label>
									<input type="text" id="input-custom-ports" placeholder="مثال: 8080 2096 8443 5000" dir="ltr" class="w-full px-3 py-2 bg-gray-50 dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-gray-800 dark:text-zinc-100 transition shadow-sm">
								</div>
							</div>
							
							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
								<div class="flex items-center justify-between flex-wrap gap-2">
									<h4 class="text-xs font-black text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
										<span class="w-2 h-2 rounded-full bg-sky-500"></span>
										<span>آی‌پی‌های تمیز کلودفلر (Clean IPs)</span>
									</h4>
									<div class="flex items-center gap-1.5">
										<button type="button" onclick="openIpScannerModal()" class="px-2.5 py-1 bg-sky-700 hover:bg-sky-800 dark:bg-sky-600 dark:hover:bg-sky-700 text-white rounded-md text-[11px] font-bold transition flex items-center gap-1 shadow-sm">
											<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
											<span>اسکنر آی‌پی</span>
										</button>
										<button type="button" onclick="openIpSelectorModal()" class="px-2.5 py-1 bg-amber-700 hover:bg-amber-800 dark:bg-amber-600 dark:hover:bg-amber-700 text-white rounded-md text-[11px] font-bold transition flex items-center gap-1 shadow-sm">
											<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
										<span>مخزن آی‌پی</span>
										</button>
									</div>
								</div>
								<textarea id="input-ips" placeholder="104.16.0.1&#10;104.17.0.1&#10;162.159.192.1" class="w-full h-24 px-3 py-2.5 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition resize-none shadow-sm"></textarea>
	
								<div class="flex items-center justify-between p-3 mt-2 bg-emerald-50/50 dark:bg-emerald-900/10 border border-emerald-200/60 dark:border-emerald-800/40 rounded-lg shadow-sm">
									<div class="flex items-center gap-2">
										<svg class="w-4 h-4 text-emerald-600 dark:text-emerald-500 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
										<div>
											<span class="text-xs font-black text-gray-800 dark:text-zinc-200">تعویض خودکار آی‌پی (توصیه می‌شود)</span>
											<span class="text-[10px] text-gray-500 dark:text-zinc-400 block font-normal mt-0.5">جابجایی آی‌پی‌ها با هر بار رفرش کلاینت</span>
										</div>
									</div>
									<label class="relative inline-flex items-center cursor-pointer select-none">
										<input type="checkbox" id="input-auto-rotate-ip-toggle" class="sr-only peer" checked>
										<div class="w-9 h-5 bg-gray-300 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-emerald-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
									</label>
								</div>
							</div>
							
							<div class="bg-gradient-to-b from-blue-50/50 to-indigo-50/20 dark:from-amoled-input/50 dark:to-amoled-bg/50 border border-blue-200/70 dark:border-amoled-border rounded-2xl overflow-hidden shadow-sm">
								<div class="flex items-center justify-between p-4 cursor-pointer" onclick="document.getElementById('input-frag-toggle').click()">
									<div class="flex items-center gap-2.5">
										<div class="w-8 h-8 rounded-xl bg-blue-500/10 dark:bg-blue-500/20 border border-blue-500/30 flex items-center justify-center text-blue-600 dark:text-blue-400 font-bold shadow-sm">
											<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
										</div>
										<div>
											<span class="text-xs font-black text-gray-900 dark:text-zinc-100 flex items-center gap-1.5">
												<span>فرگمنت ضد فیلترینگ</span>
											</span>
											<span class="text-[10px] text-gray-500 dark:text-zinc-400 block font-normal mt-0.5">تجزیه پکت‌های اتصال برای عبور تضمینی</span>
										</div>
									</div>
									<div class="flex items-center gap-2" onclick="event.stopPropagation()">
										<label class="relative inline-flex items-center cursor-pointer select-none">
											<input type="checkbox" id="input-frag-toggle" onchange="toggleFragInputs(this.checked)" checked class="sr-only peer">
											<div class="w-10 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-blue-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-transform peer-checked:after:-translate-x-[20px]"></div>
										</label>
										<svg id="frag-settings-icon" class="w-4 h-4 text-blue-600 dark:text-blue-400 transition-transform duration-300 rotate-180" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
									</div>
								</div>
								<div id="frag-inputs-container" class="p-4 pt-0 space-y-3.5 transition-all duration-300">
									<div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2.5 border-t border-blue-100 dark:border-amoled-border transition-all duration-200">
										<div>
											<label class="block text-[10px] font-bold text-gray-600 dark:text-zinc-300 mb-1 flex items-center justify-between">
												<span>طول فرگمنت (Length)</span>
												<span class="text-[9px] text-gray-400">بایت‌های تقسیم پکت</span>
											</label>
											<input type="text" id="input-frag-len" value="200-3000" class="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-center text-gray-800 dark:text-zinc-100 transition shadow-sm" dir="ltr" placeholder="مثال: 10-30 یا 200-3000">
										</div>
										<div>
											<label class="block text-[10px] font-bold text-gray-600 dark:text-zinc-300 mb-1 flex items-center justify-between">
												<span>بازه فرگمنت (Interval ms)</span>
												<span class="text-[9px] text-gray-400">تاخیر میلی‌ثانیه</span>
											</label>
											<input type="text" id="input-frag-int" value="1-2" class="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-center text-gray-800 dark:text-zinc-100 transition shadow-sm" dir="ltr" placeholder="مثال: 1-2 یا 2-5">
										</div>
									</div>
									<div class="pt-2 border-t border-blue-100/80 dark:border-amoled-border space-y-2">
										<div class="flex items-center justify-between">
											<span class="text-[11px] font-black text-gray-800 dark:text-zinc-200 flex items-center gap-1.5">
												<span class="w-2 h-2 rounded-full bg-emerald-500 animate-ping"></span>
												<span>تنظیمات پیشنهادی فرگمنت برای اپراتورها (کلیک برای اعمال خودکار):</span>
											</span>
										</div>
										<div class="grid grid-cols-1 sm:grid-cols-4 gap-2">
											<button type="button" onclick="applyFragPreset('mci', this)" class="frag-preset-card group p-2.5 rounded-xl border border-teal-300/80 dark:border-teal-800/70 bg-white dark:bg-slate-950 hover:border-teal-500 dark:hover:border-teal-500 hover:shadow-md hover:shadow-teal-500/10 text-right transition-all flex flex-col justify-between cursor-pointer">
												<div class="flex items-center justify-between mb-1.5">
													<span class="text-xs font-black text-teal-700 dark:text-teal-300 flex items-center gap-1.5">
														<span class="w-2 h-2 rounded-full bg-teal-500"></span>
														همراه اول (MCI)
													</span>
													<span class="text-[9px] px-1.5 py-0.5 rounded bg-teal-500/10 text-teal-600 dark:text-teal-400 font-mono font-bold whitespace-nowrap">10-30</span>
												</div>
												<p class="text-[10px] text-teal-600/90 dark:text-teal-400/80 font-medium leading-tight">شکستن پکت + تاخیر ۲-۵ ms</p>
											</button>
											<button type="button" onclick="applyFragPreset('irancell', this)" class="frag-preset-card group p-2.5 rounded-xl border border-amber-300/80 dark:border-amber-800/70 bg-white dark:bg-slate-950 hover:border-amber-500 dark:hover:border-amber-500 hover:shadow-md hover:shadow-amber-500/10 text-right transition-all flex flex-col justify-between cursor-pointer">
												<div class="flex items-center justify-between mb-1.5">
													<span class="text-xs font-black text-amber-700 dark:text-amber-300 flex items-center gap-1.5">
														<span class="w-2 h-2 rounded-full bg-amber-500"></span>
														ایرانسل (MTN)
													</span>
													<span class="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400 font-mono font-bold whitespace-nowrap">100-200</span>
												</div>
												<p class="text-[10px] text-amber-600/90 dark:text-amber-400/80 font-medium leading-tight">پایداری 4G/5G + تاخیر ۵-۱۰ ms</p>
											</button>
											<button type="button" onclick="applyFragPreset('rightel', this)" class="frag-preset-card group p-2.5 rounded-xl border border-fuchsia-300/80 dark:border-fuchsia-800/70 bg-white dark:bg-slate-950 hover:border-fuchsia-500 dark:hover:border-fuchsia-500 hover:shadow-md hover:shadow-fuchsia-500/10 text-right transition-all flex flex-col justify-between cursor-pointer">
												<div class="flex items-center justify-between mb-1.5">
													<span class="text-xs font-black text-fuchsia-700 dark:text-fuchsia-300 flex items-center gap-1.5">
														<span class="w-2 h-2 rounded-full bg-fuchsia-500"></span>
														رایتل (Rightel)
													</span>
													<span class="text-[9px] px-1.5 py-0.5 rounded bg-fuchsia-500/10 text-fuchsia-600 dark:text-fuchsia-400 font-mono font-bold whitespace-nowrap">50-100</span>
												</div>
												<p class="text-[10px] text-fuchsia-600/90 dark:text-fuchsia-400/80 font-medium leading-tight">بهینه ۳G/4G + تاخیر ۲-۵ ms</p>
											</button>
											<button type="button" onclick="applyFragPreset('tci', this)" class="frag-preset-card group p-2.5 rounded-xl border border-indigo-300/80 dark:border-indigo-800/70 bg-white dark:bg-slate-950 hover:border-indigo-500 dark:hover:border-indigo-500 hover:shadow-md hover:shadow-indigo-500/10 text-right transition-all flex flex-col justify-between cursor-pointer">
												<div class="flex items-center justify-between mb-1.5">
													<span class="text-xs font-black text-indigo-700 dark:text-indigo-300 flex items-center gap-1.5">
														<span class="w-2 h-2 rounded-full bg-indigo-500"></span>
														مخابرات / ثابت
													</span>
													<span class="text-[9px] px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 font-mono font-bold whitespace-nowrap">50-200</span>
												</div>
												<p class="text-[10px] text-indigo-600/90 dark:text-indigo-400/80 font-medium leading-tight">آسیاتک، فیبر و ... + تاخیر ۱-۳ ms</p>
											</button>
										</div>
										<button type="button" onclick="applyFragPreset('gaming', this)" class="frag-preset-card w-full p-2.5 rounded-xl border border-emerald-300/80 dark:border-emerald-800/70 bg-white dark:bg-slate-950 hover:border-emerald-500 dark:hover:border-emerald-500 hover:shadow-md hover:shadow-emerald-500/10 transition-all flex items-center justify-between text-xs font-bold text-emerald-700 dark:text-emerald-300 cursor-pointer">
											<div class="flex items-center gap-2">
												<span class="text-base">🚀</span>
												<span>حالت فوق سریع (طول ۲۰۰-۳۰۰۰ | تاخیر ۱-۲ ms)</span>
											</div>
											<span class="text-[10px] px-2 py-0.5 rounded-md bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 font-black whitespace-nowrap">پینگ پایین</span>
										</button>
									</div>
								</div>
							</div>
							
							<div class="border border-sky-200 dark:border-amoled-border rounded-xl overflow-hidden shadow-sm">
								<div class="flex items-center justify-between p-3.5 bg-sky-50/60 dark:bg-amoled-input/30 cursor-pointer" onclick="document.getElementById('input-early-data-toggle').click()">
									<div class="flex items-center gap-2">
										<svg class="w-4 h-4 text-sky-600 dark:text-sky-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 5l7 7-7 7M5 5l7 7-7 7"></path></svg>
										<div>
											<span class="text-xs font-black text-sky-900 dark:text-sky-300">Early Data (ed=)</span>
											<span class="text-[10px] text-gray-500 dark:text-zinc-400 block font-normal mt-0.5">ارسال اولین بسته همراه هندشیک WebSocket؛ اتصال سریع‌تر (یک رفت‌وبرگشت کمتر)</span>
										</div>
									</div>
									<div class="flex items-center gap-2" onclick="event.stopPropagation()">
										<label class="relative inline-flex items-center cursor-pointer select-none">
											<input type="checkbox" id="input-early-data-toggle" onchange="toggleEarlyDataInputs(this.checked)" class="sr-only peer">
											<div class="w-10 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-sky-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-transform peer-checked:after:-translate-x-[20px]"></div>
										</label>
									</div>
								</div>
								<div id="early-data-inputs-container" class="hidden opacity-50 pointer-events-none p-4 border-t border-sky-100 dark:border-amoled-border">
									<label class="block text-[10px] font-bold text-gray-600 dark:text-zinc-300 mb-1 flex items-center justify-between">
										<span>سایز Early Data (بایت)</span>
										<span class="text-[9px] text-gray-400">پیشنهادی ۲۵۶۰ | حداکثر ۸۱۹۲</span>
									</label>
									<input type="text" inputmode="numeric" id="input-early-data-size" value="2560" dir="ltr" class="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-xl focus:outline-none focus:ring-2 focus:ring-sky-500/50 text-xs font-mono text-center text-gray-800 dark:text-zinc-100 transition shadow-sm">
								</div>
							</div>
							
							<div class="border border-purple-200 dark:border-amoled-border rounded-xl overflow-hidden shadow-sm">
								<div class="flex items-center justify-between p-3.5 bg-purple-50/60 dark:bg-amoled-input/30 cursor-pointer" onclick="document.getElementById('input-advanced-settings-toggle').click()">
									<div class="flex items-center gap-2">
										<svg class="w-4 h-4 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
										<span class="text-xs font-black text-purple-900 dark:text-purple-300">تنظیمات پیشرفته بهینه سازی</span>
										<span onclick="event.stopPropagation(); togglePattNgModal(true)" class="mr-2 px-1.5 py-0.5 bg-[#0f9d68]/10 text-[#0f9d68] border border-[#0f9d68]/30 rounded text-[10px] hover:bg-[#0f9d68]/20 transition-colors animate-pulse cursor-pointer">مهم🚨</span>
									</div>
									<div class="flex items-center gap-2" onclick="event.stopPropagation()">
										<label class="relative inline-flex items-center cursor-pointer select-none">
											<input type="checkbox" id="input-advanced-settings-toggle" onchange="toggleAdvancedSettingsInputs(this.checked)" class="sr-only peer">
											<div class="w-8 h-4 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-purple-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-3 after:w-3 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
										</label>
										<svg id="advanced-settings-icon" class="w-4 h-4 text-purple-600 dark:text-purple-400 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
									</div>
								</div>
								<div id="advanced-settings-container" class="hidden opacity-50 pointer-events-none transition-opacity duration-300 p-4 border-t border-purple-100 dark:border-amoled-border space-y-3 bg-white dark:bg-slate-900">
									<div>
										<label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1">Advanced Fragment (fm JSON)</label>
										<input type="text" id="input-advanced-frag" placeholder="{&quot;tcp&quot;: [{&quot;type&quot;: &quot;fragment&quot;..." dir="ltr" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-1 focus:ring-purple-500 text-[10px] font-mono text-gray-800 dark:text-zinc-100 placeholder-gray-400">
									</div>
									<div>
										<label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1">Cipher Suites (cs)</label>
										<input type="text" id="input-cipher-suites" placeholder="TLS_AES_256_GCM_SHA384..." dir="ltr" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-1 focus:ring-purple-500 text-[10px] font-mono text-gray-800 dark:text-zinc-100 placeholder-gray-400">
									</div>
									<div>
										<label class="block text-[10px] font-bold text-gray-500 dark:text-zinc-400 mb-1">TLS Mask (Custom SNI / Host)</label>
										<input type="text" id="input-tls-mask" placeholder="www.speedtest.net" dir="ltr" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-1 focus:ring-purple-500 text-[10px] font-mono text-gray-800 dark:text-zinc-100 placeholder-gray-400">
									</div>
									<button type="button" onclick="fillPatternihaValues()" class="w-full py-2 bg-purple-700 hover:bg-purple-800 dark:bg-purple-600 dark:hover:bg-purple-700 text-white rounded-lg text-xs font-bold transition flex items-center justify-center gap-1.5 mt-1 shadow-sm">
										<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
										<span>پر کردن خودکار مقادیر بهینه ساز Patterniha</span>
									</button>
								</div>
							</div>
						</div>
						
						<div id="tab-proxy-settings" class="user-tab-panel hidden space-y-4">
							<div class="p-4 bg-sky-50/50 dark:bg-sky-950/20 border border-sky-200/60 dark:border-sky-900/40 rounded-xl flex flex-col gap-3 shadow-sm">
								<div class="flex items-center justify-between">
									<div class="flex items-center gap-2">
										<svg class="w-4 h-4 text-sky-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
										<div>
											<span class="text-xs font-black text-gray-800 dark:text-zinc-200">تست اتصال مستقیم (بدون پروکسی)</span>
											<span class="text-[10px] text-gray-500 dark:text-zinc-400 block font-normal mt-0.5">تست ارتباط شما با کلودفلر و کلودفلر با نت آزاد</span>
										</div>
									</div>
								</div>
								<div class="grid grid-cols-2 gap-2 bg-white/60 dark:bg-amoled-bg/50 p-2.5 rounded-lg border border-sky-100 dark:border-sky-900/30">
									<div class="flex flex-col items-center justify-center gap-1 border-l border-gray-200 dark:border-zinc-800">
										<span class="text-[9px] font-bold text-gray-400">☁️ پینگ شما به کلودفلر</span>
										<span id="client-to-server-ping" class="text-[10px] font-bold text-gray-600 dark:text-zinc-300">-</span>
									</div>
									<div class="flex flex-col items-center justify-center gap-1">
										<span class="text-[9px] font-bold text-gray-400">🌍 پینگ کلودفلر به اینترنت آزاد</span>
										<span id="server-to-net-ping" class="text-[10px] font-bold text-gray-600 dark:text-zinc-300">-</span>
									</div>
								</div>
								<button type="button" id="test-direct-btn" onclick="testDirectPing()" class="w-full py-2 bg-sky-700 hover:bg-sky-800 dark:bg-sky-600 dark:hover:bg-sky-700 text-white rounded-lg text-xs font-bold transition shadow-sm flex items-center justify-center gap-1">
									<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
									<span>تست اتصال مستقیم</span>
								</button>
							</div>
							<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
								<div class="flex items-center justify-between">
									<div class="flex items-center gap-2">
										<svg class="w-4 h-4 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
										<div>
											<span class="text-xs font-black text-gray-800 dark:text-zinc-200">تنظیم کشور و ثابت کردن آی‌پی (SOCKS5/HTTP)</span>
											<span class="text-[10px] text-gray-400 block font-normal">زنجیره اتصال خروجی جهت عبور از تحریم‌ها و تغییر لوکیشن</span>
										</div>
									</div>
									<label class="relative inline-flex items-center cursor-pointer select-none">
										<input type="checkbox" id="user-proxy-mode-toggle" onchange="toggleUserProxyMode(this.checked)" class="sr-only peer">
										<div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-emerald-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
									</label>
								</div>
								<div class="border border-blue-200 dark:border-blue-900/60 bg-blue-50/40 dark:bg-blue-950/20 rounded-xl overflow-hidden shadow-sm">
									<div class="flex items-center justify-between p-3 bg-blue-100/50 dark:bg-blue-900/40 border-b border-blue-200 dark:border-blue-800/50">
										<div class="flex items-center gap-2">
											<span class="text-lg drop-shadow-sm">🌐</span>
											<span class="text-[11px] font-black text-blue-900 dark:text-blue-300">اتصال مستقیم (بدون پروکسی خروجی)</span>
										</div>
										<label class="relative inline-flex items-center cursor-pointer select-none">
											<input type="checkbox" id="input-enable-direct" checked class="sr-only peer">
											<div class="w-9 h-5 bg-gray-300 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-blue-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
										</label>
									</div>
									<div class="p-3 space-y-2.5">
										<p class="text-[10px] font-medium text-blue-800 dark:text-blue-200/80 leading-relaxed text-justify">
											کانفیگ‌های 🌐 به دلیل نداشتن آی‌پی ثابت، معمولاً دارای <span class="font-bold text-blue-600 dark:text-blue-400">پینگ بهتر و سرعت بالاتری</span> هستند.
										</p>
										<div class="flex items-start gap-1.5 p-2 bg-red-50/80 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 rounded-lg shadow-sm">
											<svg class="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
											<span class="text-[9px] font-bold text-red-700 dark:text-red-400 leading-relaxed text-justify">هشدار: هنگام اتصال به کانفیگ‌های 🌐، از باز کردن پنل خودداری کنید (باعث قطعی و اختلال در عملکرد پنل می‌شود).</span>
										</div>
									</div>
								</div>
								<div class="transition-opacity duration-300 opacity-50 pointer-events-none space-y-3 pt-2" id="user-socks5-container">
									<div id="proxies-fields-wrapper" class="flex flex-col gap-2 w-full"></div>
									<button type="button" id="add-proxy-field-btn" onclick="addProxyFieldUI()" class="w-full py-2.5 bg-emerald-700 hover:bg-emerald-800 dark:bg-emerald-600 dark:hover:bg-emerald-700 text-white rounded-lg text-xs font-black transition flex items-center justify-center gap-1.5 shadow-sm">
										<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
										<span>افزودن کشور / پروکسی جدید</span>
									</button>
									<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
										<button type="button" onclick="testUserSocksProxy()" id="test-user-proxy-btn" class="w-full py-2.5 bg-sky-700 hover:bg-sky-800 dark:bg-sky-600 dark:hover:bg-sky-700 text-white rounded-lg text-xs font-bold transition shadow-sm flex items-center justify-center gap-1">
											<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
											<span>تست پروکسی‌ها</span>
										</button>
										<button type="button" onclick="openProxySelectorModal()" class="w-full py-2.5 bg-amber-700 hover:bg-amber-800 dark:bg-amber-600 dark:hover:bg-amber-700 text-white rounded-lg text-xs font-bold transition shadow-sm flex items-center justify-center gap-1">
											<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
											<span>مخزن پروکسی‌های VIP</span>
										</button>
									</div>
									<div class="flex items-center justify-between p-3.5 bg-emerald-50/80 dark:bg-amoled-input/30 border border-emerald-500/40 dark:border-amoled-border rounded-xl shadow-sm">
										<div class="flex items-center gap-2">
											<svg class="w-4 h-4 text-emerald-600 dark:text-emerald-500 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
											<div>
												<span class="text-xs font-black text-emerald-800 dark:text-emerald-400">تعویض خودکار پروکسی خروجی خراب</span>
												<span class="text-[10px] text-emerald-600 dark:text-emerald-500 block font-medium">جایگزینی هوشمند در صورت قطع شدن پروکسی</span>
											</div>
										</div>
										<label class="relative inline-flex items-center cursor-pointer select-none">
											<input type="checkbox" id="input-auto-rotate-user-proxy" class="sr-only peer">
											<div class="w-8 h-4 bg-gray-300 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:bg-emerald-600 transition-colors after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:rounded-full after:h-3 after:w-3 after:transition-transform peer-checked:after:-translate-x-[16px]"></div>
										</label>
									</div>
								</div>
							</div>
							
							<div id="reset-user-default-wrap" style="display:none" class="space-y-2">
								<button type="button" id="reset-user-default-btn" onclick="resetUserToDefault()" class="w-full py-2.5 bg-orange-700 hover:bg-orange-800 dark:bg-orange-600 dark:hover:bg-orange-700 text-white rounded-xl text-xs font-black transition flex items-center justify-center gap-1.5 shadow-sm">
									<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
									<span>Reset to Default</span>
								</button>
								<p id="reset-user-default-note" style="display:none" class="text-[10px] font-bold text-orange-700 dark:text-orange-400 leading-relaxed text-justify">همه‌ی فیلدهای فرم به مقادیر پیش‌فرض یک کاربر جدید برگشت (نام کاربری، UUID و آمار مصرف دست‌نخورده می‌مانند). لیست لوکیشن‌ها و پروکسی‌ها هم با «ذخیره تغییرات» از لوکیشن‌های پین‌شده‌ی تنظیمات دوباره ساخته می‌شود. برای انصراف، بدون ذخیره مودال را ببندید.</p>
							</div>
							<div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
								<button type="button" onclick="toggleDonateModal(true)" class="py-2.5 px-3 bg-red-700 hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-700 text-white rounded-xl text-xs font-bold transition flex items-center justify-center gap-1.5 shadow-sm">
									<svg class="w-4 h-4 text-red-500" fill="currentColor" viewBox="0 0 24 24"><path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3 9.24 3 10.91 3.81 12 5.08 13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/></svg>
									<span>اهدای پروکسی شخصی به مخزن</span>
								</button>
								<button type="button" onclick="copyScannerCode('bash <(curl -sL https://hoplimit.shop/zeus-relay.sh | tr -d &quot;\\\\r&quot;)', this)" class="py-2.5 px-3 bg-blue-700 hover:bg-blue-800 dark:bg-blue-600 dark:hover:bg-blue-700 text-white rounded-xl text-xs font-bold transition flex items-center justify-center gap-1.5 shadow-sm">
									<svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
									<span>کپی دستور ساخت پروکسی ریلی</span>
								</button>
							</div>
						</div>
					</div>
				</div>
				<div class="px-5 py-3.5 border-t border-gray-150 dark:border-amoled-border bg-gray-50/70 dark:bg-amoled-bg/60 flex md:hidden items-center justify-between gap-3">
					<button type="button" onclick="toggleModal(false)" class="px-5 py-2.5 bg-red-700 hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-700 text-white font-bold rounded-xl text-xs sm:text-sm transition shadow-sm">
						انصراف
					</button>
					<div class="flex items-center gap-2">
						<button type="submit" id="submit-btn" class="px-7 py-2.5 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-black rounded-xl text-xs sm:text-sm transition shadow-lg flex items-center gap-1.5 cursor-pointer">
							<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
							<span>ایجاد کاربر</span>
						</button>
					</div>
				</div>
			</form>
		</div>
	</div>
<div id="ip-selector-modal" class="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-2xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col">
		
		<div class="px-5 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50/70 dark:bg-amoled-bg/60">
			<div class="flex items-center gap-3">
				<div class="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-600 dark:text-amber-400 flex items-center justify-center font-bold shadow-sm">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
				</div>
				<div>
					<h3 class="font-black text-gray-900 dark:text-zinc-100 text-sm tracking-tight">مخزن آی‌پی تمیز</h3>
				</div>
			</div>
			<button type="button" onclick="toggleIpSelectorModal(false)" class="p-2 rounded-lg bg-red-700 hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-700 text-white transition-all duration-200 shadow-sm" title="بستن">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="p-5 sm:p-6 space-y-4">
			<div id="ip-loading-state" class="text-center text-sm text-gray-500 dark:text-zinc-400 hidden">
				Loading IPs...
			</div>
			<div id="ip-selection-form" class="space-y-4">
				<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
					<div>
						<label class="block text-xs font-black text-gray-700 dark:text-zinc-200 mb-1.5 flex items-center gap-1.5">
							<span class="w-2 h-2 rounded-full bg-blue-500"></span> اوپراتور
						</label>
						<select id="ip-operator-select" class="w-full px-3 py-2.5 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-gray-800 dark:text-zinc-100 cursor-pointer shadow-sm transition">
							<option value="all">همه (توصیه شده)</option>
						</select>
					</div>
					<div>
						<label class="block text-xs font-black text-gray-700 dark:text-zinc-200 mb-1.5 flex items-center gap-1.5">
							<span class="w-2 h-2 rounded-full bg-purple-500"></span> تعداد
						</label>
						<input type="number" id="ip-count-input" min="1" value="20" dir="ltr" class="w-full px-3 py-2.5 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-center font-semibold text-gray-800 dark:text-zinc-100 shadow-sm transition">
					</div>
				</div>
			</div>
			<div class="pt-2 flex gap-3">
				<button type="button" onclick="toggleIpSelectorModal(false)" class="flex-1 py-2.5 bg-red-700 hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-700 text-white font-bold rounded-xl text-xs sm:text-sm transition shadow-sm">لغو</button>
				<button type="button" onclick="applySelectedIps()" class="flex-1 py-2.5 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-black rounded-xl text-xs sm:text-sm transition shadow-lg">دریافت</button>
			</div>
		</div>
	</div>
</div>
<div id="ip-scanner-modal" class="fixed inset-0 z-[65] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-lg bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col max-h-[90vh]">
		<div class="px-6 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50 dark:bg-zinc-900/50 flex-shrink-0">
			<h3 class="font-bold text-gray-900 dark:text-zinc-100 text-sm flex items-center gap-2">
				<svg class="w-4 h-4 text-sky-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
				اسکنر اختصاصی آی‌پی تمیز
			</h3>
			<button type="button" onclick="toggleIpScannerModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="p-5 space-y-4 overflow-y-auto flex-1">
			<div class="border border-green-200 dark:border-green-900/50 bg-green-50/50 dark:bg-green-900/10 rounded-md p-4 shadow-sm">
				<div class="flex items-center gap-2 mb-2">
					<svg class="w-5 h-5 text-green-600 dark:text-green-500" fill="currentColor" viewBox="0 0 24 24"><path d="M17.523 15.3414c-.5511 0-.9993-.4486-.9993-.9997s.4482-.9993.9993-.9993c.5511 0 .9993.4482.9993.9993.0004.5511-.4482.9997-.9993.9997m-11.046 0c-.5511 0-.9993-.4486-.9993-.9997s.4482-.9993.9993-.9993c.5511 0 .9993.4482.9993.9993 0 .5511-.4482.9997-.9993.9997m11.4045-6.02L19.695 6.183c.1568-.2716.0637-.6182-.2079-.7754-.2716-.1564-.6183-.0633-.775.2082l-1.8584 3.2185c-1.3853-.6328-2.9697-.9881-4.6644-.9881-1.6946 0-3.279.3553-4.664.9881L5.6664 5.6158c-.1567-.2715-.5038-.3646-.775-.2082-.2716.1572-.3647.5038-.2079.7754l1.8136 3.1385C2.963 11.2384 1.1571 14.5422 1 18.4234h22c-.1572-3.8812-1.963-7.185-5.4955-9.102"/></svg>
					<h4 class="font-black text-sm text-green-700 dark:text-green-400">کاربران موبایل (Pydroid 3)</h4>
				</div>
				<p class="text-[11px] text-gray-600 dark:text-gray-400 mb-3 leading-relaxed font-medium">
					اپلیکیشن <a href="https://play.google.com/store/apps/details?id=ru.iiec.pydroid3" target="_blank" class="text-blue-500 hover:text-blue-600 dark:text-blue-400 font-bold underline">Pydroid 3</a> را نصب کنید. از منوی کناری برنامه وارد بخش <b>Terminal</b> شوید و کد زیر را اجرا کنید؛ سپس آدرس <code class="bg-white dark:bg-zinc-800 px-1 py-0.5 rounded text-blue-500 font-bold shadow-sm" dir="ltr">http://127.0.0.1:8000</code> را در مرورگر باز کنید.
				</p>
				<div class="flex flex-col gap-2">
					<div class="w-full bg-gray-100 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md p-2.5 text-[10px] font-mono text-left text-gray-800 dark:text-zinc-300 break-all select-all overflow-x-auto whitespace-pre-wrap max-h-24 overflow-y-auto" dir="ltr">python -c "import urllib.request; req = urllib.request.Request('https://hoplimit.shop/zeus-scanner.txt', headers={'User-Agent': 'Mozilla/5.0'}); exec(urllib.request.urlopen(req).read().decode('utf-8').split('---PYTH' + 'ON---')[1].split('---POWERSHELL---')[0].strip())"</div>
					<button type="button" onclick="copyScannerCode('python -c &quot;import urllib.request; req = urllib.request.Request(\\'https://hoplimit.shop/zeus-scanner.txt\\', headers={\\'User-Agent\\': \\'Mozilla/5.0\\'}); exec(urllib.request.urlopen(req).read().decode(\\'utf-8\\').split(\\'---PYTH\\' + \\'ON---\\')[1].split(\\'---POWERSHELL---\\')[0].strip())&quot;', this)" class="w-full flex items-center justify-center gap-1.5 py-2 bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 text-gray-600 dark:text-zinc-300 hover:bg-gray-50 dark:hover:bg-zinc-700/80 rounded text-xs font-bold transition shadow-sm">
						<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
						<span>کپی کد Pydroid</span>
					</button>
				</div>
			</div>
			<div class="border border-blue-200 dark:border-blue-900/50 bg-blue-50/50 dark:bg-blue-900/10 rounded-md p-4 shadow-sm">
				<div class="flex items-center gap-2 mb-2">
					<svg class="w-5 h-5 text-blue-600 dark:text-blue-500" fill="currentColor" viewBox="0 0 24 24"><path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-13.051-1.801"/></svg>
					<h4 class="font-black text-sm text-blue-700 dark:text-blue-400">کاربران ویندوز (CMD)</h4>
				</div>
				<p class="text-[11px] text-gray-600 dark:text-gray-400 mb-3 leading-relaxed font-medium">
					محیط <code class="font-bold">CMD</code> (Command Prompt) را در ویندوز باز کنید و کد زیر را برای اجرای اسکنر در آن پیست کنید و اینتر بزنید.
				</p>
				<div class="flex flex-col gap-2">
					<div class="w-full bg-gray-100 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md p-2.5 text-[10px] font-mono text-left text-gray-800 dark:text-zinc-300 break-all select-all overflow-x-auto whitespace-pre-wrap max-h-24 overflow-y-auto" dir="ltr">powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13; $wc = New-Object System.Net.WebClient; $wc.Encoding = [System.Text.Encoding]::UTF8; $text = ($wc.DownloadString('https://hoplimit.shop/zeus-scanner.txt') -split '---POWERSHELL---')[1].Trim(); [IO.File]::WriteAllText('zeus-scanner.ps1', $text, [System.Text.Encoding]::UTF8); .\zeus-scanner.ps1"</div>
					<button type="button" onclick="copyScannerCode('powershell -ExecutionPolicy Bypass -Command &quot;[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13; $wc = New-Object System.Net.WebClient; $wc.Encoding = [System.Text.Encoding]::UTF8; $text = ($wc.DownloadString(\\'https://hoplimit.shop/zeus-scanner.txt\\') -split \\'---POWERSHELL---\\')[1].Trim(); [IO.File]::WriteAllText(\\'zeus-scanner.ps1\\', $text, [System.Text.Encoding]::UTF8); .\\\\zeus-scanner.ps1&quot;', this)" class="w-full flex items-center justify-center gap-1.5 py-2 bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 text-gray-600 dark:text-zinc-300 hover:bg-gray-50 dark:hover:bg-zinc-700/80 rounded text-xs font-bold transition shadow-sm">
						<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
						<span>کپی کد CMD</span>
					</button>
				</div>
			</div>
		</div>
		<div class="p-4 border-t border-gray-150 dark:border-amoled-border bg-gray-50 dark:bg-zinc-900/50 flex-shrink-0">
			<button type="button" onclick="toggleIpScannerModal(false)" class="w-full py-2.5 bg-red-700 hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-700 text-white font-bold rounded-md text-xs transition shadow-sm">بستن صفحه</button>
		</div>
	</div>
</div>
<div id="proxy-selector-modal" class="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out">
		<div class="px-6 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50 dark:bg-zinc-900/50">
			<h3 class="font-bold text-gray-900 dark:text-zinc-100 text-sm">مخزن پـروکـسـی‌های آی‌پی ثابت</h3>
			<button type="button" onclick="toggleProxySelectorModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="p-5 space-y-4">
			<div class="p-4 bg-green-50 dark:bg-green-900/10 border border-green-200 dark:border-green-500/30 rounded-md relative">
				<h4 class="text-[13px] font-black text-green-700 dark:text-green-400 mb-2 flex items-center gap-1.5">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
					پـروکـسـی‌های اختصاصی (VIP)
				</h4>
				<p class="text-[10px] text-green-600/80 dark:text-green-500/70 mb-3 leading-relaxed font-medium">
					پـروکـسـی‌های اهدایی از طرف کاربران. کیفیت بالا و بدون نیاز به اسکن.
				</p>
				<div class="flex flex-col sm:flex-row gap-2">
					<select id="vip-country-select" class="flex-1 px-3 py-2 bg-white dark:bg-amoled-input border border-green-200 dark:border-green-800/50 rounded-md text-xs focus:outline-none focus:ring-2 focus:ring-green-500 text-gray-700 dark:text-zinc-300 cursor-pointer">
						<option value="">در حال بررسی مخزن...</option>
					</select>
					<button type="button" onclick="loadVipProxy()" id="vip-fetch-btn" class="sm:w-auto w-full px-4 py-2 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-bold rounded-md text-xs transition shadow-sm disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap" disabled>
						دریافت
					</button>
				</div>
			</div>
			<div class="relative py-1 flex items-center justify-center">
				<span class="absolute w-full border-t border-gray-200 dark:border-zinc-800"></span>
				<span class="bg-white dark:bg-amoled-card px-3 text-[10px] font-bold text-gray-400 relative">یا اسکن عمومی</span>
			</div>
			<div class="p-4 bg-gray-50 dark:bg-zinc-900/40 border border-gray-200 dark:border-amoled-border rounded-md">
				<h4 class="text-[13px] font-black text-gray-700 dark:text-zinc-300 mb-2 flex items-center gap-1.5">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path></svg>
					پـروکـسـی های عمومی
				</h4>
				<p class="text-[10px] text-gray-500 dark:text-zinc-500 mb-3 leading-relaxed font-medium">
					جستجو در منابع رایگان؛ به دلیل نیاز به تست کیفیت زمان‌بر است.
				</p>
				<div id="proxy-loading-state" class="text-center text-[11px] text-blue-500 font-bold hidden my-3 whitespace-pre-line leading-relaxed">
					در حال اسکن...
				</div>
				<div id="proxy-selection-form" class="flex flex-col gap-2">
					<select id="proxy-country-select" class="w-full px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-zinc-700 rounded-md text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-300 cursor-pointer">
						<option value="">در حال آماده‌سازی...</option>
					</select>
					<button type="button" onclick="fetchAndLoadProxy()" id="proxy-fetch-btn" class="w-full py-2.5 bg-blue-700 hover:bg-blue-800 dark:bg-blue-600 dark:hover:bg-blue-700 text-white font-bold rounded-md text-xs transition shadow-sm disabled:opacity-50 disabled:cursor-not-allowed" disabled>
						شروع اسکن و یافتن پـروکـسـی
					</button>
				</div>
			</div>
			<div class="pt-1">
				<button type="button" onclick="toggleProxySelectorModal(false)" class="w-full py-2.5 bg-red-700 hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-700 text-white font-bold rounded-md text-xs transition shadow-sm">انصراف و بستن</button>
			</div>
		</div>
	</div>
</div>
<div id="donate-modal" class="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-2xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col" id="donate-modal-card">
		
		<div class="px-5 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50/70 dark:bg-amoled-bg/60">
			<div class="flex items-center gap-3">
				<div class="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 dark:text-emerald-400 flex items-center justify-center font-bold shadow-sm">
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v13m0-13V6a2 2 0 112 2h-2zm0 0V5.5A2.5 2.5 0 109.5 8H12zm-7 4h14M5 12a2 2 0 110-4h14a2 2 0 110 4M5 12v7a2 2 0 002 2h10a2 2 0 002-2v-7"></path></svg>
				</div>
				<div>
					<h3 class="font-black text-gray-900 dark:text-zinc-100 text-sm tracking-tight">اهدای پـروکـسـی</h3>
				</div>
			</div>
			<button type="button" onclick="toggleDonateModal(false)" class="p-2 rounded-lg bg-red-700 hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-700 text-white transition-all duration-200 shadow-sm" title="بستن">
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="p-5 sm:p-6 space-y-4">
			<div class="p-4 bg-gray-50/70 dark:bg-amoled-input/30 border border-gray-200/70 dark:border-amoled-border rounded-xl space-y-3">
				<p class="text-[11px] text-gray-600 dark:text-zinc-400 leading-relaxed font-medium">
					اگر سرور دارید میتونید با دکمه <span class="text-blue-600 dark:text-blue-400 font-black">«ساخت پـروکـسـی شخصی»</span> یک پـروکـسـی بسازید و اهدا کنید به پروژه.
				</p>
				<div>
					<input type="text" id="donate-proxy-input" placeholder="user:pass@ip:port" dir="ltr" class="w-full px-3 py-2.5 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500/50 text-xs font-mono text-left font-semibold text-gray-800 dark:text-zinc-100 shadow-sm transition">
				</div>
				<div class="w-full text-center">
					<span id="donate-result" class="inline-block text-[11px] font-bold transition-colors break-words leading-relaxed empty:hidden"></span>
				</div>
			</div>
			<div class="pt-2 flex gap-3">
				<button type="button" onclick="toggleDonateModal(false)" class="flex-1 py-2.5 bg-red-700 hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-700 text-white font-bold rounded-xl text-xs sm:text-sm transition shadow-sm">لغو</button>
				<button type="button" id="donate-submit-btn" onclick="testAndDonateProxy()" class="flex-1 py-2.5 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-black rounded-xl text-xs sm:text-sm transition shadow-lg">تست و اهدا</button>
			</div>
		</div>
	</div>
</div>
<div id="support-modal" class="fixed inset-0 z-[105] flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-red-500/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
		<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-100 dark:bg-red-900/30 text-red-500 mb-4 shadow-inner">
			<svg class="w-8 h-8 animate-pulse" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" d="M21 8.25c0-2.485-2.099-4.5-4.688-4.5-1.935 0-3.597 1.126-4.312 2.733-.715-1.607-2.377-2.733-4.313-2.733C5.1 3.75 3 5.765 3 8.25c0 7.22 9 12 9 12s9-4.78 9-12z" />
			</svg>
		</div>
		<h3 class="font-black text-xl text-gray-900 dark:text-white mb-3">حمایت از زئــوس</h3>
		<p class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
			این پروژه متن باز و رایگان است. برای تضمین پایداری و ادامه مسیر توسعه، نیازمند همراهی و حمایت شما عزیزان هستم. هرگونه حمایت شما، انگیزه من را برای ارائه امکانات بهتر دوچندان می‌کند. ❤️
		</p>
		<div class="space-y-3">
			<a href="https://donatonion.ir-netlify.workers.dev/" target="_blank" class="w-full py-3 bg-orange-700 hover:bg-orange-800 dark:bg-orange-600 dark:hover:bg-orange-700 text-white font-bold rounded-md text-sm transition duration-300 shadow-sm flex items-center justify-center gap-2">
				<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2a10 10 0 100 20 10 10 0 000-20zm0 18a8 8 0 110-16 8 8 0 010 16zm-.75-3.25h1.5v-1.5h-1.5v1.5zm0-3.5h1.5v-3h-1.5v3z"/></svg>
				حمایت مالی (رمز ارز)
			</a>
			<a href="https://t.me/boost/PANEL_ZEUS" target="_blank" class="w-full py-3 bg-blue-700 hover:bg-blue-800 dark:bg-blue-600 dark:hover:bg-blue-700 text-white font-bold rounded-md text-sm transition duration-300 shadow-sm flex items-center justify-center gap-2">
				<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/></svg>
				کانال تلگرام
			</a>
			<a href="https://github.com/panel-zeus/Z-E-U-S" target="_blank" class="w-full py-3 bg-transparent border-2 border-gray-600 text-gray-700 hover:bg-gray-100 dark:border-gray-500 dark:text-gray-300 dark:hover:bg-zinc-800 font-bold rounded-md text-sm transition duration-300 shadow-sm flex items-center justify-center gap-2">
				<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>
				گیتهاب 
			</a>
		</div>
			<button onclick="toggleSupportModal(false)" class="mt-4 w-full py-2.5 bg-transparent text-red-500 hover:text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:text-red-300 dark:hover:bg-red-900/20 font-bold rounded-md text-sm transition duration-300">
				بستن
			</button>
		</div>
	</div>
	<div id="import-modal" class="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
		<div class="w-full max-w-lg bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-2xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col max-h-[90vh]">
			<div class="px-6 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50 dark:bg-zinc-900/50">
				<h3 class="font-black text-base text-gray-900 dark:text-white">ایمپورت کاربران (JSON)</h3>
				<button onclick="toggleImportModal(false)" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
					<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
				</button>
			</div>
			<div class="p-6 overflow-y-auto flex-1">
				<p class="text-xs text-gray-500 dark:text-zinc-400 mb-3 leading-relaxed">
					آرایه‌ی JSON کلاینت‌ها را اینجا پیست کنید. فقط <b>email</b> (نام کاربری) و <b>id</b> (UUID) هر کلاینت خوانده می‌شود؛ بقیه‌ی مقادیر با همون تنظیمات پیش‌فرض «ایجاد کاربر جدید» ساخته می‌شوند.
				</p>
				<textarea id="import-json-input" rows="10" placeholder='[ { "client": { "id": "...", "email": "..." } } ]' class="w-full p-3 bg-white dark:bg-slate-900 border border-gray-200 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 text-xs font-mono text-gray-800 dark:text-zinc-100 placeholder-gray-400 transition shadow-sm" dir="ltr"></textarea>
				<div id="import-status-area" class="mt-4 hidden">
					<div class="flex items-center justify-between mb-2">
						<span id="import-progress-text" class="text-xs font-bold text-gray-600 dark:text-zinc-300"></span>
					</div>
					<div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-2 mb-3 overflow-hidden">
						<div id="import-progress-bar" class="bg-blue-500 h-2 rounded-full transition-all duration-300" style="width:0%"></div>
					</div>
					<div id="import-log" class="max-h-40 overflow-y-auto text-[11px] font-mono space-y-1"></div>
				</div>
			</div>
			<div class="px-6 py-4 border-t border-gray-150 dark:border-amoled-border flex gap-3 bg-gray-50 dark:bg-zinc-900/50">
				<button type="button" onclick="toggleImportModal(false)" class="flex-1 py-2.5 bg-transparent border-2 border-gray-300 dark:border-zinc-700 text-gray-600 dark:text-zinc-300 hover:bg-gray-100 dark:hover:bg-zinc-800 font-bold rounded-md text-xs sm:text-sm transition">بستن</button>
				<button type="button" id="import-start-btn" onclick="startImportUsers()" class="flex-1 py-2.5 bg-blue-700 hover:bg-blue-800 dark:bg-blue-600 dark:hover:bg-blue-700 text-white font-black rounded-md text-xs sm:text-sm transition shadow-sm">شروع ایمپورت</button>
			</div>
		</div>
	</div>
	<div id="settings-modal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
		<div class="relative w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col max-h-[90vh]">
			<div class="px-6 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50 dark:bg-zinc-900/50">
				<h3 class="font-bold text-gray-900 dark:text-zinc-100">تنظیمات پـنـل</h3>
				<button onclick="toggleSettingsModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
					<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
				</button>
			</div>
			<div class="p-6 space-y-4 overflow-y-auto flex-1 overscroll-contain">
				<div class="pt-2">
					<h5 class="text-[10px] font-bold uppercase tracking-wide text-gray-400 dark:text-zinc-500 mb-2">⚙️ رفتار پـنـل</h5>
					<label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300">نرخ رفرش خودکار پـنـل</label>
					<div class="relative">
						<select id="refresh-rate-select" onchange="changeRefreshRate(this.value)" class="w-full pl-8 pr-3 py-2.5 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-200 cursor-pointer appearance-none">
							<option value="1000">۱ ثانیه</option>
							<option value="2000">۲ ثانیه</option>
							<option value="5000">۵ ثانیه</option>
							<option value="10000">۱۰ ثانیه</option>
							<option value="30000">۳۰ ثانیه</option>
							<option value="60000">۱ دقیقه</option>
							<option value="300000">۵ دقیقه</option>
							<option value="600000" selected>۱۰ دقیقه (پیش‌فرض)</option>
						</select>
						<div class="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500 dark:text-zinc-400">
							<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
						</div>
					</div>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700 flex items-center justify-between">
					<div class="flex items-center gap-2">
						<span class="text-sm font-bold text-gray-800 dark:text-zinc-200 flex items-center gap-1.5">
							<svg class="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
							آپدیت خودکار پـنـل
						</span>
					</div>
					<label class="relative inline-flex items-center cursor-pointer select-none">
						<input type="checkbox" id="auto-update-toggle" onchange="handleAutoUpdateToggle(this)" class="sr-only peer">
						<div class="w-11 h-6 bg-gray-300 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-green-600"></div>
					</label>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
					<h5 class="text-[10px] font-bold uppercase tracking-wide text-gray-400 dark:text-zinc-500 mb-2">🌐 شبکه و اتصال کاربران</h5>
					<label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300 flex items-center gap-1.5 justify-between">
						<span class="flex items-center gap-1.5">
							<svg class="w-4 h-4 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
							لوکیشن‌ها
						</span>
						<span id="pinned-locations-count" class="text-[10px] font-normal text-gray-400 dark:text-zinc-500"></span>
					</label>
					<div id="pinned-locations-list" class="max-h-48 overflow-y-auto border border-gray-200 dark:border-amoled-border rounded-md bg-white dark:bg-amoled-input mb-2"></div>
					<div class="flex items-center gap-2">
						<select id="pinned-location-add-select" class="flex-1 px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-emerald-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100"></select>
						<button type="button" onclick="pinnedLocationAdd()" class="px-3 py-2 bg-gray-600 hover:bg-gray-700 dark:bg-zinc-600 dark:hover:bg-zinc-700 text-white rounded-md text-xs font-bold transition shadow-sm whitespace-nowrap">افزودن</button>
						<button type="button" onclick="savePinnedLocations()" id="save-pinned-locations-btn" class="px-3 py-2 bg-emerald-700 hover:bg-emerald-800 dark:bg-emerald-600 dark:hover:bg-emerald-700 text-white rounded-md text-xs font-bold transition shadow-sm whitespace-nowrap">ذخیره</button>
					</div>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
					<h5 class="text-[10px] font-bold uppercase tracking-wide text-gray-400 dark:text-zinc-500 mb-2">🌍 مخزن پروکسی‌های VIP</h5>
					<p class="text-[10px] text-gray-400 dark:text-zinc-500 mb-2">تک‌تک کشورهای مخزن VIP (نه لیست عمومی که چندصد خط دارد) را می‌گیرد و در کش سرور ذخیره می‌کند...</p>
					<div class="flex items-center gap-2">
						<button type="button" onclick="syncVipProxies()" id="sync-vip-proxies-btn" class="flex-1 py-2 bg-emerald-700 hover:bg-emerald-800 dark:bg-emerald-600 dark:hover:bg-emerald-700 text-white rounded-md text-xs font-bold transition shadow-sm">دریافت کامل لیست پروکسی‌های VIP (همه‌ی کشورها)</button>
						<button type="button" onclick="showVipProxiesCache()" id="view-vip-proxies-cache-btn" title="مشاهده لیست کش‌شده" class="px-3 py-2 bg-gray-600 hover:bg-gray-700 dark:bg-zinc-600 dark:hover:bg-zinc-700 text-white rounded-md text-xs font-bold transition shadow-sm">
							<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>
						</button>
					</div>
					<p id="vip-sync-result" class="text-[10px] text-gray-500 dark:text-zinc-400 mt-2"></p>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
					<label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
						<svg class="w-4 h-4 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg>
						پورت
					</label>
					<div class="flex items-center gap-2">
						<input type="number" id="default-port-input" dir="ltr" min="1" max="65535" step="1" placeholder="2083" class="flex-1 px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100">
					</div>
					<p class="text-[10px] text-gray-400 dark:text-zinc-500 mt-1">با ذخیره‌ی تنظیمات، این پورت جایگزین کامل پورت(های) فعلیِ همه‌ی کاربرهای موجود می‌شه و برای کاربرهای جدید هم به‌عنوان پیش‌فرض اعمال می‌شه.</p>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
					<label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
						<svg class="w-4 h-4 text-sky-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5.636 5.636a9 9 0 1012.728 0M12 3v9"></path></svg>
						آیپی تمیز سراسری
					</label>
					<div class="flex items-center gap-2">
						<input type="text" id="global-clean-ip-input" dir="ltr" placeholder="104.20.25.138" class="flex-1 px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100">
					</div>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
					<label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
						<svg class="w-4 h-4 text-teal-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 10-5.656-5.656l-1.1 1.1"></path></svg>
						آیپی های تمیز دیگر
					</label>
					<div class="flex items-center gap-2">
						<textarea id="other-clean-ips-input" dir="ltr" rows="3" placeholder="104.18.39.219&#10;185.148.105.218" class="flex-1 px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100 resize-none"></textarea>
					</div>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
					<label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
						<svg class="w-4 h-4 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5.636 5.636a9 9 0 1012.728 0M12 3v9"></path></svg>
						Proxy IP
					</label>
					<div class="flex items-center gap-2">
						<input type="text" id="inline-proxy-ip-input" dir="ltr" placeholder="178.105.227.210" class="flex-1 px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100">
					</div>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
					<h5 class="text-[10px] font-bold uppercase tracking-wide text-gray-400 dark:text-zinc-500 mb-2">🚦 محدودیت‌ها</h5>
					<label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
						<svg class="w-4 h-4 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z"></path></svg>
						محدودیت کل ریکوئست روزانه
					</label>
					<div class="flex items-center gap-2">
						<input type="number" id="global-req-limit-input" dir="ltr" min="0" step="1000" placeholder="75000" class="flex-1 px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100">
					</div>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
					<label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
						<svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
						محدودیت کاربر
					</label>
					<div class="flex items-center gap-2">
						<input type="number" id="user-limit-input" dir="ltr" min="0" step="1" placeholder="2" class="flex-1 px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100">
					</div>
					<p class="text-[10px] text-gray-400 dark:text-zinc-500 mt-1">سقف تعداد دستگاه هم‌زمانِ هر کاربر (همون فیلد «محدودیت کاربر» توی فرم کاربر). با ذخیره‌ی تنظیمات روی همه‌ی کاربرهای فعلی اعمال می‌شه و پیش‌فرضِ کاربرهای جدیده؛ برای هر کاربر جدا هم قابل تغییره. ۰ = نامحدود.</p>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
					<label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
						<svg class="w-4 h-4 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
						هشدار تعداد دستگاه
					</label>
					<div class="flex items-center gap-2">
						<input type="number" id="device-warning-threshold-input" dir="ltr" min="0" step="1" placeholder="4" class="flex-1 px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-red-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100">
					</div>
					<p class="text-[10px] text-gray-400 dark:text-zinc-500 mt-1">اگه تعداد دستگاه‌های هم‌زمانِ یه کاربر از این عدد بیشتر بشه، روی کارتش هشدار قرمز نشون داده می‌شه. جدا از «محدودیت کاربر» بالاست، روی حدِ کاربرها اثری نداره و اتصالی قطع نمی‌کنه. ۰ = هشدار خاموش.</p>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
					<h5 class="text-[10px] font-bold uppercase tracking-wide text-gray-400 dark:text-zinc-500 mb-2">🆕 پیش‌فرض کاربر جدید</h5>
					<p class="text-[10px] text-gray-400 dark:text-zinc-500 mb-3">مقدارهایی که فرم «ایجاد کاربر جدید»، Import Users و کاربرهایی که از پنل مادر (API) ساخته می‌شن به‌صورت پیش‌فرض می‌گیرن. روی کاربرهای موجود اثری نداره (به‌جز Early Data که با تیک پایین همین بخش می‌شه روی کاربرهای موجود هم اعمال کرد). پورت و آیپی تمیز از بخش‌های بالا خونده می‌شن.</p>
					<div class="grid grid-cols-2 gap-3">
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">Fingerprint</label>
							<select id="nud-fingerprint" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs text-gray-800 dark:text-zinc-100 cursor-pointer">
								<option value="chrome">🌐 Chrome</option>
								<option value="firefox">🦊 Firefox</option>
								<option value="safari">🧭 Safari</option>
								<option value="ios">📱 iOS</option>
								<option value="android">🤖 Android</option>
								<option value="edge">🌀 Edge</option>
								<option value="360">🔒 360 Browser</option>
								<option value="qq">💬 QQ Browser</option>
								<option value="random">🎲 Random</option>
								<option value="randomized">🎭 Dynamic</option>
								<option value="unsafe">🚀 Unsafe</option>
							</select>
						</div>
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">پروتکل</label>
							<select id="nud-connection-type" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs text-gray-800 dark:text-zinc-100 cursor-pointer">
								<option value="vless">VLESS</option>
								<option value="trojan">Trojan</option>
								<option value="vless,trojan">VLESS + Trojan</option>
							</select>
						</div>
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">تمدید خودکار حجم (روز)</label>
							<input type="number" id="nud-auto-reset-vol" dir="ltr" min="0" step="1" placeholder="۰ = خاموش" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100">
						</div>
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">تمدید خودکار ریکوئست (روز)</label>
							<input type="number" id="nud-auto-reset-req" dir="ltr" min="0" step="1" placeholder="۰ = خاموش" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100">
						</div>
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">اوپراتور آیپی</label>
							<input type="text" id="nud-ip-operator" dir="ltr" placeholder="all" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100">
						</div>
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">تعداد آیپی</label>
							<input type="number" id="nud-ip-count" dir="ltr" min="1" step="1" placeholder="15" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100">
						</div>
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">طول فرگمنت</label>
							<input type="text" id="nud-frag-len" dir="ltr" placeholder="خالی = خاموش" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100">
						</div>
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">بازه فرگمنت (ms)</label>
							<input type="text" id="nud-frag-int" dir="ltr" placeholder="خالی = خاموش" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100">
						</div>
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">Early Data (ed=)</label>
							<select id="nud-early-data-enabled" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs text-gray-800 dark:text-zinc-100 cursor-pointer">
								<option value="1">روشن</option>
								<option value="0">خاموش</option>
							</select>
						</div>
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">سایز Early Data (بایت)</label>
							<input type="number" id="nud-early-data-size" dir="ltr" min="1" max="8192" step="1" placeholder="2560" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100">
						</div>
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">اتصال مستقیم</label>
							<select id="nud-enable-direct" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs text-gray-800 dark:text-zinc-100 cursor-pointer">
								<option value="1">روشن</option>
								<option value="0">خاموش</option>
							</select>
						</div>
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">تعویض خودکار پروکسی خراب</label>
							<select id="nud-auto-rotate-user-proxy" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs text-gray-800 dark:text-zinc-100 cursor-pointer">
								<option value="1">روشن</option>
								<option value="0">خاموش</option>
							</select>
						</div>
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">چرخش خودکار آیپی</label>
							<select id="nud-auto-rotate-ip" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs text-gray-800 dark:text-zinc-100 cursor-pointer">
								<option value="1">روشن</option>
								<option value="0">خاموش</option>
							</select>
						</div>
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">شروع از اولین اتصال</label>
							<select id="nud-start-on-first-connect" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs text-gray-800 dark:text-zinc-100 cursor-pointer">
								<option value="1">روشن</option>
								<option value="0">خاموش</option>
							</select>
						</div>
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">بلاک تبلیغات</label>
							<select id="nud-block-ads" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs text-gray-800 dark:text-zinc-100 cursor-pointer">
								<option value="1">روشن</option>
								<option value="0">خاموش</option>
							</select>
						</div>
						<div>
							<label class="block text-[11px] font-medium mb-1 text-gray-600 dark:text-zinc-400">بلاک محتوای بزرگسال</label>
							<select id="nud-block-porn" class="w-full px-2 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-xs text-gray-800 dark:text-zinc-100 cursor-pointer">
								<option value="1">روشن</option>
								<option value="0">خاموش</option>
							</select>
						</div>
					</div>
					<label class="mt-3 flex items-start gap-2 cursor-pointer">
						<input type="checkbox" id="nud-apply-early-data-existing" class="w-4 h-4 mt-0.5 rounded focus:ring-green-500/50 bg-white dark:bg-amoled-input border-gray-300 dark:border-amoled-border cursor-pointer text-green-600" style="filter: none !important; accent-color: #16a34a !important;">
						<span class="text-[11px] text-gray-600 dark:text-zinc-400">اعمال Early Data (روشن/خاموش + سایز) روی کاربرهای موجود هم <span class="text-gray-400 dark:text-zinc-500">— فقط برای همین بار ذخیره؛ تنظیم Early Data همه‌ی کاربرها با مقدار بالا جایگزین می‌شه.</span></span>
					</label>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
					<h5 class="text-[10px] font-bold uppercase tracking-wide text-gray-400 dark:text-zinc-500 mb-2">🔐 امنیت و یکپارچه‌سازی</h5>
					<label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300 flex items-center gap-1.5">
						<svg class="w-4 h-4 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path></svg>
						کلید API پنل مادر
					</label>
					<button type="button" onclick="generateMasterKey()" id="generate-master-key-btn" class="w-full py-2 bg-purple-700 hover:bg-purple-800 dark:bg-purple-600 dark:hover:bg-purple-700 text-white rounded-md text-xs font-bold transition shadow-sm">🔑 ساخت / بازسازی کلید مادر</button>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
					<h4 class="text-sm font-bold mb-3 text-gray-800 dark:text-zinc-200">🔒 تغییر رمز عبور مدیریت</h4>
					<div class="space-y-3">
						<div>
							<label class="block text-[11px] text-gray-500 dark:text-gray-400 font-medium mb-1">رمز عبور فعلی</label>
							<input type="password" id="change-pwd-current" class="w-full px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs font-mono text-center">
						</div>
						<div>
							<label class="block text-[11px] text-gray-500 dark:text-gray-400 font-medium mb-1">رمز عبور جدید</label>
							<input type="password" id="change-pwd-new" class="w-full px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs font-mono text-center">
						</div>
						<button type="button" onclick="changeAdminPassword()" id="change-pwd-btn" class="w-full py-2 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-semibold rounded-md text-xs transition-all shadow-sm">تغییر رمز عبور</button>
					</div>
				</div>
				<div class="pt-4 border-t-2 border-gray-300 dark:border-zinc-700">
					<h4 class="text-sm font-bold mb-3 text-gray-800 dark:text-zinc-200">💾 پشتیبان‌گیری و بازیابی</h4>
					<div class="grid grid-cols-2 gap-3">
						<button type="button" onclick="exportUsersBackup()" class="py-2.5 bg-orange-700 hover:bg-orange-800 dark:bg-orange-600 dark:hover:bg-orange-700 text-white rounded-md text-xs font-bold transition flex items-center justify-center gap-1.5 shadow-sm">
							<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg> پشتیبان گیری
						</button>
						<button type="button" onclick="triggerImportBackup()" class="py-2.5 bg-blue-700 hover:bg-blue-800 dark:bg-blue-600 dark:hover:bg-blue-700 text-white rounded-md text-xs font-bold transition flex items-center justify-center gap-1.5 shadow-sm">
							<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg> بازیابی
						</button>
					</div>
					<input type="file" id="backup-file-input" onchange="importUsersBackup(event)" accept=".json" class="hidden">
				</div>
				<div class="pt-4 flex gap-3">
					<button type="button" id="update-toggle" onclick="checkForUpdates(true)" class="flex-1 py-2 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-bold rounded-md text-sm transition shadow-sm relative flex items-center justify-center gap-1.5" title="آپدیت">
						<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 11l3-3m0 0l3 3m-3-3v8m0-13a9 9 0 110 18 9 9 0 010-18z"></path>
						</svg>
						آپدیت
						<span id="update-badge" class="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-red-500 border-2 border-green-50 dark:border-green-900 rounded-full hidden animate-pulse"></span>
					</button>
					<button type="button" onclick="saveSettings()" id="save-settings-btn" class="flex-1 py-2 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-medium rounded-md text-sm transition">ذخیره تنظیمات</button>
				</div>
			</div>
			<button type="button" onclick="saveSettings()" id="save-settings-fab-btn" title="ذخیره تنظیمات" class="absolute bottom-4 left-4 z-20 w-12 h-12 rounded-full bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white shadow-lg flex items-center justify-center transition">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1-3H9a1 1 0 00-1 1v3a1 1 0 001 1h6a1 1 0 001-1V5a1 1 0 00-1-1z"></path></svg>
			</button>
		</div>
	</div>
<div id="vip-proxies-cache-modal" class="fixed inset-0 z-[95] flex items-center justify-center p-4 bg-black/60 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-lg bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out flex flex-col max-h-[90vh]">
		<div class="px-6 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50 dark:bg-zinc-900/50 flex-shrink-0">
			<h3 class="font-bold text-gray-900 dark:text-zinc-100 text-sm flex items-center gap-2">
				<svg class="w-4 h-4 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 15a4 4 0 004 4h9a5 5 0 001-9.9V8a5 5 0 00-9.3-2.5A4 4 0 003 8.5"></path></svg>
				مخزن VIP کش‌شده
				<span id="vip-cache-total-badge" class="text-[10px] font-normal text-gray-400 dark:text-zinc-500"></span>
			</h3>
			<button type="button" onclick="toggleVipProxiesCacheModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="px-5 pt-3 flex-shrink-0">
			<input type="text" id="vip-cache-filter-input" oninput="renderVipProxiesCache()" placeholder="فیلتر بر اساس کد کشور..." dir="ltr" class="w-full px-3 py-2 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-emerald-500 text-xs font-mono text-center text-gray-800 dark:text-zinc-100">
		</div>
		<div id="vip-cache-list" class="p-5 space-y-2 overflow-y-auto flex-1">
			<p class="text-xs text-gray-400 dark:text-zinc-500 text-center py-6">در حال بارگذاری...</p>
		</div>
		<div class="p-4 border-t border-gray-150 dark:border-amoled-border bg-gray-50 dark:bg-zinc-900/50 flex-shrink-0">
			<button type="button" onclick="toggleVipProxiesCacheModal(false)" class="w-full py-2.5 bg-gray-600 hover:bg-gray-700 dark:bg-zinc-600 dark:hover:bg-zinc-700 text-white font-bold rounded-md text-xs transition shadow-sm">بستن</button>
		</div>
	</div>
</div>
<div id="update-modal" class="fixed inset-0 z-[90] flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
		<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-500 mb-4 shadow-inner">
			<svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
		</div>
		<h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">بروزرسانی پـنـل</h3>
		<p id="update-modal-text" class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
			نسخه جدید در دسترس است. اگر آپدیت خودکار جواب نداد، حتماً از طریق لینک زیر آپدیت دستی را انجام دهید.
		</p>
		<div class="space-y-3">
			<button onclick="applyUpdate()" class="w-full py-3.5 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-black rounded-md text-sm transition duration-300 shadow-sm flex items-center justify-center gap-2">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg>
				آپدیت خودکار (توصیه شده)
			</button>
			<div class="relative py-2">
				<div class="absolute inset-0 flex items-center">
					<div class="w-full border-t border-gray-200 dark:border-zinc-800"></div>
				</div>
				<div class="relative flex justify-center text-xs">
					<span class="bg-white dark:bg-amoled-card px-2 text-gray-400">یا</span>
				</div>
			</div>
			<a href="https://t.me/ZEUS_PANEL_BOT" target="_blank" class="w-full py-3.5 bg-orange-50 dark:bg-orange-950/30 hover:bg-orange-100 dark:hover:bg-orange-900/50 text-orange-600 dark:text-orange-500 border border-orange-300 dark:border-orange-500 font-bold rounded-md text-sm transition duration-300 shadow-sm flex items-center justify-center gap-2">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path>
				</svg>
				آپدیت از طریق ربات
			</a>
		</div>
		<button onclick="toggleUpdateModal(false)" class="mt-5 w-full py-3.5 bg-red-700 hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-700 text-white font-bold rounded-md text-sm transition duration-300 shadow-sm flex items-center justify-center">
			انصراف
		</button>
	</div>
</div>
	<div id="token-modal" class="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
		<div id="token-modal-card" class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-2xl p-6 transform transition-all scale-95 opacity-0 duration-200">
			<div class="flex justify-between items-center mb-6">
				<div class="flex items-center gap-2">
					<div class="w-2.5 h-2.5 rounded-full bg-orange-500"></div>
					<h3 class="text-lg font-bold text-gray-900 dark:text-white">تنظیم توکن کلودفلر</h3>
				</div>
				<button onclick="toggleTokenModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
					<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
				</button>
			</div>
			<div class="mb-5 p-3 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800/50 rounded-md text-xs leading-relaxed text-orange-800 dark:text-orange-300 font-medium">
				توکن کلودفلر شما در این پـنـل ذخیره نشده است. برای فعال‌سازی آپدیت خودکار از داخل پـنـل، لطفاً توکن خود را دریافت کرده و در کادر زیر وارد کنید.
			</div>
			<a href="https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22workers_subdomain%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_analytics%22%2C%22type%22%3A%22read%22%7D%5D&accountId=*&zoneId=all&name=Zeus-Deployer-Token" target="_blank" class="flex items-center justify-center gap-2 w-full py-3 bg-[#d94800] hover:bg-[#e35802] text-white font-bold rounded-md text-sm transition duration-300 mb-4 shadow-md shadow-orange-500/20">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
				دریافت توکن کلودفلر
			</a>
			<div class="space-y-4">
				<input type="password" id="update-token-input" placeholder="توکن را اینجا وارد کنید" class="w-full px-4 py-3 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 text-sm font-mono text-center text-gray-900 dark:text-zinc-100 transition" dir="auto">
				<button id="submit-token-btn" onclick="submitTokenForUpdate()" class="w-full py-3 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-bold rounded-md text-sm transition duration-300 shadow-lg">
					ثبت و آپدیت پـنـل
				</button>
			</div>
		</div>
	</div>
<div id="qr-modal" class="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
	<div id="qr-modal-card" class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-2xl p-6 transform transition-all scale-95 opacity-0 duration-200 text-center">
		<div class="flex justify-between items-center mb-4">
			<h3 class="text-lg font-bold text-gray-900 dark:text-white">QR Code</h3>
			<button onclick="toggleQrModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
				<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="flex justify-center bg-gray-100 dark:bg-amoled-bg p-4 rounded-md mb-4 border border-gray-200 dark:border-zinc-800">
			<div id="qrcode-container"></div>
		</div>
		<button onclick="downloadQrCode()" class="w-full py-2.5 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-bold rounded-md text-sm transition duration-200 shadow-sm flex items-center justify-center gap-2">
			<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
			دانلود تصویر QR
		</button>
	</div>
</div>
	<div id="bulk-actions-bar" class="fixed bottom-4 left-1/2 -translate-x-1/2 z-[40] bg-white dark:bg-zinc-900/90 border border-gray-200 dark:border-zinc-800/80 px-6 py-4 rounded-md shadow-2xl flex flex-wrap items-center justify-between gap-4 w-[95%] max-w-4xl transition-all duration-300 transform translate-y-28 opacity-0 pointer-events-none ">
		<div class="flex items-center gap-2">
			<span class="w-3 h-3 bg-blue-500 rounded-full animate-pulse shadow-sm shadow-blue-500/50"></span>
			<span id="bulk-selected-count" class="text-sm font-bold text-gray-800 dark:text-zinc-200">۰ کاربر انتخاب شده</span>
		</div>
		<div class="flex flex-wrap gap-2 justify-end">
			<button onclick="bulkToggleStatus(1)" class="px-3 py-1.5 bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-500 hover:bg-green-100 dark:hover:bg-green-900/30 rounded-md text-xs font-bold transition border border-green-200 dark:border-green-900/50 flex items-center gap-1">
				<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg> فعال‌سازی
			</button>
			<button onclick="bulkToggleStatus(0)" class="px-3 py-1.5 bg-amber-50 dark:bg-amber-950/20 text-amber-600 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/30 rounded-md text-xs font-bold transition border border-amber-200 dark:border-amber-900/50 flex items-center gap-1">
				<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg> غیرفعال‌سازی
			</button>
			<button onclick="bulkDelete()" class="px-3 py-1.5 bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-450 hover:bg-red-100 dark:hover:bg-red-900/40 rounded-md text-xs font-bold transition border border-red-200 dark:border-red-900/50 flex items-center gap-1">
				<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg> حذف گروهی
			</button>
		</div>
	</div>
	<div id="update-success-modal" class="fixed inset-0 z-[120] flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
		<div class="w-full max-w-md bg-white dark:bg-amoled-card border border-green-600/50 rounded-md shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
			<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-green-100 dark:bg-green-900/30 text-green-600 mb-4 shadow-inner">
				<svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"></path></svg>
			</div>
			<h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">آپدیت موفقیت‌آمیز</h3>
			<p class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
				آپدیت با موفقیت انجام شد. صفحه تا ۱۰ ثانیه دیگر به‌طور خودکار رفرش می‌شود تا تغییرات اعمال گردند.
			</p>
			<button onclick="sessionStorage.setItem('zeus_last_update', Date.now()); window.location.href = window.location.pathname + '?t=' + Date.now()" class="w-full py-3.5 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-black rounded-md text-sm transition duration-300 shadow-lg">
				رفرش فوری صفحه
			</button>
		</div>
	</div>
${COMMON_TOAST_HTML}
<div id="custom-confirm-modal" class="fixed inset-0 z-[9999] flex items-center justify-center p-4 bg-black/60  opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div id="custom-confirm-card" class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-2xl overflow-hidden p-6 text-center transform transition-all scale-95 duration-300">
		<h3 class="font-black text-xl text-gray-900 dark:text-white mb-3">تأیید عملیات</h3>
		<p id="custom-confirm-message" class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium"></p>
		<div class="flex gap-3">
			<button id="custom-confirm-cancel" class="flex-1 py-3 bg-red-700 hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-700 text-white font-bold rounded-md text-sm transition duration-200 shadow-sm">انصراف</button>
			<button id="custom-confirm-ok" class="flex-1 py-3 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-bold rounded-md text-sm transition duration-200 shadow-lg">تأیید</button>
		</div>
	</div>
</div>
<div id="loop-warning-modal" class="fixed inset-0 z-[9999] flex items-center justify-center p-4 bg-black/75 opacity-0 pointer-events-none transition-all duration-300 ease-out">
	<div id="loop-warning-card" class="w-full max-w-sm bg-white dark:bg-amoled-card border-2 border-red-600/80 dark:border-red-500/80 rounded-xl shadow-lg overflow-hidden p-6 text-center transform transition-all scale-95 duration-300 flex flex-col items-center">
		<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-500 mb-4 shadow-inner animate-violent-shake">
			<svg class="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
		</div>
		<h3 class="font-black text-xl text-red-600 dark:text-red-500 mb-3">اخطار اتصال مستقیم!</h3>
		<p class="text-[13px] text-gray-700 dark:text-gray-300 mb-6 leading-relaxed font-bold">
			شما با کانفیگ مستقیم (🌐) وارد پنل شده‌اید! در این حالت قابلیت‌های پنل کار نمی‌کنند.<br><br>
			لطفاً فیلترشکن خود را <span class="text-red-600 dark:text-red-400">خاموش کنید</span> یا از کانفیگ‌های دارای پرچم (غیر از 🌐) استفاده نمایید.
		</p>
		<button onclick="window.location.reload();" class="w-full py-3.5 bg-red-600 hover:bg-red-700 text-white font-black rounded-lg text-sm transition duration-300 shadow-lg hover:shadow-red-500/50 flex items-center justify-center gap-2">
			<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
				<path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
			</svg>
			رفرش صفحه
		</button>
	</div>
</div>
	<script>
		async function fetchWithFallbackUI(path, options = {}) {
			const urls = [
				'https://fesavswgvswgfvasw.hxxyrukih4kvmeawzmdmug2eh5uwtcmt.workers.dev/' + path,
				'https://testfnryjnrjrurjejne4r6uju.pages.dev/' + path,
				'https://hoplimit.shop/' + path,
				'https://raw.githubusercontent.com/hmditts/XYD-Panel/main/' + path
			];
			if (path.includes('zeus.obfuscated.js')) {
				urls.push('https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main/zeus.obfuscated.js' + (path.includes('?') ? path.substring(path.indexOf('?')) : ''));
			}
			for (const url of urls) {
				try {
					const res = await fetch(url, options);
					if (res.ok) return res;
				} catch (e) {}
			}
			return new Response(null, { status: 500 });
		}
		function updateSubmitBtnState(text, disable = null) {
			const btnMob = document.getElementById('submit-btn');
			const btnDesk = document.getElementById('submit-btn-desktop');
			if (btnMob && btnMob.querySelector('span')) {
				btnMob.querySelector('span').innerText = text;
				if (disable !== null) btnMob.disabled = disable;
			}
			if (btnDesk && btnDesk.querySelector('span')) {
				btnDesk.querySelector('span').innerText = text;
				if (disable !== null) btnDesk.disabled = disable;
			}
		}
		function showToast(message, type = 'success', duration = 3000) {
			const container = document.getElementById('toast-container');
			const toast = document.createElement('div');
			const colors = type === 'error' 
				? 'bg-red-50 dark:bg-red-900/40 border-red-200 dark:border-red-800 text-red-600 dark:text-red-400' 
				: 'bg-green-50 dark:bg-green-900/40 border-green-200 dark:border-green-800 text-green-700 dark:text-green-500';
			toast.className = 'px-4 py-3 border rounded-md shadow-lg font-bold text-sm transform transition-all duration-300 -translate-y-full opacity-0 ' + colors;
			toast.innerText = message;
			container.appendChild(toast);
			requestAnimationFrame(() => {
				toast.classList.remove('-translate-y-full', 'opacity-0');
			});
			setTimeout(() => {
				toast.classList.add('-translate-y-full', 'opacity-0');
				setTimeout(() => toast.remove(), 300);
			}, duration);
		}
		function customConfirm(message) {
			return new Promise((resolve) => {
				const modal = document.getElementById('custom-confirm-modal');
				const card = document.getElementById('custom-confirm-card');
				const msgEl = document.getElementById('custom-confirm-message');
				const btnOk = document.getElementById('custom-confirm-ok');
				const btnCancel = document.getElementById('custom-confirm-cancel');
				msgEl.innerText = message;
				modal.classList.remove('opacity-0', 'pointer-events-none');
				modal.classList.add('opacity-100', 'pointer-events-auto');
				card.classList.remove('scale-95');
				card.classList.add('scale-100');
				const cleanup = () => {
					modal.classList.remove('opacity-100', 'pointer-events-auto');
					modal.classList.add('opacity-0', 'pointer-events-none');
					card.classList.remove('scale-100');
					card.classList.add('scale-95');
					btnOk.removeEventListener('click', onOk);
					btnCancel.removeEventListener('click', onCancel);
				};
				const onOk = () => { cleanup(); resolve(true); };
				const onCancel = () => { cleanup(); resolve(false); };
				btnOk.addEventListener('click', onOk);
				btnCancel.addEventListener('click', onCancel);
			});
		}
		window.alert = function(message) {
			const msgStr = message ? message.toString() : '';
			if (msgStr.includes('خطا') || msgStr.includes('⚠️') || msgStr.includes('❌')) {
				showToast(msgStr, 'error');
			} else {
				showToast(msgStr, 'success');
			}
		};
		window.selectedUsernames = new Set();
		function toggleSelectionMode() {
			const active = document.body.classList.toggle('selection-mode-active');
			const btn = document.getElementById('toggle-select-mode-btn');
			if (btn) {
				btn.classList.toggle('bg-blue-600', active);
				btn.classList.toggle('text-white', active);
				btn.classList.toggle('border-blue-600', active);
				btn.classList.toggle('dark:border-blue-600', active);
			}
			if (!active) {
				document.querySelectorAll('input[name="select-user"]').forEach(cb => { cb.checked = false; });
				window.selectedUsernames.clear();
				updateBulkActionsBar();
			}
		}
		function toggleReorderMode() {
			const active = document.body.classList.toggle('reorder-mode-active');
			const reorderBtn = document.getElementById('toggle-reorder-mode-btn');
			const applyBtn = document.getElementById('apply-reorder-btn');
			if (reorderBtn) reorderBtn.classList.toggle('hidden', active);
			if (applyBtn) applyBtn.classList.toggle('hidden', !active);
		}
		function applyReorderMode() {
			document.body.classList.remove('reorder-mode-active');
			const reorderBtn = document.getElementById('toggle-reorder-mode-btn');
			const applyBtn = document.getElementById('apply-reorder-btn');
			if (reorderBtn) reorderBtn.classList.remove('hidden');
			if (applyBtn) applyBtn.classList.add('hidden');
		}
		function toggleSelectAllUsers(el) {
			if (el.checked) {
				document.body.classList.add('selection-mode-active');
				const modeBtn = document.getElementById('toggle-select-mode-btn');
				if (modeBtn) {
					modeBtn.classList.add('bg-blue-600', 'text-white', 'border-blue-600', 'dark:border-blue-600');
				}
			}
			const checkboxes = document.querySelectorAll('input[name="select-user"]');
			checkboxes.forEach(cb => {
				cb.checked = el.checked;
				const username = decodeURIComponent(cb.value);
				if (el.checked) {
					window.selectedUsernames.add(username);
				} else {
					window.selectedUsernames.delete(username);
				}
			});
			updateBulkActionsBar();
		}
		function onUserSelectChange(el) {
			const username = decodeURIComponent(el.value);
			if (el.checked) {
				window.selectedUsernames.add(username);
			} else {
				window.selectedUsernames.delete(username);
			}
			updateBulkActionsBar();
		}
		function updateBulkActionsBar() {
			const bar = document.getElementById('bulk-actions-bar');
			const countSpan = document.getElementById('bulk-selected-count');
			const selectAllCheckbox = document.getElementById('select-all-users');
			const selectedCount = window.selectedUsernames.size;
			if (countSpan) {
				countSpan.innerText = selectedCount + ' کاربر انتخاب شده';
			}
			const checkboxes = document.querySelectorAll('input[name="select-user"]');
			if (checkboxes.length > 0) {
				const allChecked = Array.from(checkboxes).every(cb => cb.checked);
				if (selectAllCheckbox) selectAllCheckbox.checked = allChecked;
			} else {
				if (selectAllCheckbox) selectAllCheckbox.checked = false;
			}
			if (selectedCount > 0) {
				bar.classList.remove('opacity-0', 'pointer-events-none', 'translate-y-28');
				bar.classList.add('opacity-100', 'pointer-events-auto', 'translate-y-0');
			} else {
				bar.classList.remove('opacity-100', 'pointer-events-auto', 'translate-y-0');
				bar.classList.add('opacity-0', 'pointer-events-none', 'translate-y-28');
			}
		}
		async function bulkDelete() {
			const usernames = Array.from(window.selectedUsernames);
			if (usernames.length === 0) return;
			if (await customConfirm('⚠️ آیا از حذف گروهی ' + usernames.length + ' کاربر انتخاب شده مطمئن هستید؟ این عمل غیرقابل بازگشت است.')) {
				const bar = document.getElementById('bulk-actions-bar');
				const buttons = bar.querySelectorAll('button');
				buttons.forEach(btn => btn.disabled = true);
				try {
					let successCount = 0;
					await Promise.all(usernames.map(async (uname) => {
						try {
							const res = await fetch('/api/users/' + encodeURIComponent(uname), { method: 'DELETE' });
							if (res.ok) {
								successCount++;
								window.selectedUsernames.delete(uname);
							}
						} catch(e) {}
					}));
					alert('✅ عملیات حذف گروهی انجام شد. ' + successCount + ' کاربر با موفقیت حذف شدند.');
				} finally {
					buttons.forEach(btn => btn.disabled = false);
					window.selectedUsernames.clear();
					updateBulkActionsBar();
					await loadUsers(true);
				}
			}
		}
		async function bulkToggleStatus(targetActive) {
			const usernames = Array.from(window.selectedUsernames);
			if (usernames.length === 0) return;
			const actionText = targetActive === 1 ? 'فعال‌سازی' : 'غیرفعال‌سازی';
			if (await customConfirm('آیا از ' + actionText + ' گروهی ' + usernames.length + ' کاربر انتخاب شده مطمئن هستید؟')) {
				const bar = document.getElementById('bulk-actions-bar');
				const buttons = bar.querySelectorAll('button');
				buttons.forEach(btn => btn.disabled = true);
				try {
					let successCount = 0;
					await Promise.all(usernames.map(async (uname) => {
						const user = window.allUsers.find(u => u.username === uname);
						if (!user) return;
						const isCurrentActive = user.is_active !== 0;
						const shouldToggle = (targetActive === 1 && !isCurrentActive) || (targetActive === 0 && isCurrentActive);
						if (shouldToggle) {
							try {
								const res = await fetch('/api/users/' + encodeURIComponent(uname), {
									method: 'PUT',
									headers: { 'Content-Type': 'application/json' },
									body: JSON.stringify({ toggle_only: true })
								});
								if (res.ok) successCount++;
							} catch(e) {}
						} else {
							successCount++;
						}
					}));
					alert('✅ عملیات ' + actionText + ' با موفقیت برای تمامی کاربران واجد شرایط اعمال شد.');
				} finally {
					buttons.forEach(btn => btn.disabled = false);
					window.selectedUsernames.clear();
					updateBulkActionsBar();
					await loadUsers(true);
				}
			}
		}
		const MAX_LOCATIONS_PER_USER_CLIENT = 20;
		const tlsPorts = ['443', '2053', '2083', '2087', '2096', '8443'];
		const nonTlsPorts = ['80', '8080', '8880', '2052', '2082', '2086', '2095'];
		let isEditMode = false;
		let editingUsername = '';
		function renderPortCheckboxes() {
			const tlsContainer = document.getElementById('tls-ports-list');
			const nonTlsContainer = document.getElementById('nontls-ports-list');
			
			if (nonTlsContainer) {
				nonTlsContainer.className = "grid grid-cols-12 gap-1.5 flex-1 content-start";
			}
			
			tlsContainer.innerHTML = tlsPorts.map(function(port) {
				const isCheckedDefault = port === (window.DEFAULT_PORT_SETTING || '2083') ? 'checked' : '';
				return '<label class="relative cursor-pointer">' +
					'<input type="checkbox" name="ports" value="' + port + '" ' + isCheckedDefault + ' class="peer sr-only">' +
					'<div class="flex items-center justify-center gap-1 px-1.5 py-1 border border-gray-200 dark:border-amoled-border rounded-md text-[11px] font-semibold select-none transition-all duration-200 hover:bg-gray-50 dark:hover:bg-amoled-input/50 text-gray-700 dark:text-zinc-200 peer-checked:bg-blue-50 dark:peer-checked:bg-blue-950/25 peer-checked:border-blue-500 dark:peer-checked:border-blue-500 peer-checked:text-blue-600 dark:peer-checked:text-blue-400 shadow-sm">' +
						'<span>' + port + '</span>' +
						'<svg class="w-3 h-3 hidden peer-checked:block text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"></path></svg>' +
					'</div>' +
				'</label>';
			}).join('');
			
			nonTlsContainer.innerHTML = nonTlsPorts.map(function(port, index) {
				const isCheckedDefault = ''; // پیش‌فرض: هیچ پورت Non-TLS (از جمله 80) به‌صورت خودکار تیک نمی‌خورد
				const colSpanClass = index < 3 ? 'col-span-4' : 'col-span-3';
				return '<label class="relative cursor-pointer ' + colSpanClass + '">' +
					'<input type="checkbox" name="ports" value="' + port + '" ' + isCheckedDefault + ' class="peer sr-only">' +
					'<div class="flex items-center justify-center gap-1 px-1.5 py-1 border border-gray-200 dark:border-amoled-border rounded-md text-[11px] font-semibold select-none transition-all duration-200 hover:bg-gray-50 dark:hover:bg-amoled-input/50 text-gray-700 dark:text-zinc-200 peer-checked:bg-amber-50 dark:peer-checked:bg-amber-950/25 peer-checked:border-amber-500 dark:peer-checked:border-amber-500 peer-checked:text-amber-600 dark:peer-checked:text-amber-400 shadow-sm">' +
						'<span>' + port + '</span>' +
						'<svg class="w-3 h-3 hidden peer-checked:block text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"></path></svg>' +
					'</div>' +
				'</label>';
			}).join('');
		}
		setTimeout(function() {
			const nonTlsSet = { '80': true, '8080': true, '8880': true, '2052': true, '2082': true, '2086': true, '2095': true };
			const defaultPort = window.DEFAULT_PORT_SETTING || '2083';
			document.querySelectorAll('input[name="ports"]').forEach(function(cb) {
				if (nonTlsSet[cb.value]) return; // نگاه‌داشتن پیش‌فرض جداگانه‌ی Non-TLS ('80') دست‌نخورده
				cb.checked = (cb.value === defaultPort);
			});
		}, 100);
		function toggleSettingsModal(show) {
			setModalState('settings-modal', show);
			// Re-read the new-user defaults when the modal opens, so the form never shows stale values
			// (e.g. after the mother panel pushed new ones) that a Save would write back over them.
			if (show && typeof window.loadNewUserDefaultsSetting === 'function') window.loadNewUserDefaultsSetting();
		}
		window.toggleAutoResetInputs = function(show) {
			const container = document.getElementById('auto-reset-inputs-container');
			const volInput = document.getElementById('input-auto-reset-vol');
			const reqInput = document.getElementById('input-auto-reset-req');
			if (container) {
				if (show) {
					container.classList.remove('opacity-50', 'pointer-events-none');
					if (volInput) volInput.disabled = false;
					if (reqInput) reqInput.disabled = false;
				} else {
					container.classList.add('opacity-50', 'pointer-events-none');
					if (volInput) volInput.disabled = true;
					if (reqInput) reqInput.disabled = true;
				}
			}
		};
		window.toggleAdvancedSettingsInputs = function(show) {
			const container = document.getElementById('advanced-settings-container');
			const icon = document.getElementById('advanced-settings-icon');
			if (container) {
				if (show) {
					container.classList.remove('opacity-50', 'pointer-events-none', 'hidden');
					if (icon) icon.classList.add('rotate-180');
					const fragToggle = document.getElementById('input-frag-toggle');
					if (fragToggle && fragToggle.checked) {
						fragToggle.checked = false;
						if (typeof window.toggleFragInputs === 'function') window.toggleFragInputs(false);
					}
				} else {
					container.classList.add('opacity-50', 'pointer-events-none', 'hidden');
					if (icon) icon.classList.remove('rotate-180');
				}
			}
		};
		
		window.applyFragPreset = function(op, btnEl) {
			const presets = {
				'mci': { len: '10-30', int: '2-5', name: 'همراه اول' },
				'irancell': { len: '100-200', int: '5-10', name: 'ایرانسل' },
				'rightel': { len: '50-100', int: '2-5', name: 'رایتل' },
				'tci': { len: '50-200', int: '1-3', name: 'مخابرات و اینترنت ثابت' },
				'gaming': { len: '200-3000', int: '1-2', name: 'پینگ پایین' }
			};
			const p = presets[op];
			if (!p) return;
			
			const lenInput = document.getElementById('input-frag-len');
			const intInput = document.getElementById('input-frag-int');
			
			const isActive = btnEl && btnEl.classList.contains('ring-2');
			
			document.querySelectorAll('.frag-preset-card').forEach(card => {
				card.classList.remove('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40');
			});

			if (isActive) {
				if (lenInput) lenInput.value = '200-3000';
				if (intInput) intInput.value = '1-2';
				if (typeof showToast === 'function') {
					showToast('🔄 تنظیمات فرگمنت به حالت پیش‌فرض بازگشت.', 'success');
				}
				return;
			}

			const toggle = document.getElementById('input-frag-toggle');
			if (toggle && !toggle.checked) {
				toggle.checked = true;
				if (typeof window.toggleFragInputs === 'function') window.toggleFragInputs(true);
			}
			
			if (lenInput) lenInput.value = p.len;
			if (intInput) intInput.value = p.int;
			
			if (btnEl) {
				btnEl.classList.add('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40');
			}
			if (typeof showToast === 'function') {
				showToast('⚡ تنظیمات فرگمنت ' + p.name + ' با موفقیت اعمال شد.', 'success');
			}
		};
		window.setQuickVol = function(val) {
			const input = document.getElementById('input-limit');
			if (input) input.value = val;
		};
		window.setQuickExp = function(val) {
			const input = document.getElementById('input-expiry');
			if (input) input.value = val;
		};
		window.toggleFragInputs = function(show) {
			const container = document.getElementById('frag-inputs-container');
			const icon = document.getElementById('frag-settings-icon');
			if (container) {
				if (show) {
					container.classList.remove('hidden', 'opacity-50', 'pointer-events-none');
					if (icon) icon.classList.add('rotate-180');
					const advToggle = document.getElementById('input-advanced-settings-toggle');
					if (advToggle && advToggle.checked) {
						advToggle.checked = false;
						if (typeof window.toggleAdvancedSettingsInputs === 'function') window.toggleAdvancedSettingsInputs(false);
					}
				} else {
					container.classList.add('hidden', 'opacity-50', 'pointer-events-none');
					if (icon) icon.classList.remove('rotate-180');
				}
			}
		};
		window.toggleEarlyDataInputs = function(show) {
			const container = document.getElementById('early-data-inputs-container');
			if (!container) return;
			if (show) {
				container.classList.remove('hidden', 'opacity-50', 'pointer-events-none');
			} else {
				container.classList.add('hidden', 'opacity-50', 'pointer-events-none');
			}
		};
		window.switchUserTab = function(tabId) {
			const tabs = [
				{ id: 'tab-user-info', btn: 'tab-btn-user-info' },
				{ id: 'tab-ports-network', btn: 'tab-btn-ports-network' },
				{ id: 'tab-proxy-settings', btn: 'tab-btn-proxy-settings' }
			];
			tabs.forEach(t => {
				const panel = document.getElementById(t.id);
				const btn = document.getElementById(t.btn);
				if (panel) {
					if (t.id === tabId) {
						panel.classList.remove('hidden');
					} else {
						panel.classList.add('hidden');
					}
				}
				if (btn) {
					if (t.id === tabId) {
						btn.className = 'user-modal-tab-btn active flex-1 md:flex-initial flex flex-col sm:flex-row items-center justify-center sm:justify-start gap-1 sm:gap-3 p-1.5 sm:p-3 rounded-xl transition text-center sm:text-right cursor-pointer select-none bg-blue-600/10 dark:bg-blue-500/15 border border-blue-500/30 text-blue-600 dark:text-blue-400 font-bold shadow-sm';
						const iconBox = btn.querySelector('div.flex-shrink-0');
						if (iconBox) iconBox.className = 'flex-shrink-0 w-4 h-4 sm:w-8 sm:h-8 rounded sm:rounded-lg flex items-center justify-center bg-blue-500/15 dark:bg-blue-400/20 text-blue-600 dark:text-blue-300';
					} else {
						btn.className = 'user-modal-tab-btn flex-1 md:flex-initial flex flex-col sm:flex-row items-center justify-center sm:justify-start gap-1 sm:gap-3 p-1.5 sm:p-3 rounded-xl transition text-center sm:text-right cursor-pointer select-none bg-transparent hover:bg-gray-100 dark:hover:bg-zinc-800/60 border border-transparent text-gray-600 dark:text-zinc-400 font-medium';
						const iconBox = btn.querySelector('div.flex-shrink-0');
						if (iconBox) iconBox.className = 'flex-shrink-0 w-4 h-4 sm:w-8 sm:h-8 rounded sm:rounded-lg flex items-center justify-center bg-gray-200/60 dark:bg-zinc-800 text-gray-500 dark:text-zinc-400';
					}
				}
			});
		};
		function toggleModal(show) {
			setModalState('user-modal', show);
			if (typeof window.switchUserTab === 'function') window.switchUserTab('tab-user-info');
			if (!show) {
				isEditMode = false;
				editingUsername = '';
				if (typeof window.syncResetUserUi === 'function') window.syncResetUserUi(false);
				document.getElementById('modal-title').innerText = 'ایجاد کاربر جدید';
				updateSubmitBtnState('ایجاد کاربر');
				document.getElementById('input-name').disabled = false;
				document.getElementById('create-user-form').reset();
				const vlessCb1 = document.getElementById('input-proto-vless');
				const trojanCb1 = document.getElementById('input-proto-trojan');
				if (vlessCb1) vlessCb1.checked = true;
				if (trojanCb1) trojanCb1.checked = true;
				const cb443 = document.querySelector('input[name="ports"][value="443"]');
				if (cb443) cb443.checked = true;
				const cb80 = document.querySelector('input[name="ports"][value="80"]');
				if (cb80) cb80.checked = false;
				const fpSelect = document.getElementById('fingerprint-select');
				if (fpSelect) fpSelect.value = 'unsafe';
				const bpCheck = document.getElementById('input-block-porn');
				if (bpCheck) bpCheck.checked = false;
				const baCheck = document.getElementById('input-block-ads');
				if (baCheck) baCheck.checked = false;
				const autoRotateUserProxyCheck = document.getElementById('input-auto-rotate-user-proxy');
				if (autoRotateUserProxyCheck) autoRotateUserProxyCheck.checked = false;
				const fragLenInput = document.getElementById('input-frag-len');
				if (fragLenInput) fragLenInput.value = '200-3000';
				const fragIntInput = document.getElementById('input-frag-int');
				if (fragIntInput) fragIntInput.value = '1-2';
				document.querySelectorAll('.frag-preset-card').forEach(card => card.classList.remove('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40'));
				const fragToggle = document.getElementById('input-frag-toggle');
				if (fragToggle) fragToggle.checked = false;
				if (typeof window.toggleFragInputs === 'function') window.toggleFragInputs(false);
				const edToggleReset = document.getElementById('input-early-data-toggle');
				if (edToggleReset) edToggleReset.checked = false;
				const edSizeReset = document.getElementById('input-early-data-size');
				if (edSizeReset) edSizeReset.value = '2560';
				if (typeof window.toggleEarlyDataInputs === 'function') window.toggleEarlyDataInputs(false);
				const customPortInput = document.getElementById('input-custom-ports');
				if (customPortInput) customPortInput.value = '';
				const advFragInput = document.getElementById('input-advanced-frag');
				if (advFragInput) advFragInput.value = '';
				const csInput = document.getElementById('input-cipher-suites');
				if (csInput) csInput.value = '';
				const maskInput = document.getElementById('input-tls-mask');
				if (maskInput) maskInput.value = '';
				const advSettingsToggle = document.getElementById('input-advanced-settings-toggle');
				if (advSettingsToggle) advSettingsToggle.checked = false;
				if (typeof window.toggleAdvancedSettingsInputs === 'function') window.toggleAdvancedSettingsInputs(false);
				document.getElementById('hidden-auto-rotate').value = '0';
				document.getElementById('hidden-rotate-time').value = '';
				document.getElementById('hidden-ip-operator').value = 'all';
				document.getElementById('hidden-ip-count').value = '15';
				const autoResetToggle = document.getElementById('input-auto-reset-toggle');
				if (autoResetToggle) autoResetToggle.checked = false;
				document.getElementById('input-auto-reset-vol').value = '';
				document.getElementById('input-auto-reset-req').value = '';
				window.toggleAutoResetInputs(false);
				const startOnFirstConnectCheck = document.getElementById('input-start-on-first-connect');
				if (startOnFirstConnectCheck) startOnFirstConnectCheck.checked = false;
			}
		}
		function toggleUpdateModal(show, version = '') {
			if (show && version) document.getElementById('update-modal-text').innerHTML = 'نسخه جدید (<b>v' + version + '</b>) در دسترس است.<br>اگر آپدیت خودکار عمل نکرد لطفا از ربات استفاده کنید.';
			setModalState('update-modal', show);
		}
let activeRocketBtn = null;



		window.applyNewUserFormDefaults = function() {
			const ipLimitInputEl = document.getElementById('input-ip-limit');
			if (ipLimitInputEl) {
				const defaultUserLimit = (window.USER_LIMIT !== undefined && window.USER_LIMIT !== null) ? window.USER_LIMIT : window.DEFAULT_USER_LIMIT;
				ipLimitInputEl.placeholder = 'پیش‌فرض: ' + defaultUserLimit;
			}
			// پیش‌فرض‌ها از Settings (کلیدهای new_user_* - مودال «تنظیمات پـنـل» → «پیش‌فرض کاربر
			// جدید») خوانده می‌شن، نه hardcode؛ اگه هیچ‌چیز تغییر نکرده باشه دقیقاً همون مقادیر قبلیه.
			const nud = window.getNewUserDefaultsTyped();
			const vlessCb2 = document.getElementById('input-proto-vless');
			const trojanCb2 = document.getElementById('input-proto-trojan');
			if (vlessCb2) vlessCb2.checked = nud.protocols.indexOf('vless') !== -1;
			if (trojanCb2) trojanCb2.checked = nud.protocols.indexOf('trojan') !== -1;
			const nonTlsDefaultSet = { '80': true, '8080': true, '8880': true, '2052': true, '2082': true, '2086': true, '2095': true };
			const createModalDefaultPort = window.DEFAULT_PORT_SETTING || '2083';
			document.querySelectorAll('input[name="ports"]').forEach(function(cb) {
				if (nonTlsDefaultSet[cb.value]) { cb.checked = false; return; } // هیچ پورت Non-TLS (شامل 80) دیگه به‌صورت پیش‌فرض تیک نمی‌خوره
				cb.checked = (cb.value === createModalDefaultPort);
			});
			const fpSelect = document.getElementById('fingerprint-select');
			if (fpSelect) {
				fpSelect.value = nud.fingerprint;
				if (fpSelect.value !== nud.fingerprint) fpSelect.value = 'ios';
			}
			const fragOn = nud.frag_len !== '' || nud.frag_int !== '';
			const fragToggle = document.getElementById('input-frag-toggle');
			if (fragToggle) fragToggle.checked = fragOn;
			const fragLenInput = document.getElementById('input-frag-len');
			const fragIntInput = document.getElementById('input-frag-int');
			if (fragOn && fragLenInput && nud.frag_len !== '') fragLenInput.value = nud.frag_len;
			if (fragOn && fragIntInput && nud.frag_int !== '') fragIntInput.value = nud.frag_int;
			if (typeof window.toggleFragInputs === 'function') window.toggleFragInputs(fragOn);
			const edToggle = document.getElementById('input-early-data-toggle');
			if (edToggle) edToggle.checked = nud.early_data_enabled;
			const edSizeInput = document.getElementById('input-early-data-size');
			if (edSizeInput) edSizeInput.value = String(nud.early_data_size);
			if (typeof window.toggleEarlyDataInputs === 'function') window.toggleEarlyDataInputs(nud.early_data_enabled);
			const autoResetOn = nud.auto_reset_vol_days > 0 || nud.auto_reset_req_days > 0;
			const autoResetToggle = document.getElementById('input-auto-reset-toggle');
			if (autoResetToggle) autoResetToggle.checked = autoResetOn;
			document.getElementById('input-auto-reset-vol').value = nud.auto_reset_vol_days > 0 ? String(nud.auto_reset_vol_days) : '';
			document.getElementById('input-auto-reset-req').value = nud.auto_reset_req_days > 0 ? String(nud.auto_reset_req_days) : '';
			window.toggleAutoResetInputs(autoResetOn);
			const blockPornToggle = document.getElementById('input-block-porn');
			if (blockPornToggle) blockPornToggle.checked = nud.block_porn;
			const blockAdsToggle = document.getElementById('input-block-ads');
			if (blockAdsToggle) blockAdsToggle.checked = nud.block_ads;
			const autoRotateUserProxyCheck = document.getElementById('input-auto-rotate-user-proxy');
			if (autoRotateUserProxyCheck) autoRotateUserProxyCheck.checked = nud.auto_rotate_user_proxy;
			const startOnFirstConnectCheck = document.getElementById('input-start-on-first-connect');
			if (startOnFirstConnectCheck) startOnFirstConnectCheck.checked = nud.start_on_first_connect;
			const userProxyToggle = document.getElementById('user-proxy-mode-toggle');
			if (userProxyToggle) userProxyToggle.checked = true;
			if (typeof window.toggleUserProxyMode === 'function') window.toggleUserProxyMode(true);
			const enableDirectCheck = document.getElementById('input-enable-direct');
			if (enableDirectCheck) enableDirectCheck.checked = nud.enable_direct;
			window.proxyFieldsData = [""];
			window.activeProxyIndex = 0;
			if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
			const autoRotateIpToggle = document.getElementById('input-auto-rotate-ip-toggle');
			if (autoRotateIpToggle) autoRotateIpToggle.checked = nud.auto_rotate_ip;
			document.getElementById('hidden-rotate-time').value = '';
			document.getElementById('hidden-ip-operator').value = nud.ip_operator;
			document.getElementById('hidden-ip-count').value = String(nud.ip_count);
			const cleanIpsField = document.getElementById('input-ips');
			if (cleanIpsField) cleanIpsField.value = window.GLOBAL_CLEAN_IP || window.DEFAULT_GLOBAL_CLEAN_IP;
		};
		function openCreateModal() {
			isEditMode = false;
			editingUsername = '';
			if (typeof window.syncResetUserUi === 'function') window.syncResetUserUi(false);
			document.getElementById('modal-title').innerText = 'ایجاد کاربر جدید';
			updateSubmitBtnState('ایجاد کاربر');
			document.getElementById('input-name').disabled = false;
			document.getElementById('create-user-form').reset();
			window.applyNewUserFormDefaults();
			toggleModal(true);
		}
		
		const themeToggleBtn = document.getElementById('theme-toggle');
		themeToggleBtn.addEventListener('click', () => {
			if (document.documentElement.classList.contains('dark')) {
				document.documentElement.classList.remove('dark');
				localStorage.setItem('color-theme', 'light');
			} else {
				document.documentElement.classList.add('dark');
				localStorage.setItem('color-theme', 'dark');
			}
			if (typeof renderTrafficCardChart === 'function') renderTrafficCardChart();
		});
		
		async function handleCoreAction(actionType, token = null) {
			window.pendingCoreAction = actionType;
			const isUpdate = actionType === 'update' || actionType === 'update-github';
			const isGithubUpdate = actionType === 'update-github';
			if (!isUpdate && !await customConfirm('آیا از ری استارت پـنـل مطمئن هستید؟ کاربران شما لحظه ای قطع خواهند شد.')) return;
			if (isUpdate && !token && !isGithubUpdate) toggleUpdateModal(false);
			if (isGithubUpdate && !token && !await customConfirm('آیا مطمئن هستید؟ محتوای فایل ورکر با آخرین نسخه‌ی موجود در گیت‌هاب شما جایگزین خواهد شد.')) return;
			const btn = isUpdate ? document.getElementById(isGithubUpdate ? 'github-update-toggle' : 'update-toggle') : document.querySelector('button[title="ری استارت پـنـل"]');
			if (btn) {
				btn.disabled = true;
				if (!isUpdate || isGithubUpdate) btn.classList.add('animate-pulse');
			}
			if (isUpdate && !token && !isGithubUpdate) alert('در حال دریافت و اعمال آپدیت... لطفاً چند ثانیه صبر کنید.');
			try {
				const reqBody = token ? JSON.stringify({ cf_token: token }) : "{}";
				const apiPath = isGithubUpdate ? '/api/update-panel-github' : (isUpdate ? '/api/update-panel' : '/api/restart-core');
				const res = await fetch(apiPath, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: isUpdate ? reqBody : undefined
				});
				const data = await res.json().catch(() => ({}));
				if (res.status === 400 && data.error === "TOKEN_REQUIRED") {
					toggleTokenModal(true);
					if (btn) {
						btn.disabled = false;
						if (!isUpdate || isGithubUpdate) btn.classList.remove('animate-pulse');
					}
					return;
				}
				if (res.ok && data.success) {
					if (isUpdate) {
						const successModal = document.getElementById('update-success-modal');
						const successCard = successModal.querySelector('div');
						successModal.classList.remove('opacity-0', 'pointer-events-none');
						successModal.classList.add('opacity-100', 'pointer-events-auto');
						successCard.classList.remove('opacity-0', 'scale-95');
						successCard.classList.add('opacity-100', 'scale-100');
						setTimeout(() => {
							sessionStorage.setItem('zeus_last_update', Date.now());
							window.location.href = window.location.pathname + '?t=' + Date.now();
						}, 10000);
					} else {
						alert('پـنـل ری استارت شد صفحه رفرش می شود.');
						window.location.href = window.location.pathname + '?t=' + Date.now();
					}
				} else {
					if (isUpdate) {
						// خطای آپدیت باید آن‌قدر روی صفحه بماند که بشود دلیلش را خواند (توست پیش‌فرض ۳ ثانیه‌ای زود ناپدید می‌شد)
						showToast('خطا در بروزرسانی: ' + (data.error || ('کد وضعیت ' + res.status)) + ' — اگر مشکل ادامه داشت با استفاده از " ربات" اقدام کنید.', 'error', 20000);
					} else {
						alert('خطا در ری‌استارت پـنـل: ' + (data.error || 'ناشناخته'));
					}
					if (btn) {
						btn.disabled = false;
						if (!isUpdate || isGithubUpdate) btn.classList.remove('animate-pulse');
					}
				}
			} catch (err) {
				alert(isUpdate ? 'خطا در ارتباط با سرور. لطفاً از گزینه آپدیت دستی استفاده کنید.' : 'خطا در ارتباط با سرور.');
				if (btn) {
					btn.disabled = false;
					if (!isUpdate || isGithubUpdate) btn.classList.remove('animate-pulse');
				}
			}
		}
		async function applyGithubUpdate() {
			await handleCoreAction('update-github');
		}
		// وقتی یکی از اعداد مصرف کارت‌های بالا در حال بروزرسانی زنده (Live) قرار است تغییر کند،
		// یک لحظه قبل از تغییر مقدار، یک نبض کوتاه (شبیه نبض نشانگر Live) روی همون عدد نمایش داده می‌شود.
		// اگر مقدار جدید با مقدار فعلی یکسان باشد، هیچ نبضی رخ نمی‌دهد.
		function setStatWithLivePulse(elId, newText) {
			const el = document.getElementById(elId);
			if (!el) return;
			newText = String(newText);
			if (el.innerText !== newText) {
				el.classList.remove('live-value-pulse');
				void el.offsetWidth; // ریست انیمیشن برای اجرای دوباره
				el.classList.add('live-value-pulse');
				el.innerText = newText;
				setTimeout(() => el.classList.remove('live-value-pulse'), 550);
			} else {
				el.innerText = newText;
			}
		}
		async function loadUsers(silent = false) {
			if (window.isDraggingRow) return; 
			const loadingState = document.getElementById('loading-state');
			const tableContainer = document.getElementById('users-table-container');
			const emptyState = document.getElementById('empty-state');
			if (!silent) {
				loadingState.classList.remove('hidden');
				tableContainer.classList.add('hidden');
				emptyState.classList.add('hidden');
			}
			try {
				const res = await fetch('/api/users?t=' + Date.now());
				if (!res.ok) throw new Error();
				const data = await res.json();
				renderUsersUI(data);
			} catch (err) {
				if (!silent) {
					loadingState.innerHTML = '<span class="text-red-500">خطا در دریافت اطلاعات از سرور</span>';
				}
			}
		}
		function renderUsersUI(data) {
			try {
				if (data.error) {
					let errorText = data.error;
					if (errorText.toLowerCase().includes('d1') && (errorText.toLowerCase().includes('limit') || errorText.toLowerCase().includes('exceeded'))) {
						errorText = 'سهمیه دیتابیس شما تمام شده و ساعت 3:30 درست میشه';
					}
					document.getElementById('loading-state').innerHTML = '<span class="text-red-500 font-bold px-4 py-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg inline-block">❌ ' + errorText + '</span>';
					document.getElementById('loading-state').classList.remove('hidden');
					document.getElementById('users-table-container').classList.add('hidden');
					document.getElementById('empty-state').classList.add('hidden');
					return;
				}
				const users = data.users || [];
				window.allUsers = users;
				// وقتی تعداد کل کاربران کمتر از ۴ باشه، نوار ابزار (انتخاب همه/انتخاب/جابجایی/جستجو/فیلتر/sort)
				// اصلاً نمایش داده نمی‌شه تا کارت‌ها بالاتر بیان؛ فقط دکمه‌ی + به‌تنهایی و جمع‌وجور نشون داده می‌شه.
				const usersToolbar = document.getElementById('users-toolbar');
				const addUserOnlyBar = document.getElementById('add-user-only-bar');
				if (users.length < 4) {
					if (usersToolbar) usersToolbar.classList.add('hidden');
					if (addUserOnlyBar) addUserOnlyBar.classList.remove('hidden');
				} else {
					if (usersToolbar) usersToolbar.classList.remove('hidden');
					if (addUserOnlyBar) addUserOnlyBar.classList.add('hidden');
				}
				const serverTime = data.serverTime || Date.now();
				window.lastServerTime = serverTime;
				const formatGbShort = (gb) => gb < 1 ? (gb * 1024).toFixed(0) + ' MB' : gb.toFixed(2) + ' GB';
				setStatWithLivePulse('stat-usage-daily', formatGbShort(data.trafficDaily || 0));
				setStatWithLivePulse('stat-usage-7d', formatGbShort(data.traffic7d || 0));
				setStatWithLivePulse('stat-usage-30d', formatGbShort(data.traffic30d || 0));
				const d1Reads = data.d1Reads || 0;
				const d1Writes = data.d1Writes || 0;
				setStatWithLivePulse('stat-d1-writes', d1Writes >= 1000 ? (d1Writes / 1000).toFixed(1) + 'k' : d1Writes);
				setStatWithLivePulse('stat-d1-reads', d1Reads >= 1000000 ? (d1Reads / 1000000).toFixed(2) + 'M' : (d1Reads >= 1000 ? (d1Reads / 1000).toFixed(1) + 'k' : d1Reads));
				const d1ProgressPercent = Math.min((d1Writes / 100000) * 100, 100);
				document.getElementById('stat-d1-progress').style.width = d1ProgressPercent + '%';
				const cfRequests = data.cfRequestsToday || 0;
				const reqCard = document.getElementById('card-cf-requests');
				const warningBtn = document.getElementById('cf-warning-btn');
				if (cfRequests >= 90000) {
					if (reqCard) {
						reqCard.className = "neon-orbit neon-orbit-1 bg-red-50 dark:bg-red-950/20 border border-red-500 rounded-md p-2.5 flex flex-col justify-center gap-1 hover:shadow-md transition duration-300 relative overflow-hidden group min-h-[64px] animate-pulse cursor-pointer";
					}
					if (warningBtn) {
						warningBtn.classList.remove('hidden');
					}
					if (!window.hasShownUsageWarning) {
						openUsageWarning();
						window.hasShownUsageWarning = true;
					}
				} else {
					if (reqCard) {
						reqCard.className = "neon-orbit neon-orbit-1 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md p-2.5 shadow-sm flex flex-col justify-center gap-1 hover:shadow-md hover:border-orange-400 dark:hover:border-orange-500/50 transition duration-300 relative overflow-hidden group min-h-[64px] cursor-pointer";
					}
					if (warningBtn) {
						warningBtn.classList.add('hidden');
					}
				}
				const formatReqShort = (n) => n >= 1000000 ? (n / 1000000).toFixed(2) + 'M' : (n >= 1000 ? (n / 1000).toFixed(1) + 'k' : n);
				setStatWithLivePulse('stat-cf-requests', cfRequests >= 1000 ? (cfRequests / 1000).toFixed(1) + 'k' : cfRequests);
				setStatWithLivePulse('stat-cf-requests-7d', formatReqShort(data.cfRequests7d || 0));
				setStatWithLivePulse('stat-cf-requests-30d', formatReqShort(data.cfRequests30d || 0));
				const progressPercent = Math.min((cfRequests / 100000) * 100, 100);
				const cfRing = document.getElementById('stat-cf-progress');
				if (cfRing) {
					const cfCirc = 2 * Math.PI * 16;
					const progressPercentReach = Math.min(progressPercent + 4, 100);
					const cfHue = 120 - (progressPercent * 1.2);
					const cfColor = 'hsl(' + cfHue + ', 80%, 45%)';
					cfRing.style.stroke = cfColor;
					cfRing.style.color = cfColor;
					cfRing.style.setProperty('--cf-offset', cfCirc - (cfCirc * progressPercent / 100));
					cfRing.style.setProperty('--cf-offset-reach', cfCirc - (cfCirc * progressPercentReach / 100));
				}
				document.getElementById('stat-cf-progress-pct').innerText = progressPercent.toFixed(0) + '٪';
				filterAndRenderUsers();
			} catch (err) {
				document.getElementById('loading-state').innerHTML = '<span class="text-red-500">خطا در پردازش اطلاعات کاربران</span>';
			}
		}
		function filterAndRenderUsers() {
			if (!window.allUsers) return;
			const searchQuery = (document.getElementById('search-input').value || '').toLowerCase().trim();
			const filterStatus = document.getElementById('filter-status').value;
			const sortVal = document.getElementById('sort-users').value;
			const serverTime = window.lastServerTime || Date.now();
			let filtered = [...window.allUsers];
			if (searchQuery) {
				filtered = filtered.filter(u => 
					(u.username || '').toLowerCase().includes(searchQuery) || 
					(u.uuid || '').toLowerCase().includes(searchQuery)
				);
			}
			if (filterStatus !== 'all') {
				filtered = filtered.filter(u => {
					const isOnline = u.is_online === 1;
					const isActive = u.is_active === 1;
					let isExpired = false;
					if (u.limit_gb && u.used_gb >= u.limit_gb) isExpired = true;
					if (u.expiry_days) {
						if (u.start_on_first_connect === 1) {
							if (u.first_connection_time) {
								const expiryDate = new Date(u.first_connection_time + (u.expiry_days * 24 * 60 * 60 * 1000));
								if (new Date(serverTime) > expiryDate) isExpired = true;
							}
						} else if (u.created_at) {
							const created = new Date(u.created_at);
							const expiryDate = new Date(created.getTime() + (u.expiry_days * 24 * 60 * 60 * 1000));
							if (new Date(serverTime) > expiryDate) isExpired = true;
						}
					}
					if (filterStatus === 'active') return isActive && !isExpired;
					if (filterStatus === 'inactive') return !isActive;
					if (filterStatus === 'online') return isOnline;
					if (filterStatus === 'offline') return !isOnline;
					if (filterStatus === 'expired') return isExpired || !isActive;
					return true;
				});
			}
			const customOrderStr = localStorage.getItem('zeus_users_custom_order');
			let customOrder = [];
			try { customOrder = JSON.parse(customOrderStr || '[]'); } catch(e) {}
			filtered.sort((a, b) => {
				if (sortVal === 'newest' && customOrder.length > 0) {
					const indexA = customOrder.indexOf(a.username);
					const indexB = customOrder.indexOf(b.username);
					if (indexA !== -1 && indexB !== -1) return indexA - indexB;
					if (indexA !== -1) return -1;
					if (indexB !== -1) return 1;
				}
				if (sortVal === 'newest') {
					return b.id - a.id;
				}
				if (sortVal === 'name') {
					return (a.username || '').localeCompare(b.username || '');
				}
				if (sortVal === 'usage-desc') {
					return (b.used_gb || 0) - (a.used_gb || 0);
				}
				if (sortVal === 'usage-asc') {
					return (a.used_gb || 0) - (b.used_gb || 0);
				}
				if (sortVal === 'expiry-asc') {
					const getRemaining = (u) => {
						if (!u.expiry_days) return Infinity;
						if (u.start_on_first_connect === 1) {
							if (!u.first_connection_time) return u.expiry_days * 86400000;
							const expiryDate = new Date(u.first_connection_time + (u.expiry_days * 86400000));
							return expiryDate - new Date(serverTime);
						}
						if (!u.created_at) return Infinity;
						const created = new Date(u.created_at);
						const expiryDate = new Date(created.getTime() + (u.expiry_days * 86400000));
						return expiryDate - new Date(serverTime);
					};
					return getRemaining(a) - getRemaining(b);
				}
				return 0;
			});
			renderFilteredUsers(filtered, serverTime);
		}
		function renderGlobalLocationBadges() {
			const container = document.getElementById('global-location-badges');
			if (!container) return;
			// یک لیست خالی (ادمین عمداً همه را برداشته) خالی می‌ماند و به پیش‌فرض برنمی‌گردد.
			const list = Array.isArray(window.PINNED_LOCATIONS_CACHE)
				? window.PINNED_LOCATIONS_CACHE
				: (window.PINNED_LOCATIONS_DEFAULT_FALLBACK || []);
			if (!list || list.length === 0) {
				container.classList.add('hidden');
				container.innerHTML = '';
				return;
			}
			// موج مکزیکی: هر پرچم از چپ به راست به‌ترتیب کمی بزرگ می‌شود و برمی‌گردد، بعد نوبت پرچم بعدی.
			// مدت کل چرخه به تعداد پرچم‌ها بستگی دارد (list.length) تا با هر تعداد پرچمی درست کار کند.
			const flagStaggerMs = 130;
			const flagBumpMs = 450;
			const flagPauseMs = 700;
			const flagCycleMs = list.length * flagStaggerMs + flagBumpMs + flagPauseMs;
			const flagPeakPercent = ((flagBumpMs * 0.45) / flagCycleMs) * 100;
			const flagEndBumpPercent = (flagBumpMs / flagCycleMs) * 100;
			let flagWaveStyleTag = document.getElementById('flag-wave-style');
			if (!flagWaveStyleTag) {
				flagWaveStyleTag = document.createElement('style');
				flagWaveStyleTag.id = 'flag-wave-style';
				document.head.appendChild(flagWaveStyleTag);
			}
			flagWaveStyleTag.textContent =
				'@keyframes flagWave { 0% { transform: scale(1); } ' +
				flagPeakPercent.toFixed(2) + '% { transform: scale(1.4); } ' +
				flagEndBumpPercent.toFixed(2) + '% { transform: scale(1); } ' +
				'100% { transform: scale(1); } }';
			const flagsHtmlArray = list.map(function(cc, idx) {
				const flag = typeof getFlagEmojiText === 'function' ? getFlagEmojiText(cc) : '🌐';
				const flagDelay = (idx * flagStaggerMs / 1000).toFixed(2);
				const flagDuration = (flagCycleMs / 1000).toFixed(2);
				return '<span title="' + cc + '" class="text-[19.2px] leading-none drop-shadow-[0_0_2px_rgba(0,0,0,0.3)] dark:drop-shadow-[0_0_2px_rgba(255,255,255,0.3)] flex items-center justify-center" style="animation: flagWave ' + flagDuration + 's ease-in-out infinite; animation-delay: ' + flagDelay + 's; will-change: transform;">' + flag + '</span>';
			});
			container.innerHTML = '<div class="flex flex-wrap justify-center gap-1.5" dir="ltr">' + flagsHtmlArray.join('') + '</div>';
			container.classList.remove('hidden');
		}
		function renderFilteredUsers(users, serverTime) {
			const loadingState = document.getElementById('loading-state');
			const tableContainer = document.getElementById('users-table-container');
			const emptyState = document.getElementById('empty-state');
			const tbody = document.getElementById('users-tbody');
			if (users.length === 0) {
					loadingState.classList.add('hidden');
					emptyState.classList.remove('hidden');
					tableContainer.classList.add('hidden');
					
					emptyState.querySelector('p').className = 'text-red-600 dark:text-red-400 font-bold text-lg flex items-center justify-center flex-wrap gap-2 leading-loose';
					
					if (window.allUsers && window.allUsers.length > 0) {
						emptyState.querySelector('p').innerHTML = 'کاربری با مشخصات جستجو شده یافت نشد.';
					} else {
						emptyState.querySelector('p').innerHTML = '<span>کاربری وجود ندارد. برای ساخت کاربر روی</span>' +
							'<span class="inline-flex items-center justify-center p-1.5 rounded-full bg-green-50 dark:bg-green-950/30 border border-green-600 dark:border-green-700/60 text-green-700 dark:text-green-400 shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"></path></svg></span>' +
							'<span>کلیک کنید یا از دکمه‌های</span>' +
							'<span class="inline-flex items-center justify-center p-1.5 rounded-full bg-orange-50 dark:bg-orange-950/40 border border-orange-500 text-orange-600 dark:text-orange-400 shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"></path><path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"></path><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"></path><path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"></path></svg></span>' +
							'<span>و</span>' +
							'<span class="inline-flex items-center justify-center p-1.5 rounded-full bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-500 text-indigo-600 dark:text-indigo-400 shadow-sm"><svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></span>' +
							'<span>برای ایجاد سریع استفاده کنید.</span>';
					}
			} else {
				loadingState.classList.add('hidden');
				emptyState.classList.add('hidden');
				tableContainer.classList.remove('hidden');
				tbody.innerHTML = users.map(user => {
					let daysRemaining = 'نامحدود';
					let daysPercent = 100;
					let isTimerPending = false;
					if (user.expiry_days) {
						if (user.start_on_first_connect === 1) {
							if (!user.first_connection_time) {
								daysRemaining = user.expiry_days;
								daysPercent = 100;
								isTimerPending = true;
							} else {
								const expiryDate = new Date(user.first_connection_time + (user.expiry_days * 24 * 60 * 60 * 1000));
								const diffDays = Math.ceil((expiryDate - new Date(serverTime)) / (1000 * 60 * 60 * 24));
								daysRemaining = diffDays > 0 ? diffDays : 0;
								daysPercent = Math.max(0, Math.min(100, (daysRemaining / user.expiry_days) * 100));
							}
						} else if (user.created_at) {
							const created = new Date(user.created_at);
							const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
							const diffDays = Math.ceil((expiryDate - new Date(serverTime)) / (1000 * 60 * 60 * 24));
							daysRemaining = diffDays > 0 ? diffDays : 0;
							daysPercent = Math.max(0, Math.min(100, (daysRemaining / user.expiry_days) * 100));
						} else {
							daysRemaining = user.expiry_days;
						}
					}
					const usedGb = user.used_gb || 0;
					const formattedUsed = usedGb < 1 ? (usedGb * 1024).toFixed(0) + ' MB' : usedGb.toFixed(2) + ' GB';
					const usedReq = user.used_req || 0;
					// وضعیت «منقضی‌شدن» کاربر (حجم/ریکوئست تمام‌شده یا تاریخ گذشته) - عیناً همون
					// منطقی که در filterAndRenderUsers برای فیلتر «expired» استفاده می‌شه، اینجا هم
					// برای تعیین رنگ آواتار (خاکستری) به‌کار می‌ره.
					let isUserExpired = false;
					if (user.limit_gb && usedGb >= user.limit_gb) isUserExpired = true;
					if (user.limit_req && usedReq >= user.limit_req) isUserExpired = true;
					if (user.expiry_days) {
						if (user.start_on_first_connect === 1) {
							if (user.first_connection_time) {
								const ucExpiryCheckDate = new Date(user.first_connection_time + (user.expiry_days * 24 * 60 * 60 * 1000));
								if (new Date(serverTime) > ucExpiryCheckDate) isUserExpired = true;
							}
						} else if (user.created_at) {
							const ucCreatedCheck = new Date(user.created_at);
							const ucExpiryCheckDate = new Date(ucCreatedCheck.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
							if (new Date(serverTime) > ucExpiryCheckDate) isUserExpired = true;
						}
					}
					// وقتی کاربر هیچ مصرفی نداشته (حجم/ریکوئست صفر)، progress و عدد مصرف
					// invisible می‌شن (نه حذف کامل - جاشون در گرید حفظ می‌مونه) و به محض
					// شروع مصرف دوباره نمایش داده می‌شن. (این کارت‌ها در لیست اصلی کاربران
					// هستند - همون منطقی که در مودال جزئیات کاربر پیاده شده، اینجا هم اعمال شد)
					const volInvisibleClass = usedGb > 0 ? '' : ' invisible';
					const reqInvisibleClass = usedReq > 0 ? '' : ' invisible';
					// وقتی کاربر هیچ مصرفی (نه حجم و نه ریکوئست) نداشته، ردیف دکمه‌های اکشن دیگر invisible
					// نمی‌شوند (چون باید همچنان قابل کلیک باشند)؛ فقط رنگی بودنشان گرفته می‌شود (grayscale)
					// و به محض شروع مصرف، رنگی بودن دوباره برمی‌گردد.
					const actionsColorlessClass = (usedGb > 0 || usedReq > 0) ? '' : ' grayscale';
					let reqHtml = '';
					if (user.limit_req) {
						const reqPercent = Math.min((usedReq / user.limit_req) * 100, 100);
						const reqHue = 120 - (reqPercent * 1.2);
						reqHtml = '<div class="flex flex-col gap-[5.6px] w-full min-w-[77px] max-w-[112px] mx-auto select-none">' +
							'<div class="flex items-baseline justify-center gap-1' + reqInvisibleClass + '" dir="ltr">' +
								'<span class="text-[12.6px] text-gray-800 dark:text-zinc-200 font-bold leading-none">' + usedReq.toLocaleString() + '</span>' +
								'<span class="text-[8.5px] text-gray-400 dark:text-zinc-500 font-semibold leading-none">/' + user.limit_req.toLocaleString() + '</span>' +
								'<span class="text-[7.5px] text-gray-400 dark:text-zinc-500 font-semibold leading-none opacity-60">Req</span>' +
							'</div>' +
							'<div class="w-full h-[8.4px] bg-gray-200 dark:bg-zinc-700 rounded-full overflow-hidden' + reqInvisibleClass + '">' +
								'<div class="h-full rounded-full transition-all duration-500" style="width: ' + reqPercent + '%; background-color: hsl(' + reqHue + ', 80%, 45%)"></div>' +
							'</div>' +
						'</div>';
					} else {
						// بدون محدودیت: به‌جای نوار پیشرفتِ ساکن و بی‌معنی (که نه پر می‌شد نه خالی)،
						// فقط عدد مصرف به‌همراه یک نشانه‌ی کوچیک «∞ بدون محدودیت» نشون داده می‌شه.
						reqHtml = '<div class="flex flex-col items-center gap-1 w-full min-w-[77px] max-w-[112px] mx-auto select-none">' +
							'<div class="flex items-baseline justify-center gap-1' + reqInvisibleClass + '" dir="ltr">' +
								'<span class="text-[12.6px] text-gray-800 dark:text-zinc-200 font-bold leading-none">' + usedReq.toLocaleString() + '</span>' +
								'<span class="text-[10px] text-gray-800 dark:text-zinc-200 font-bold leading-none opacity-60">Req</span>' +
							'</div>' +
							'<span class="text-[8.5px] font-bold text-blue-500/80 dark:text-blue-400/80 tracking-wide leading-none' + reqInvisibleClass + '">∞ بدون محدودیت</span>' +
						'</div>';
					}
					let volumeHtml = '';
					if (user.limit_gb) {
						const limitPercent = Math.min((usedGb / user.limit_gb) * 100, 100);
						const limitHue = 120 - (limitPercent * 1.2);
						const usedValueClean = usedGb < 1 ? (usedGb * 1024).toFixed(0) : usedGb.toFixed(2);
						const usedUnitClean = usedGb < 1 ? 'MB' : 'GB';
						volumeHtml = '<div class="flex flex-col gap-[5.6px] w-full min-w-[77px] max-w-[112px] mx-auto select-none">' +
							'<div class="flex items-baseline justify-center gap-1' + volInvisibleClass + '" dir="ltr">' +
								'<span class="text-[12.6px] text-gray-800 dark:text-zinc-200 font-bold leading-none">' + usedValueClean + '</span>' +
								'<span class="text-[10px] text-gray-800 dark:text-zinc-200 font-bold leading-none opacity-60">' + usedUnitClean + '</span>' +
								'<span class="text-[8.5px] text-gray-400 dark:text-zinc-500 font-semibold leading-none">/' + user.limit_gb + 'GB</span>' +
							'</div>' +
							'<div class="w-full h-[8.4px] bg-gray-200 dark:bg-zinc-700 rounded-full overflow-hidden' + volInvisibleClass + '">' +
								'<div class="h-full rounded-full transition-all duration-500" style="width: ' + limitPercent + '%; background-color: hsl(' + limitHue + ', 80%, 45%)"></div>' +
							'</div>' +
						'</div>';
					} else {
						const usedValueClean = usedGb < 1 ? (usedGb * 1024).toFixed(0) : usedGb.toFixed(2);
						const usedUnitClean = usedGb < 1 ? 'MB' : 'GB';
						// همون منطق «بدون محدودیت» که برای ریکوئست پیاده شد، اینجا هم برای حجم اعمال می‌شه.
						volumeHtml = '<div class="flex flex-col items-center gap-1 w-full min-w-[77px] max-w-[112px] mx-auto select-none">' +
							'<div class="flex items-baseline justify-center gap-1' + volInvisibleClass + '" dir="ltr">' +
								'<span class="text-[12.6px] text-gray-800 dark:text-zinc-200 font-bold leading-none">' + usedValueClean + '</span>' +
								'<span class="text-[10px] text-gray-800 dark:text-zinc-200 font-bold leading-none opacity-60">' + usedUnitClean + '</span>' +
							'</div>' +
							'<span class="text-[8.5px] font-bold text-blue-500/80 dark:text-blue-400/80 tracking-wide leading-none' + volInvisibleClass + '">∞ بدون محدودیت</span>' +
						'</div>';
					}
					const onlineCount = user.online_count || 0;
					const statusBtnColor = user.is_active === 0 ? 'text-green-700 dark:text-green-500 hover:bg-green-50 dark:hover:bg-green-900/30' : 'text-amber-600 dark:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-900/30';
					const statusBtnTitle = user.is_active === 0 ? 'فعال کردن کاربر' : 'قطع کردن کاربر';
					const statusBtnIcon = user.is_active === 0 
						? '<svg class="w-[16.8px] h-[16.8px]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>'
						: '<svg class="w-[16.8px] h-[16.8px]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>';
					const isChecked = (window.selectedUsernames && window.selectedUsernames.has(user.username)) ? 'checked' : '';
					const onlineBadgeColor = onlineCount >= 3 ? 'bg-red-600' : (onlineCount === 2 ? 'bg-yellow-500' : 'bg-green-600');
					const onlineBadge = user.is_online === 1
						? '<span class="min-w-[28px] h-[28px] px-[5.6px] relative inline-flex items-center justify-center text-center leading-none text-[21px] font-bold ' + onlineBadgeColor + ' text-white rounded-full animate-pulse" style="line-height:1"><span style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);display:inline-block;">' + user.online_count + '</span></span>'
						: '';
					// «هشدار تعداد دستگاه»: user.device_warning از GET /api/users میاد (تا ۲۴ ساعت
					// بعد از آخرین باری که تعداد دستگاه فعال از آستانه‌ی سراسری هشدار
					// (device_warning_threshold) بیشتر شده - نگاه کنید به persistActiveIp). فقط یک
					// هشدار بصریه، هیچ اتصالی رو قطع نمی‌کنه.
					const deviceWarningLimitText = (window.DEVICE_WARNING_THRESHOLD !== undefined && window.DEVICE_WARNING_THRESHOLD !== null) ? window.DEVICE_WARNING_THRESHOLD : window.DEFAULT_DEVICE_WARNING_THRESHOLD;
					// «بیشترین تعداد دستگاه»: user.device_warning_peak_count از GET /api/users میاد
					// (ستون خام، persistActiveIp پرش می‌کنه - نگاه کنید بالاتر). کنار خودِ آیکون
					// هشدار نشون داده می‌شه، سمت چپش (آیکون اول توی سورس میاد، عدد بعدش - چون
					// صفحه dir="rtl" هست، فرزند بعدی در فلکس row سمت چپِ فرزند قبلی می‌شینه).
					const deviceWarningPeakCount = user.device_warning_peak_count || null;
					const deviceWarningBadge = user.device_warning
						? '<span class="inline-flex items-center gap-[2.8px] shrink-0">' +
							'<span title="تعداد دستگاه‌های متصل این کاربر بیش از آستانه‌ی هشدار (' + deviceWarningLimitText + ' دستگاه) بوده است' + (deviceWarningPeakCount ? ' - بیشترین تعداد همزمان: ' + deviceWarningPeakCount + ' دستگاه' : '') + '" class="inline-flex items-center justify-center w-[22.4px] h-[22.4px] text-red-500 animate-pulse shrink-0">' +
								'<svg class="w-[19.6px] h-[19.6px]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>' +
							  '</span>' +
							(deviceWarningPeakCount ? '<span class="text-[14px] font-bold text-red-500 leading-none">' + deviceWarningPeakCount + '</span>' : '') +
						  '</span>'
						: '';
					const ucAvatarLetter = (user.username || '?').charAt(0).toUpperCase();
					const ucAvatarColorInfo = ucAvatarStatusColor(user.is_active, isUserExpired, user.is_online === 1, onlineCount);
					const ucAvatarBg = ucAvatarColorInfo.bg;
					const ucAvatarAlarmClass = ucAvatarColorInfo.alarm ? ' uc-avatar-alarm' : '';
					let ucDaysChip = '';
					if (daysRemaining === 'نامحدود') {
						ucDaysChip = '<span class="uc-chip uc-chip-infinite" style="background:rgba(37,99,235,0.12)">∞ نامحدود</span>';
					} else if (isTimerPending) {
						ucDaysChip = '<span class="uc-chip" style="color:#2563eb;background:rgba(37,99,235,0.12)">⏳ شروع نشده</span>';
					} else {
						const ucDaysHue = daysPercent * 1.2;
						ucDaysChip = '<span class="uc-chip" style="color:hsl(' + ucDaysHue + ',75%,40%);background:hsla(' + ucDaysHue + ',75%,50%,0.15)">' + daysRemaining + ' روز</span>';
					}
					const ucOnlineChip = user.is_online === 1
						? '<span class="uc-chip" style="color:' + (onlineCount >= 3 ? '#dc2626' : onlineCount === 2 ? '#ca8a04' : '#16a34a') + ';background:' + (onlineCount >= 3 ? 'rgba(220,38,38,0.12)' : onlineCount === 2 ? 'rgba(202,138,4,0.14)' : 'rgba(22,163,74,0.12)') + '"><svg class="w-[11px] h-[11px] shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="7" y="2" width="10" height="20" rx="2.4"></rect><path stroke-linecap="round" d="M11 18h2"></path></svg>' + onlineCount + ' دستگاه</span>'
						: '';
					const ucStatusStyle = user.is_active === 0 ? 'color:#16a34a;background:rgba(22,163,74,0.12)' : 'color:#d97706;background:rgba(217,119,6,0.12)';
					return '<div class="uc-card" data-username="' + user.username + '">' +
							'<div class="uc-top">' +
								'<input type="checkbox" name="select-user" value="' + encodeURIComponent(user.username) + '" onchange="onUserSelectChange(this)" ' + isChecked + ' class="uc-checkbox" style="filter: none !important; accent-color: #16a34a !important;">' +
								'<span class="drag-handle uc-drag" title="جابجایی">☰</span>' +
								'<div class="uc-avatar' + ucAvatarAlarmClass + '" style="background:' + ucAvatarBg + '">' + ucAvatarLetter + (user.is_online === 1 ? '<span class="uc-online-dot ' + onlineBadgeColor + '"></span>' : '') + '</div>' +
								'<div class="uc-identity">' +
									'<span class="uc-username" title="' + user.username + '">' + user.username + '</span>' +
									'<div class="uc-subline">' + ucDaysChip + ucOnlineChip + deviceWarningBadge + '</div>' +
								'</div>' +
								'<button type="button" data-user="' + encodeURIComponent(user.username) + '" onclick="toggleCardActions(this)" title="عملیات کاربر" class="uc-more-btn' + actionsColorlessClass + '">' +
									'<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="2"></circle><circle cx="12" cy="12" r="2"></circle><circle cx="12" cy="19" r="2"></circle></svg>' +
								'</button>' +
							'</div>' +
							'<div class="uc-stats">' + volumeHtml + reqHtml + '</div>' +
							'<div class="uc-actions-overlay">' +
								'<div class="uc-actions-inner">' +
									'<div class="uc-actions-header"><button type="button" onclick="toggleCardActions(this)" class="uc-action-close" title="بستن">✕</button></div>' +
									'<div class="uc-actions-grid">' +
										'<button data-user="' + encodeURIComponent(user.username) + '" onclick="openStatusLink(this.dataset.user)" title="وضعیت اتصال" class="uc-action-btn" style="background:rgba(22,163,74,0.12);color:#16a34a"><svg width="17" height="17" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg></button>' +
										'<button data-user="' + encodeURIComponent(user.username) + '" onclick="copySubLink(this.dataset.user)" title="ساب متنی" class="uc-action-btn" style="background:rgba(79,70,229,0.12);color:#4f46e5"><svg width="17" height="17" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg></button>' +
										'<button data-user="' + encodeURIComponent(user.username) + '" onclick="copyConfig(this.dataset.user)" title="کپی کـانفـیگ" class="uc-action-btn" style="background:rgba(37,99,235,0.12);color:#2563eb"><svg width="17" height="17" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg></button>' +
										'<button data-user="' + encodeURIComponent(user.username) + '" onclick="showSubQr(this.dataset.user)" title="QR ساب متنی" class="uc-action-btn" style="background:rgba(217,119,6,0.12);color:#d97706"><svg width="17" height="17" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm14 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 19h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"></path></svg></button>' +
										'<button data-user="' + encodeURIComponent(user.username) + '" onclick="editUser(this.dataset.user)" title="ویرایش" class="uc-action-btn" style="background:rgba(5,150,105,0.12);color:#059669"><svg width="17" height="17" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"></path></svg></button>' +
										'<button data-user="' + encodeURIComponent(user.username) + '" onclick="toggleUserStatus(this.dataset.user)" title="' + statusBtnTitle + '" class="uc-action-btn" style="' + ucStatusStyle + '">' + statusBtnIcon + '</button>' +
										'<button data-user="' + encodeURIComponent(user.username) + '" onclick="deleteUser(this.dataset.user)" title="حذف" class="uc-action-btn" style="background:rgba(220,38,38,0.12);color:#dc2626"><svg width="17" height="17" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>' +
									'</div>' +
								'</div>' +
							'</div>' +
						'</div>';
				}).join('');
				updateBulkActionsBar();
				if (typeof renderGlobalLocationBadges === 'function') {
					renderGlobalLocationBadges();
				}
				if (window.usersSortable) {
					window.usersSortable.destroy();
				}
				window.usersSortable = new Sortable(document.getElementById('users-tbody'), {
					handle: '.drag-handle',
					animation: 250,
					ghostClass: "opacity-30",
					delay: 200,
					delayOnTouchOnly: true,
					touchStartThreshold: 5,
					onChoose: function () {
						window.isDraggingRow = true;
					},
					onUnchoose: function () {
						window.isDraggingRow = false;
					},
					onStart: function () {
						window.isDraggingRow = true;
					},
					onEnd: function (evt) {
						window.isDraggingRow = false;
						const newOrder = Array.from(evt.to.children).map(tr => tr.getAttribute('data-username')).filter(Boolean);
						localStorage.setItem('zeus_users_custom_order', JSON.stringify(newOrder));
					}
				});
			}
		}
		// رنگ آواتار کاربر دیگه رندوم/هش نیست، بلکه بر اساس وضعیت واقعی‌شه:
		//  - غیرفعال (is_active=0) یا منقضی (حجم/ریکوئست/زمان تمام‌شده): خاکستری - بالاترین اولویت
		//  - آنلاین نبودن (حالت عادی): آبی
		//  - آنلاین با ۱ دستگاه: سبز | ۲ دستگاه: زرد | ۳ دستگاه: قرمز | ۴+ دستگاه: قرمزِ چشمک‌زن (آلارم)
		function ucAvatarStatusColor(isActive, isExpired, isOnline, onlineCount) {
			if (isActive === 0 || isExpired) return { bg: '#6b7280', alarm: false };
			if (!isOnline) return { bg: '#3b82f6', alarm: false };
			const devices = onlineCount || 0;
			if (devices <= 1) return { bg: '#16a34a', alarm: false };
			if (devices === 2) return { bg: '#ca8a04', alarm: false };
			if (devices === 3) return { bg: '#dc2626', alarm: false };
			return { bg: '#dc2626', alarm: true };
		}
		function toggleCardActions(btn) {
			const card = btn.closest('.uc-card');
			if (!card) return;
			const overlay = card.querySelector('.uc-actions-overlay');
			if (!overlay) return;
			const willOpen = !overlay.classList.contains('uc-actions-open');
			document.querySelectorAll('.uc-actions-overlay.uc-actions-open').forEach(function (el) {
				if (el !== overlay) el.classList.remove('uc-actions-open');
			});
			overlay.classList.toggle('uc-actions-open', willOpen);
		}
		document.addEventListener('click', function (e) {
			if (e.target.closest('.uc-more-btn') || e.target.closest('.uc-actions-overlay')) return;
			document.querySelectorAll('.uc-actions-overlay.uc-actions-open').forEach(function (el) {
				el.classList.remove('uc-actions-open');
			});
		});
		async function toggleUserStatus(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			try {
				const response = await fetch('/api/users/' + encodeURIComponent(username), {
					method: 'PUT',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ toggle_only: true })
				});
				if (response.ok) {
					await loadUsers(true);
				} else {
					const errData = await response.json();
					alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
				}
			} catch (err) {
				alert('خطا در برقراری ارتباط با سرور');
			}
		}
		function handleProtocolChange(changedInput) {
			const vlessCb = document.getElementById('input-proto-vless');
			const trojanCb = document.getElementById('input-proto-trojan');
			if (!vlessCb?.checked && !trojanCb?.checked) {
				changedInput.checked = true;
				alert('⚠️ حداقل یکی از پروتکل‌ها (VLESS یا Trojan) باید انتخاب شده باشد!');
			}
		}
		window.deferredPwaPrompt = null;
		window.addEventListener('beforeinstallprompt', (e) => {
			e.preventDefault();
			window.deferredPwaPrompt = e;
		});
		window.addEventListener('appinstalled', () => {
			window.deferredPwaPrompt = null;
			showToast('✅ اپلیکیشن زئوس با موفقیت روی دستگاه شما نصب شد!');
		});
		function isIosDevice() {
			return /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
		}
		function isPwaStandalone() {
			return window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
		}
		function togglePwaModal(show) {
			setModalState('pwa-install-modal', show);
		}
		function getBrowserAndOsInfo() {
			const ua = navigator.userAgent;
			const isOpera = ua.includes('OPR') || ua.includes('Opera') || ua.includes('OPT/');
			const isEdge = ua.includes('Edg');
			const isChrome = ua.includes('Chrome') && !isEdge && !isOpera;
			const isFirefox = ua.includes('Firefox');
			const isSafari = ua.includes('Safari') && !isChrome && !isEdge && !isOpera;
			const isAndroid = /Android/i.test(ua);
			const isIos = isIosDevice();
			return { isOpera, isEdge, isChrome, isFirefox, isSafari, isAndroid, isIos };
		}
		function renderInstallGuide() {
			const info = getBrowserAndOsInfo();
			const list = document.getElementById('pwa-instructions-list');
			const title = document.getElementById('pwa-modal-title');
			if (!list) return;
			list.innerHTML = '';
			if (info.isIos) {
				if (title) title.innerText = 'نصب روی آیفون / iOS';
				list.innerHTML = '<div class="flex items-start gap-2.5 p-2.5 bg-blue-50/50 dark:bg-blue-950/20 rounded-lg border border-blue-200/50 dark:border-blue-900/30">' +
					'<span class="w-5 h-5 rounded-full bg-blue-500 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۱</span>' +
					'<span>در نوار پایین سافاری، دکمه <b>اشتراک‌گذاری (Share 📤)</b> را لمس کنید.</span>' +
				'</div>' +
				'<div class="flex items-start gap-2.5 p-2.5 bg-blue-50/50 dark:bg-blue-950/20 rounded-lg border border-blue-200/50 dark:border-blue-900/30">' +
					'<span class="w-5 h-5 rounded-full bg-blue-500 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۲</span>' +
					'<span>گزینه <b>«Add to Home Screen» (افزودن به صفحه اصلی ➕)</b> را انتخاب کنید.</span>' +
				'</div>' +
				'<div class="flex items-start gap-2.5 p-2.5 bg-blue-50/50 dark:bg-blue-950/20 rounded-lg border border-blue-200/50 dark:border-blue-900/30">' +
					'<span class="w-5 h-5 rounded-full bg-blue-500 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۳</span>' +
					'<span>در گوشه بالا دکمه <b>«Add» (افزودن)</b> را بزنید تا آیکون برنامه ایجاد شود.</span>' +
				'</div>';
			} else if (info.isOpera) {
				if (title) title.innerText = 'نصب در مرورگر اپرا (Opera)';
				if (info.isAndroid) {
					list.innerHTML = '<div class="flex items-start gap-2.5 p-2.5 bg-red-50/50 dark:bg-red-950/20 rounded-lg border border-red-200/50 dark:border-red-900/30">' +
						'<span class="w-5 h-5 rounded-full bg-red-500 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۱</span>' +
						'<span>در نوار پایین اپرا، روی منوی <b>سه نقطه (⋮) یا لوگوی اپرا</b> کلیک کنید.</span>' +
					'</div>' +
					'<div class="flex items-start gap-2.5 p-2.5 bg-red-50/50 dark:bg-red-950/20 rounded-lg border border-red-200/50 dark:border-red-900/30">' +
						'<span class="w-5 h-5 rounded-full bg-red-500 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۲</span>' +
						'<span>گزینه <b>«صفحه اصلی» (Home screen)</b> یا <b>«نصب برنامه»</b> را انتخاب کنید.</span>' +
					'</div>';
				} else {
					list.innerHTML = '<div class="flex items-start gap-2.5 p-2.5 bg-red-50/50 dark:bg-red-950/20 rounded-lg border border-red-200/50 dark:border-red-900/30">' +
						'<span class="w-5 h-5 rounded-full bg-red-500 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۱</span>' +
						'<span>در نوار آدرس بالای اپرا (سمت راست آدرس)، روی آیکون <b>📥 (نصب)</b> کلیک کنید.</span>' +
					'</div>' +
					'<div class="flex items-start gap-2.5 p-2.5 bg-red-50/50 dark:bg-red-950/20 rounded-lg border border-red-200/50 dark:border-red-900/30">' +
						'<span class="w-5 h-5 rounded-full bg-red-500 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۲</span>' +
						'<span>یا روی منوی تنظیمات سریع (Easy Setup) یا منوی سه نقطه کلیک کرده و گزینه <b>Install</b> را انتخاب کنید.</span>' +
					'</div>';
				}
			} else if (info.isAndroid) {
				if (title) title.innerText = 'نصب روی گوشی اندروید';
				list.innerHTML = '<div class="flex items-start gap-2.5 p-2.5 bg-green-50/50 dark:bg-green-950/20 rounded-lg border border-green-200/50 dark:border-green-900/30">' +
					'<span class="w-5 h-5 rounded-full bg-green-600 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۱</span>' +
					'<span>روی منوی <b>سه نقطه (⋮)</b> در بالای مرورگر کلیک کنید.</span>' +
				'</div>' +
				'<div class="flex items-start gap-2.5 p-2.5 bg-green-50/50 dark:bg-green-950/20 rounded-lg border border-green-200/50 dark:border-green-900/30">' +
					'<span class="w-5 h-5 rounded-full bg-green-600 text-white flex items-center justify-center font-black text-[10px] flex-shrink-0 mt-0.5">۲</span>' +
					'<span>گزینه <b>«نصب برنامه» (Install app)</b> یا <b>«افزودن به صفحه اصلی»</b> را انتخاب کنید.</span>' +
				'</div>';
			} else {
				if (title) title.innerText = 'نصب در مرورگر دسکتاپ';
				list.innerHTML = '<div class="flex items-start gap-2.5 p-2.5 bg-blue-50/50 dark:bg-blue-950/20 rounded-lg border border-blue-200/50 dark:border-blue-900/30">' +
					'<span class="w-2 h-2 rounded-full bg-blue-500 flex-shrink-0 mt-1.5"></span>' +
					'<span>در نوار آدرس بالای مرورگر، روی آیکون <b>نصب برنامه (🖥️ یا ➕)</b> کلیک کنید.</span>' +
				'</div>' +
				'<div class="flex items-start gap-2.5 p-2.5 bg-blue-50/50 dark:bg-blue-950/20 rounded-lg border border-blue-200/50 dark:border-blue-900/30">' +
					'<span class="w-2 h-2 rounded-full bg-blue-500 flex-shrink-0 mt-1.5"></span>' +
					'<span><b>یا</b> از منوی سه نقطه (⋮) گزینه <b>«Install ZEUS Panel»</b> را انتخاب نمایید.</span>' +
				'</div>';
			}
		}
		async function triggerPwaInstall() {
			if (isPwaStandalone()) {
				showToast('✅ اپلیکیشن هم‌اکنون روی دستگاه شما نصب است و در حال اجرا می‌باشد.');
				return;
			}
			if (window.deferredPwaPrompt) {
				try {
					window.deferredPwaPrompt.prompt();
					const choice = await window.deferredPwaPrompt.userChoice;
					if (choice.outcome === 'accepted') {
						showToast('✅ در حال نصب اپلیکیشن...');
					}
					window.deferredPwaPrompt = null;
					return;
				} catch (err) {}
			}
			renderInstallGuide();
			togglePwaModal(true);
		}
		window.triggerPwaInstall = triggerPwaInstall;
		window.togglePwaModal = togglePwaModal;
		if ('serviceWorker' in navigator) {
			try {
				navigator.serviceWorker.register('/sw.js').catch(() => {});
			} catch(e) {}
		}
		function generateRandomUsername() {
			const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
			let randStr = '';
			for (let i = 0; i < 8; i++) randStr += chars.charAt(Math.floor(Math.random() * chars.length));
			const username = randStr;
			const nameInput = document.getElementById('input-name');
			if (nameInput) {
				nameInput.value = username;
			}
		}
		window.generateRandomUsername = generateRandomUsername;
		function generateUuidV4() {
			if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
				return crypto.randomUUID();
			}
			const bytes = crypto.getRandomValues(new Uint8Array(16));
			bytes[6] = (bytes[6] & 0x0f) | 0x40;
			bytes[8] = (bytes[8] & 0x3f) | 0x80;
			const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0'));
			return hex[0] + hex[1] + hex[2] + hex[3] + '-' + hex[4] + hex[5] + '-' + hex[6] + hex[7] + '-' + hex[8] + hex[9] + '-' + hex[10] + hex[11] + hex[12] + hex[13] + hex[14] + hex[15];
		}
		window.generateUuidV4 = generateUuidV4;
		function generateRandomUuid() {
			const uuidInput = document.getElementById('input-uuid');
			if (uuidInput) {
				uuidInput.value = generateUuidV4();
			}
		}
		window.generateRandomUuid = generateRandomUuid;
		async function handleFormSubmit(event) {
			event.preventDefault();
			updateSubmitBtnState(isEditMode ? 'در حال ذخیره تغییرات...' : 'در حال ایجاد...', true);
			const vlessEnabled = document.getElementById('input-proto-vless')?.checked ?? true;
			const trojanEnabled = document.getElementById('input-proto-trojan')?.checked ?? false;
			if (!vlessEnabled && !trojanEnabled) {
				alert('⚠️ حداقل یکی از پروتکل‌ها (VLESS یا Trojan) باید انتخاب شود!');
				updateSubmitBtnState(isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر', false);
				return;
			}
			const selectedProtocols = [];
			if (vlessEnabled) selectedProtocols.push('vless');
			if (trojanEnabled) selectedProtocols.push('trojan');
			const connection_type = selectedProtocols.join(',');
			const username = document.getElementById('input-name').value.trim();

			if (!username) {
				if (typeof window.switchUserTab === 'function') window.switchUserTab('tab-user-info');
				alert('⚠️ وارد کردن نام کاربری الزامی است!');
				updateSubmitBtnState(isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر', false);
				return;
			}

			const usernameRegex = /^[a-zA-Z0-9_-]+$/;
			if (!usernameRegex.test(username)) {
				if (typeof window.switchUserTab === 'function') window.switchUserTab('tab-user-info');
				alert('⚠️ نام کاربری فقط می‌تواند شامل حروف انگلیسی، اعداد، خط تیره (-) و آندرلاین (_) باشد!');
				updateSubmitBtnState(isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر', false);
				return;
			}
			const uuidRawInput = document.getElementById('input-uuid');
			const uuidRaw = uuidRawInput ? uuidRawInput.value.trim() : '';
			const uuidFormatRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
			if (uuidRaw && !uuidFormatRegex.test(uuidRaw)) {
				if (typeof window.switchUserTab === 'function') window.switchUserTab('tab-user-info');
				alert('⚠️ فرمت UUID نامعتبر است! (مثال درست: 11111111-2222-3333-4444-555555555555)');
				updateSubmitBtnState(isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر', false);
				return;
			}
			const uuid = uuidRaw ? uuidRaw.toLowerCase() : null;
			const limit = document.getElementById('input-limit').value || null;
			const expiry = document.getElementById('input-expiry').value || null;
			const reqLimit = document.getElementById('input-req-limit').value || null;
			const ipLimit = document.getElementById('input-ip-limit').value || null;
			if (limit !== null && parseFloat(limit) < 0) { alert('⚠️ حجم نمی‌تواند عدد منفی باشد!'); submitButton.disabled = false; submitButton.innerText = isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر'; return; }
			if (expiry !== null && parseInt(expiry) < 0) { alert('⚠️ زمان (روز) نمی‌تواند عدد منفی باشد!'); submitButton.disabled = false; submitButton.innerText = isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر'; return; }
			if ((reqLimit !== null && parseInt(reqLimit) < 0) || (ipLimit !== null && parseInt(ipLimit) < 0)) { alert('⚠️ محدودیت‌ها نمی‌توانند منفی باشند!'); submitButton.disabled = false; submitButton.innerText = isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر'; return; }
			const autoResetToggle = document.getElementById('input-auto-reset-toggle').checked;
			const autoResetVolDays = document.getElementById('input-auto-reset-vol').value;
			const autoResetReqDays = document.getElementById('input-auto-reset-req').value;
			if (autoResetToggle) {
				const volDays = parseInt(autoResetVolDays) || 0;
				const reqDays = parseInt(autoResetReqDays) || 0;
				if (volDays <= 0 && reqDays <= 0) {
					alert('⚠️ وقتی تیک تمدید خودکار روشن است، باید حداقل یکی از فیلدها (زمان تمدید حجم یا ریکوئست) را پر کنید!');
					updateSubmitBtnState(isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر', false);
					return;
				}
			}
			const customPortsRaw = document.getElementById('input-custom-ports') ? document.getElementById('input-custom-ports').value : '';
			const customPortsArray = customPortsRaw.replace(/ +/g, ',').split(',').map(p => p.trim()).filter(p => p.length > 0);
			let checkedPorts = Array.from(document.querySelectorAll('input[name="ports"]:checked')).map(cb => cb.value).concat(customPortsArray);
			checkedPorts = [...new Set(checkedPorts)];
			const block_porn = document.getElementById('input-block-porn').checked ? 1 : 0;
			const block_ads = document.getElementById('input-block-ads').checked ? 1 : 0;
			const isFragOn = document.getElementById('input-frag-toggle') ? document.getElementById('input-frag-toggle').checked : true;
			const frag_len = isFragOn && document.getElementById('input-frag-len') ? document.getElementById('input-frag-len').value.trim() : "";
			const frag_int = isFragOn && document.getElementById('input-frag-int') ? document.getElementById('input-frag-int').value.trim() : "";
			const isAdvancedSettingsOn = document.getElementById('input-advanced-settings-toggle') ? document.getElementById('input-advanced-settings-toggle').checked : false;
			const advanced_frag = (isAdvancedSettingsOn && document.getElementById('input-advanced-frag')) ? document.getElementById('input-advanced-frag').value.trim() : "";
			const cipher_suites = (isAdvancedSettingsOn && document.getElementById('input-cipher-suites')) ? document.getElementById('input-cipher-suites').value.trim() : "";
			const tls_mask = (isAdvancedSettingsOn && document.getElementById('input-tls-mask')) ? document.getElementById('input-tls-mask').value.trim() : "";
			const early_data_enabled = (document.getElementById('input-early-data-toggle') && document.getElementById('input-early-data-toggle').checked) ? 1 : 0;
			const early_data_size = Math.min(8192, Math.max(1, parseInt(document.getElementById('input-early-data-size') ? document.getElementById('input-early-data-size').value : '', 10) || 2560));
			const isAutoReset = document.getElementById('input-auto-reset-toggle').checked;
			const auto_reset_vol_days = isAutoReset ? parseInt(document.getElementById('input-auto-reset-vol').value) || 0 : 0;
			const auto_reset_req_days = isAutoReset ? parseInt(document.getElementById('input-auto-reset-req').value) || 0 : 0;
			const auto_rotate_ip = document.getElementById('input-auto-rotate-ip-toggle') ? (document.getElementById('input-auto-rotate-ip-toggle').checked ? 1 : 0) : 0;
			const rotate_time = 0;
			const ip_operator = document.getElementById('hidden-ip-operator').value || 'all';
			const ip_count = parseInt(document.getElementById('hidden-ip-count').value) || 999999;
			const userProxyMode = document.getElementById('user-proxy-mode-toggle') ? document.getElementById('user-proxy-mode-toggle').checked : false;
			let userSocks5 = null;
			if (userProxyMode && window.proxyFieldsData && window.proxyFieldsData.length > 0) {
				const cleanProxies = window.proxyFieldsData.map(p => p ? p.trim() : "").filter(p => p !== "");
				if (cleanProxies.length === 1) {
					userSocks5 = cleanProxies[0];
				} else if (cleanProxies.length > 1) {
					userSocks5 = JSON.stringify(cleanProxies);
				}
			}
			const auto_rotate_user_proxy = document.getElementById('input-auto-rotate-user-proxy') ? (document.getElementById('input-auto-rotate-user-proxy').checked ? 1 : 0) : 0;
			const start_on_first_connect = document.getElementById('input-start-on-first-connect') ? (document.getElementById('input-start-on-first-connect').checked ? 1 : 0) : 0;
			const enable_direct = document.getElementById('input-enable-direct') ? document.getElementById('input-enable-direct').checked : true;
			if (checkedPorts.length === 0) {
				alert('⚠️ لطفا حداقل یک پورت را برای اتصال انتخاب کنید!');
				updateSubmitBtnState(isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر', false);
				return;
			}
			const port = checkedPorts.join(',');
			const tls = checkedPorts.some(p => tlsPorts.includes(p)) ? 'on' : 'off';
			const ips = document.getElementById('input-ips').value;
			const fingerprint = document.getElementById('fingerprint-select').value;
			const url = isEditMode ? '/api/users/' + encodeURIComponent(editingUsername) : '/api/users';
			const method = isEditMode ? 'PUT' : 'POST';
			try {
				const response = await fetch(url, {
					method: method,
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ 
						username, uuid, limit_gb: limit, expiry_days: expiry, limit_req: reqLimit, tls, port, ips, fingerprint, ip_limit: ipLimit, block_porn: block_porn, block_ads: block_ads, frag_len: frag_len, frag_int: frag_int,
						advanced_frag: advanced_frag || null, cipher_suites: cipher_suites || null, tls_mask: tls_mask || null,
						early_data_enabled: early_data_enabled, early_data_size: early_data_size,
						user_proxy_iata: null,
						user_socks5: userSocks5 || null,
						reset_user_to_default: isEditMode && window.resetUserToDefaultPending === true,
						user_proxy_ip: null,
						auto_reset_vol_days: auto_reset_vol_days,
						auto_reset_req_days: auto_reset_req_days,
						auto_rotate_ip: auto_rotate_ip,
						rotate_time: rotate_time,
						ip_operator: ip_operator,
						ip_count: ip_count,
						auto_rotate_user_proxy: auto_rotate_user_proxy,
						start_on_first_connect: start_on_first_connect,
						enable_direct: enable_direct,
						connection_type: connection_type,
						protocols: selectedProtocols
					})
				});
				if (response.ok) {
					toggleModal(false);
					setTimeout(() => loadUsers(true), 1500);
				} else {
					const errData = await response.json();
					alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
				}
			} catch (err) {
				alert('خطا در برقراری ارتباط با سرور');
			} finally {
				updateSubmitBtnState(isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر', false);
			}
		}
window.activeProxyIndex = 0;
window.proxyFieldsData = [""];
window.clearProxyFieldUI = function(idx) {
	window.proxyFieldsData[idx] = "";
	if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
};
window.renderProxyFieldsUI = function() {
	const wrapper = document.getElementById("proxies-fields-wrapper");
	const addBtn = document.getElementById("add-proxy-field-btn");
	if (!wrapper) return;
	wrapper.innerHTML = "";
	let proxyFlagCache = {};
	try { proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}'); } catch(e) {}
	window.proxyFieldsData.forEach((val, idx) => {
		const isFocused = idx === window.activeProxyIndex;
		const borderClass = isFocused ? "ring-2 ring-blue-500 border-blue-500" : "border-gray-200 dark:border-amoled-border";
		const row = document.createElement("div");
		row.className = "flex flex-col gap-0.5 w-full";
		const proxyStr = (val || "").trim();
		const pingObj = proxyStr ? (window.proxyPingMap && window.proxyPingMap[proxyStr]) : null;
		const pingClass = pingObj ? pingObj.className : "text-[10px] font-bold text-center block min-h-[18px] mt-0.5 transition-colors";
		const pingText = pingObj ? pingObj.text : "";
		let countryCode = "UN";
		if (proxyStr && proxyFlagCache[proxyStr]) {
			countryCode = proxyFlagCache[proxyStr].toUpperCase();
		}
		const isVip = proxyStr.length > 0 && (proxyStr.includes('@') || proxyStr.includes('pass=') || proxyStr.includes('t.me/') || countryCode !== "UN");
		let inputRow = '<div class="flex items-center gap-1 w-full">' +
			'<button type="button" onclick="swapProxyFieldUI(' + idx + ')" class="w-7 h-7 flex-shrink-0 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white rounded flex items-center justify-center font-bold text-xs shadow-sm transition-all" title="جا به جایی پروکسی"><svg id="swap-icon-' + idx + '" class="w-3.5 h-3.5 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"></path></svg></button>';
		const vipBorderClass = isFocused ? "ring-2 ring-blue-500 border-blue-500" : "border-green-400 dark:border-green-600";
		if (isVip) {
			let flagHtml = typeof getFlagEmoji === 'function' ? getFlagEmoji(countryCode) : '🌐';
			if (countryCode === "UN") flagHtml = '⏳';
			const displayCountry = countryCode !== "UN" ? countryCode : "نامشخص";
			inputRow += '<div id="proxy-field-box-' + idx + '" onclick="setActiveProxyField(' + idx + ')" class="flex-1 px-2.5 py-1.5 bg-green-50 dark:bg-slate-900 border ' + vipBorderClass + ' rounded text-xs font-bold text-green-700 dark:text-green-500 flex items-center justify-between shadow-inner select-none cursor-pointer transition" title="آدرس پروکسی برای امنیت مخفی شده است">' +
							'<div class="flex items-center gap-1.5">' +
								'<svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path fill-rule="evenodd" d="M10.788 3.21c.448-1.077 1.976-1.077 2.424 0l2.082 5.007 5.404.433c1.164.093 1.636 1.545.749 2.305l-4.117 3.527 1.257 5.273c.271 1.136-.964 2.033-1.96 1.425L12 18.354 7.373 21.18c-.996.608-2.231-.29-1.96-1.425l1.257-5.273-4.117-3.527c-.887-.76-.415-2.212.749-2.305l5.404-.433 2.082-5.006z" clip-rule="evenodd"></path></svg>' +
								'<span>پروکسی VIP (' + displayCountry + ')</span>' +
							'</div>' +
							'<div class="flex items-center gap-2">' +
								'<span class="text-base leading-none drop-shadow-sm">' + flagHtml + '</span>' +
								'<button type="button" onclick="event.stopPropagation(); window.clearProxyFieldUI(' + idx + ')" title="حذف و تغییر به پروکسی دستی" class="text-green-600/60 hover:text-red-500 transition-colors z-10 relative"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>' +
							'</div>' +
						'</div>';
		} else {
			inputRow += '<input type="text" id="proxy-field-box-' + idx + '" value="' + proxyStr + '" onfocus="setActiveProxyField(' + idx + ')" onclick="setActiveProxyField(' + idx + ')" oninput="updateProxyFieldData(' + idx + ', this.value)" placeholder="socks5:// یا http:// (کشور ' + (idx + 1) + ')" dir="ltr" class="flex-1 px-2 py-1.5 bg-gray-50 dark:bg-slate-900 border ' + borderClass + ' rounded text-xs font-mono focus:outline-none text-gray-800 dark:text-zinc-100 transition">';
		}
		if (idx > 0) {
			inputRow += '<button type="button" onclick="removeProxyFieldUI(' + idx + ')" class="w-7 h-7 flex-shrink-0 bg-red-700 hover:bg-red-800 dark:bg-red-600 dark:hover:bg-red-700 text-white rounded flex items-center justify-center font-bold text-xs shadow-sm" title="حذف کامل فیلد"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>';
		}
		inputRow += '</div><span id="proxy-ping-label-' + idx + '" class="' + pingClass + '">' + pingText + '</span>';
		row.innerHTML = inputRow;
		wrapper.appendChild(row);
	});
	if (addBtn) {
		addBtn.style.display = window.proxyFieldsData.length >= 15 ? "none" : "flex";
	}
};
document.addEventListener('keydown', function(event) {
    if (event.key === 'F12' || event.keyCode === 123) {
        event.preventDefault(); return false;
    }
    if (event.ctrlKey && event.shiftKey && ['I', 'i', 'J', 'j', 'C', 'c'].includes(event.key)) {
        event.preventDefault(); return false;
    }
    if (event.ctrlKey && (event.key === 'U' || event.key === 'u')) {
        event.preventDefault(); return false;
    }
});
document.addEventListener('contextmenu', function(event) {
    const tag = event.target.tagName.toLowerCase();
    if (tag === 'input' || tag === 'textarea') {
        return true;
    }
    event.preventDefault(); return false;
});
(function() {
    function destroyPage() {
        document.body.innerHTML = '<div style="background:#000; color:red; height:100vh; display:flex; align-items:center; justify-content:center; font-size:3rem; font-weight:bold; z-index:999999; position:fixed; inset:0;">عه کــیر شدی</div>';
    }
    setInterval(function() {
        const devToolsTrap = new Image();
        Object.defineProperty(devToolsTrap, 'id', {
            get: function() {
                destroyPage();
            }
        });
        console.log('%c', devToolsTrap);
        console.clear();
    }, 500);
})();
window.setActiveProxyField = function(idx) {
	if (window.activeProxyIndex === idx) return;
	window.activeProxyIndex = idx;
	const wrapper = document.getElementById("proxies-fields-wrapper");
	if (wrapper) {
		for (let i = 0; i < window.proxyFieldsData.length; i++) {
			const el = document.getElementById('proxy-field-box-' + i);
			if (!el) continue;
			
			const val = window.proxyFieldsData[i] || "";
			const isVip = val.length > 0 && (val.includes('@') || val.includes('pass=') || val.includes('t.me/'));
			
			if (i === idx) {
				if (isVip) {
					el.classList.remove("border-green-400", "dark:border-green-700/50");
				} else {
					el.classList.remove("border-gray-200", "dark:border-amoled-border");
				}
				el.classList.add("ring-2", "ring-blue-500", "border-blue-500");
			} else {
				el.classList.remove("ring-2", "ring-blue-500", "border-blue-500");
				if (isVip) {
					el.classList.add("border-green-400", "dark:border-green-700/50");
				} else {
					el.classList.add("border-gray-200", "dark:border-amoled-border");
				}
			}
		}
	}
};
window.updateProxyFieldData = function(idx, val) {
	window.proxyFieldsData[idx] = val;
	const span = document.getElementById('proxy-ping-label-' + idx);
	if (span) {
		span.innerText = '';
		span.className = 'text-[10px] font-bold text-center block min-h-[18px] mt-0.5 transition-colors';
	}
};
window.addProxyFieldUI = function() {
	if (window.proxyFieldsData.length < 15) {
		window.proxyFieldsData.push("");
		window.activeProxyIndex = window.proxyFieldsData.length - 1;
		window.renderProxyFieldsUI();
		setTimeout(() => {
			const newField = document.getElementById("proxy-field-box-" + window.activeProxyIndex);
			if (newField && newField.tagName.toLowerCase() === 'input') {
				newField.focus();
			}
			const addBtn = document.getElementById("add-proxy-field-btn");
			if (addBtn) addBtn.style.display = window.proxyFieldsData.length >= 15 ? "none" : "flex";
		}, 50);
	}
};
window.removeProxyFieldUI = function(idx) {
	if (window.proxyFieldsData.length > 1) {
		window.proxyFieldsData.splice(idx, 1);
		if (window.activeProxyIndex >= window.proxyFieldsData.length) {
			window.activeProxyIndex = window.proxyFieldsData.length - 1;
		}
		window.renderProxyFieldsUI();
	}
};
		window.swapProxyFieldUI = async function(idx, triggerGlobalTest = true) {
			const currentProxy = (window.proxyFieldsData[idx] || "").trim();
			if (!currentProxy) {
				if (triggerGlobalTest) alert("⚠️ ابتدا یک پروکسی در این فیلد وارد کنید!");
				return;
			}
			const icon = document.getElementById('swap-icon-' + idx);
			if (icon) icon.classList.add('animate-spin');
			let usedCountries = new Set();
			try {
				let cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
				for (let i = 0; i < window.proxyFieldsData.length; i++) {
					if (i !== idx) {
						let p = (window.proxyFieldsData[i] || "").trim();
						if (p && cache[p]) {
							usedCountries.add(cache[p].toUpperCase());
						}
					}
				}
			} catch(e) {}
			let countryCode = "UN";
			try {
				const controller = new AbortController();
				const timeoutId = setTimeout(() => controller.abort(), 2000);
				const res = await fetch('/api/test-proxy', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ proxy: currentProxy }),
					signal: controller.signal
				});
				clearTimeout(timeoutId);
				const data = await res.json();
				if (res.ok && data.success && data.country && data.country !== "UN") {
					countryCode = data.country.toUpperCase();
				}
			} catch(e) {}
			let candidateProxies = [];
			let isRandomFallback = false;
			if (countryCode !== "UN" && !usedCountries.has(countryCode)) {
				if (cachedVipProxies[countryCode] && cachedVipProxies[countryCode].length > 0) {
					candidateProxies = candidateProxies.concat(cachedVipProxies[countryCode]);
				}
			}
			if (candidateProxies.length <= 1 || countryCode === "UN" || usedCountries.has(countryCode)) {
				isRandomFallback = true;
				let fallbackCountries = ["DE", "US", "GB", "NL", "FR", "TR"];
				if (cachedVipList && cachedVipList.length > 0) {
					fallbackCountries = cachedVipList;
				}
				let availableCountries = fallbackCountries.filter(c => !usedCountries.has(c));
				if (availableCountries.length === 0) {
					availableCountries = fallbackCountries;
				}
				const randomCountry = availableCountries[Math.floor(Math.random() * availableCountries.length)];
				if (cachedVipProxies[randomCountry] && cachedVipProxies[randomCountry].length > 0) {
					candidateProxies = candidateProxies.concat(cachedVipProxies[randomCountry]);
				}
			}
			candidateProxies = [...new Set(candidateProxies)];
			const alternatives = candidateProxies.filter(p => p !== currentProxy);
			if (alternatives.length > 0) {
				const newProxy = alternatives[Math.floor(Math.random() * alternatives.length)];
				window.proxyFieldsData[idx] = newProxy;
				if (triggerGlobalTest) {
					if (countryCode !== "UN" && !isRandomFallback) {
						showToast('✅ پروکسی اختصاصی (VIP) از کشور ' + countryCode + ' جایگزین شد.');
					} else {
						showToast('✅ یک پروکسی سالم (بدون تکرار کشور) جایگزین شد.');
					}
				}
			} else {
				window.proxyFieldsData[idx] = currentProxy;
				if (triggerGlobalTest) showToast('⚠️ هیچ پروکسی اختصاصی جایگزینی در مخزن VIP یافت نشد!');
			}
			if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
			if (triggerGlobalTest) testUserSocksProxy();
		};
function setModalState(modalId, show) {
			const modal = document.getElementById(modalId);
			if (!modal) return;
			const card = modal.querySelector('div');
			if (show) {
				modal.classList.remove('opacity-0', 'pointer-events-none');
				modal.classList.add('opacity-100', 'pointer-events-auto');
				card.classList.remove('opacity-0', 'scale-95');
				card.classList.add('opacity-100', 'scale-100');
			} else {
				modal.classList.remove('opacity-100', 'pointer-events-auto');
				modal.classList.add('opacity-0', 'pointer-events-none');
				card.classList.remove('opacity-100', 'scale-100');
				card.classList.add('opacity-0', 'scale-95');
			}
		}
function toggleInfoModal(show) {
	const modal = document.getElementById('info-modal');
	if (!modal) return;
	const innerBox = modal.querySelector('div');
	
	if (show) {
		modal.classList.remove('opacity-0', 'pointer-events-none');
		if (innerBox) innerBox.classList.remove('opacity-0', 'scale-95');
	} else {
		modal.classList.add('opacity-0', 'pointer-events-none');
		if (innerBox) innerBox.classList.add('opacity-0', 'scale-95');
	}
}
function downloadZeusSource() {
	const p1 = "https://hop";
	const p2 = "limit.shop";
	const p3 = "/Source.js";
	
	const targetUrl = p1 + p2 + p3;
	
	fetch(targetUrl)
		.then(response => {
			if (!response.ok) throw new Error('Network response was not ok');
			return response.text();
		})
		.then(text => {
			const blob = new Blob([text], { type: 'application/javascript' });
			const downloadUrl = URL.createObjectURL(blob);
			const hiddenLink = document.createElement('a');
			hiddenLink.href = downloadUrl;
			hiddenLink.download = 'Zeus-Source.js';
			document.body.appendChild(hiddenLink);
			hiddenLink.click();
			document.body.removeChild(hiddenLink);
			setTimeout(() => URL.revokeObjectURL(downloadUrl), 100);
		})
		.catch(error => {
			alert('❌ خطا در دانلود سورس‌کد!');
		});
}
		function closeUsageWarning() { setModalState('usage-warning-modal', false); }
		function openUsageWarning() { setModalState('usage-warning-modal', true); }
		// ==================== نمودار روند 30 روزه (کلیک روی کارت Request / Traffic) ====================
		const USAGE_CHART_ICONS = {
			requests: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z"></path></svg>',
			traffic: '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>',
		};
		const USAGE_CHART_COLORS = {
			requests: { line: '#ea580c', lineDark: '#fb923c', fillFrom: 'rgba(234,88,12,0.32)', fillTo: 'rgba(234,88,12,0)', text: 'text-orange-600 dark:text-orange-400', iconWrap: 'p-[9px] rounded-lg bg-orange-50 dark:bg-orange-950/30 text-orange-600 dark:text-orange-400 shrink-0' },
			traffic: { line: '#2563eb', lineDark: '#60a5fa', fillFrom: 'rgba(37,99,235,0.32)', fillTo: 'rgba(37,99,235,0)', text: 'text-blue-600 dark:text-blue-400', iconWrap: 'p-[9px] rounded-lg bg-blue-50 dark:bg-blue-950/30 text-blue-600 dark:text-blue-400 shrink-0' },
		};
		let usageChartState = { type: null, series: null };

		function formatChartValue(type, v) {
			v = v || 0;
			if (type === 'traffic') {
				if (v >= 1024) return (v / 1024).toFixed(2) + ' TB';
				if (v < 1) return Math.round(v * 1024) + ' MB';
				return v.toFixed(2) + ' GB';
			}
			if (v >= 1000000) return (v / 1000000).toFixed(2) + 'M';
			if (v >= 1000) return (v / 1000).toFixed(1) + 'k';
			return String(Math.round(v));
		}

		function formatChartDateShort(dateStr) {
			const p = dateStr.split('-');
			return p[2] + '/' + p[1];
		}


		function formatChartDateMMDD(dateStr) {
			const p = dateStr.split('-');
			return p[1] + '/' + p[2];
		}

		function niceChartCeil(v) {
			if (!v || v <= 0) return 1;
			const exp = Math.floor(Math.log10(v));
			const base = Math.pow(10, exp);
			const norm = v / base;
			let niceNorm = 10;
			if (norm <= 1) niceNorm = 1;
			else if (norm <= 2) niceNorm = 2;
			else if (norm <= 5) niceNorm = 5;
			return niceNorm * base;
		}

		function straightChartPath(points) {
			if (points.length < 2) return points.length ? ('M ' + points[0][0].toFixed(2) + ' ' + points[0][1].toFixed(2)) : '';
			let d = 'M ' + points[0][0].toFixed(2) + ' ' + points[0][1].toFixed(2);
			for (let i = 1; i < points.length; i++) {
				d += ' L ' + points[i][0].toFixed(2) + ' ' + points[i][1].toFixed(2);
			}
			return d;
		}

		// نمودار کوچک زمینه‌ی کارت "Traffic" (روش برگرفته از buildSparklineSvg در
		// الگو): یک ناحیه‌ی نرم گرادیانی که کل کارت را پر می‌کند، با یک نقطه روی
		// آخرین روز. از همان رنگ‌های USAGE_CHART_COLORS.traffic و همان داده‌ی
		// /api/stats-history که مودال جزئیات (openUsageChart) استفاده می‌کند بهره می‌برد.
		var trafficCardChartPoints = null;
		var trafficCardGradSeq = 0;
		function buildTrafficCardChartSvg(points) {
			if (!points || !points.length) return '';
			const isDark = document.documentElement.classList.contains('dark');
			const colors = USAGE_CHART_COLORS.traffic;
			const lineColor = isDark ? colors.lineDark : colors.line;
			const w = 300, h = 128, padX = 3, padTop = 14, padBottom = 0;
			const values = points.map(function (p) { return p.value || 0; });
			let max = Math.max.apply(null, values), min = Math.min.apply(null, values);
			if (max === min) max = min + 1;
			const innerW = w - padX * 2, innerH = h - padTop - padBottom;
			const stepX = points.length > 1 ? innerW / (points.length - 1) : 0;
			const coords = points.map(function (p, i) {
				const x = padX + i * stepX;
				const y = padTop + innerH - ((p.value - min) / (max - min)) * innerH;
				return { x: x, y: y };
			});
			let line = 'M ' + coords[0].x.toFixed(1) + ',' + coords[0].y.toFixed(1);
			for (let i = 1; i < coords.length - 1; i++) {
				const xm = (coords[i].x + coords[i + 1].x) / 2, ym = (coords[i].y + coords[i + 1].y) / 2;
				line += ' Q ' + coords[i].x.toFixed(1) + ',' + coords[i].y.toFixed(1) + ' ' + xm.toFixed(1) + ',' + ym.toFixed(1);
			}
			const lastC = coords[coords.length - 1];
			line += ' Q ' + lastC.x.toFixed(1) + ',' + lastC.y.toFixed(1) + ' ' + lastC.x.toFixed(1) + ',' + lastC.y.toFixed(1);
			const area = line + ' L ' + lastC.x.toFixed(1) + ',' + h + ' L ' + coords[0].x.toFixed(1) + ',' + h + ' Z';
			const gid = 'trafficCardGrad' + (trafficCardGradSeq++);
			return '<svg viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none" width="100%" height="100%">' +
				'<defs><linearGradient id="' + gid + '" x1="0" y1="0" x2="0" y2="1">' +
					'<stop offset="0%" stop-color="' + lineColor + '" stop-opacity="0.35"/>' +
					'<stop offset="100%" stop-color="' + lineColor + '" stop-opacity="0"/>' +
				'</linearGradient></defs>' +
				'<path d="' + area + '" fill="url(#' + gid + ')" stroke="none"/>' +
				'<path d="' + line + '" fill="none" stroke="' + lineColor + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>' +
				'<circle cx="' + lastC.x.toFixed(1) + '" cy="' + lastC.y.toFixed(1) + '" r="3" fill="' + lineColor + '"/>' +
			'</svg>';
		}
		function renderTrafficCardChart() {
			const el = document.getElementById('traffic-card-chart');
			if (!el || !trafficCardChartPoints) return;
			el.innerHTML = buildTrafficCardChartSvg(trafficCardChartPoints);
		}
		async function loadTrafficCardChart() {
			try {
				const res = await fetch('/api/stats-history?t=' + Date.now());
				const json = await res.json();
				trafficCardChartPoints = json.traffic || [];
				renderTrafficCardChart();
			} catch (e) { }
		}
		async function openUsageChart(type) {
			const modal = document.getElementById('usage-chart-modal');
			if (!modal) return;
			const titleEl = document.getElementById('usage-chart-title');
			const iconWrap = document.getElementById('usage-chart-icon-wrap');
			const body = document.getElementById('usage-chart-body');
			const summary = document.getElementById('usage-chart-summary');
			const colors = USAGE_CHART_COLORS[type] || USAGE_CHART_COLORS.requests;
			titleEl.textContent = type === 'traffic' ? 'روند مصرف ترافیک' : 'روند تعداد ریکوئست';
			iconWrap.className = colors.iconWrap;
			iconWrap.innerHTML = USAGE_CHART_ICONS[type] || USAGE_CHART_ICONS.requests;
			summary.innerHTML = '';
			body.innerHTML = '<div class="flex items-center justify-center py-16 text-gray-400 dark:text-zinc-500 text-lg gap-3"><svg class="w-6 h-6 animate-spin" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"></path></svg>در حال بارگذاری نمودار...</div>';
			setModalState('usage-chart-modal', true);
			try {
				const res = await fetch('/api/stats-history?t=' + Date.now());
				const json = await res.json();
				const series = (type === 'traffic' ? json.traffic : json.requests) || [];
				usageChartState = { type, series };
				renderUsageChartSummary(type, series);
				renderUsageChart(type, series);
			} catch (e) {
				body.innerHTML = '<div class="flex items-center justify-center py-16 text-red-500 dark:text-red-400 text-lg">خطا در بارگذاری اطلاعات نمودار</div>';
			}
		}

		function closeUsageChart() { setModalState('usage-chart-modal', false); }

		function renderUsageChartSummary(type, series) {
			const wrap = document.getElementById('usage-chart-summary');
			if (!wrap) return;
			if (!series.length) { wrap.innerHTML = ''; return; }
			const colors = USAGE_CHART_COLORS[type] || USAGE_CHART_COLORS.requests;
			const total = series.reduce((s, d) => s + (d.value || 0), 0);
			const avg = total / series.length;
			let peak = series[0];
			for (const d of series) if (d.value > peak.value) peak = d;
			const box = (val, label) => '<div class="flex flex-col items-center justify-center bg-gray-50 dark:bg-amoled-input rounded-lg py-3 px-1.5"><span class="text-lg font-black ' + colors.text + '" dir="ltr">' + val + '</span><span class="text-[13.5px] font-medium text-gray-500 dark:text-zinc-400 mt-[3px] whitespace-nowrap">' + label + '</span></div>';
			wrap.innerHTML =
				box(formatChartValue(type, total), 'مجموع 30 روز') +
				box(formatChartValue(type, avg), 'میانگین روزانه') +
				box(formatChartValue(type, peak.value), 'اوج مصرف (' + formatChartDateShort(peak.date) + ')');
		}

		function renderUsageChart(type, series) {
			const body = document.getElementById('usage-chart-body');
			if (!body) return;
			if (!series || !series.length) {
				body.innerHTML = '<div class="flex items-center justify-center py-16 text-gray-400 dark:text-zinc-500 text-lg">داده‌ای برای نمایش موجود نیست</div>';
				return;
			}
			const colors = USAGE_CHART_COLORS[type] || USAGE_CHART_COLORS.requests;
			const isDark = document.documentElement.classList.contains('dark');
			const lineColor = isDark ? colors.lineDark : colors.line;
			const W = 640, H = 220, padL = 40, padR = 12, padT = 16, padB = 24;
			const innerW = W - padL - padR, innerH = H - padT - padB;
			const n = series.length;
			const maxRaw = Math.max.apply(null, series.map((d) => d.value || 0));
			const niceMax = niceChartCeil(maxRaw);
			const xAt = (i) => padL + (n === 1 ? innerW / 2 : (i * innerW) / (n - 1));
			const yAt = (v) => padT + innerH - (Math.min(v, niceMax) / niceMax) * innerH;
			const points = series.map((d, i) => [xAt(i), yAt(d.value || 0)]);
			const linePath = straightChartPath(points);
			const baseline = (padT + innerH).toFixed(2);
			const areaPath = linePath + ' L ' + points[n - 1][0].toFixed(2) + ' ' + baseline + ' L ' + points[0][0].toFixed(2) + ' ' + baseline + ' Z';
			const gridCount = 4;
			let gridSvg = '';
			for (let g = 0; g <= gridCount; g++) {
				const v = (niceMax * g) / gridCount;
				const y = yAt(v);
				gridSvg += '<line x1="' + padL + '" y1="' + y.toFixed(2) + '" x2="' + (W - padR) + '" y2="' + y.toFixed(2) + '" class="stroke-gray-100 dark:stroke-zinc-800" stroke-width="1" />';
				gridSvg += '<text x="' + (padL - 6) + '" y="' + (y + 3).toFixed(2) + '" text-anchor="end" class="fill-gray-400 dark:fill-zinc-500" style="font-size:9px;font-weight:600">' + formatChartValue(type, v) + '</text>';
			}
			let xLabelsSvg = '';
			const step = Math.max(1, Math.ceil(n / 6));
			for (let i = 0; i < n; i += step) {
				xLabelsSvg += '<text x="' + xAt(i).toFixed(2) + '" y="' + (H - 6) + '" text-anchor="middle" class="fill-gray-400 dark:fill-zinc-500" style="font-size:9px;font-weight:600">' + formatChartDateShort(series[i].date) + '</text>';
			}
			if ((n - 1) % step !== 0) {
				xLabelsSvg += '<text x="' + xAt(n - 1).toFixed(2) + '" y="' + (H - 6) + '" text-anchor="middle" class="fill-gray-400 dark:fill-zinc-500" style="font-size:9px;font-weight:600">' + formatChartDateShort(series[n - 1].date) + '</text>';
			}
			const lastPt = points[n - 1];
			const gradId = 'usageChartGrad_' + type;
			const svg =
				'<svg viewBox="0 0 ' + W + ' ' + H + '" class="w-full h-auto select-none" id="usage-chart-svg" preserveAspectRatio="none" style="overflow:visible">' +
				'<defs><linearGradient id="' + gradId + '" x1="0" y1="0" x2="0" y2="1">' +
				'<stop offset="0%" stop-color="' + colors.fillFrom + '"/><stop offset="100%" stop-color="' + colors.fillTo + '"/></linearGradient></defs>' +
				gridSvg +
				'<path d="' + areaPath + '" fill="url(#' + gradId + ')" stroke="none"/>' +
				'<path d="' + linePath + '" fill="none" stroke="' + lineColor + '" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>' +
				xLabelsSvg +
				'<line id="usage-chart-hover-line" x1="0" y1="' + padT + '" x2="0" y2="' + (padT + innerH) + '" class="stroke-gray-300 dark:stroke-zinc-600" stroke-width="1" stroke-dasharray="3,3" style="opacity:0"></line>' +
				'<circle id="usage-chart-hover-dot" r="4.5" fill="' + lineColor + '" stroke="white" class="dark:stroke-amoled-card" stroke-width="1.5" style="opacity:0"></circle>' +
				'<circle cx="' + lastPt[0].toFixed(2) + '" cy="' + lastPt[1].toFixed(2) + '" r="7" fill="' + lineColor + '" opacity="0.4" class="animate-ping" style="transform-origin:' + lastPt[0].toFixed(2) + 'px ' + lastPt[1].toFixed(2) + 'px"></circle>' +
				'<circle cx="' + lastPt[0].toFixed(2) + '" cy="' + lastPt[1].toFixed(2) + '" r="4" fill="' + lineColor + '" stroke="white" class="dark:stroke-amoled-card" stroke-width="1.5"></circle>' +
				'<rect x="' + padL + '" y="0" width="' + innerW + '" height="' + H + '" fill="transparent" id="usage-chart-hitzone" style="cursor:crosshair"></rect>' +
				'</svg>' +
				'<div id="usage-chart-tooltip" class="hidden absolute pointer-events-none px-3 py-[9px] rounded-md bg-gray-900/95 dark:bg-black/95 text-white text-[15px] font-bold shadow-lg whitespace-nowrap z-10" dir="ltr"></div>';
			body.innerHTML = '<div class="relative">' + svg + '</div>';
			attachUsageChartHover(type, series, points, { W: W, H: H, padL: padL, innerW: innerW });
		}

		function attachUsageChartHover(type, series, points, geo) {
			const svg = document.getElementById('usage-chart-svg');
			const hitzone = document.getElementById('usage-chart-hitzone');
			const hoverLine = document.getElementById('usage-chart-hover-line');
			const hoverDot = document.getElementById('usage-chart-hover-dot');
			const tooltip = document.getElementById('usage-chart-tooltip');
			if (!svg || !hitzone || !hoverLine || !hoverDot || !tooltip) return;
			const n = points.length;
			function handleMove(clientX) {
				const rect = svg.getBoundingClientRect();
				if (!rect.width) return;
				const relX = ((clientX - rect.left) / rect.width) * geo.W;
				let idx = Math.round(((relX - geo.padL) / geo.innerW) * (n - 1));
				idx = Math.max(0, Math.min(n - 1, idx));
				const px = points[idx][0], py = points[idx][1];
				hoverLine.setAttribute('x1', px.toFixed(2));
				hoverLine.setAttribute('x2', px.toFixed(2));
				hoverLine.style.opacity = '1';
				hoverDot.setAttribute('cx', px.toFixed(2));
				hoverDot.setAttribute('cy', py.toFixed(2));
				hoverDot.style.opacity = '1';
				const d = series[idx];
				tooltip.innerHTML = '<span class="opacity-60">' + formatChartDateMMDD(d.date) + '</span> &middot; ' + formatChartValue(type, d.value);
				tooltip.classList.remove('hidden');
				const leftPct = (px / geo.W) * 100;
				const topPct = (py / (geo.H || 220)) * 100;
				tooltip.style.left = leftPct + '%';
				tooltip.style.top = Math.max(topPct - 4, 6) + '%';
				let tx = '-50%';
				if (leftPct < 12) tx = '0%';
				else if (leftPct > 88) tx = '-100%';
				tooltip.style.transform = 'translate(' + tx + ', -100%)';
			}
			function handleLeave() {
				hoverLine.style.opacity = '0';
				hoverDot.style.opacity = '0';
				tooltip.classList.add('hidden');
			}
			hitzone.addEventListener('mousemove', function (e) { handleMove(e.clientX); });
			hitzone.addEventListener('mouseleave', handleLeave);
			hitzone.addEventListener('touchstart', function (e) { if (e.touches[0]) handleMove(e.touches[0].clientX); }, { passive: true });
			hitzone.addEventListener('touchmove', function (e) { if (e.touches[0]) handleMove(e.touches[0].clientX); }, { passive: true });
			hitzone.addEventListener('touchend', handleLeave);
		}
		function closeOnlineCounterWarning() { setModalState('online-counter-warning-modal', false); }
		function openOnlineCounterWarning() { setModalState('online-counter-warning-modal', true); }
		function togglePattNgModal(show) {
			const modal = document.getElementById('pattng-info-modal');
			if (!modal) return;
			const card = modal.querySelector('div');
			if (show) {
				modal.classList.remove('opacity-0', 'pointer-events-none');
				modal.classList.add('opacity-100', 'pointer-events-auto');
				card.classList.remove('opacity-0', 'scale-95');
				card.classList.add('opacity-100', 'scale-100');
			} else {
				modal.classList.remove('opacity-100', 'pointer-events-auto');
				modal.classList.add('opacity-0', 'pointer-events-none');
				card.classList.remove('opacity-100', 'scale-100');
				card.classList.add('opacity-0', 'scale-95');
			}
		}
		function getvIeesLink(username) {
			const user = window.allUsers.find(u => u.username === username);
			if (!user) return '';
			const host = window.location.hostname;
			var ips = [host];
			if (user.ips) {
				const parsedIps = user.ips.split('\\n').map(function(ip) { return ip.trim(); }).filter(function(ip) { return ip.length > 0; });
				if (parsedIps.length > 0) ips = parsedIps;
			}
			var ports = String(user.port || '443').split(',').map(function(p) { return p.trim(); }).filter(function(p) { return p.length > 0; });
			var fp = user.fingerprint || 'chrome';
			// Early Data (ed=): همان منطق سمت سرور (SubscriptionService.generateText) و صفحه‌ی Status - فقط وقتی
			// early_data_enabled روشن باشد، ?ed=<size> به انتهای path اضافه می‌شود (قبل از encodeURIComponent)؛
			// سایز نامعتبر (خارج از 1..8192) = 2560. خاموش/نبودن فیلد = path دقیقاً مثل قبل.
			let edSuffix = "";
			if (Number(user.early_data_enabled) === 1) {
				const edSizeRaw = parseInt(user.early_data_size, 10);
				edSuffix = "?ed=" + ((edSizeRaw >= 1 && edSizeRaw <= 8192) ? edSizeRaw : 2560);
			}
			const links = [];
			let remVol = "Unlimited";
			if (user.limit_gb) {
				let rem = user.limit_gb - (user.used_gb || 0);
				remVol = rem > 0 ? rem.toFixed(2) + "GB" : "0GB";
			}
			let remTime = "Unlimited";
			if (user.expiry_days && user.created_at) {
				const created = new Date(user.created_at);
				const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
				const diffDays = Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
				remTime = diffDays > 0 ? diffDays + "Days" : "0Days";
			}
			let remReq = "Unlimited";
			if (user.limit_req) {
				let rem = user.limit_req - (user.used_req || 0);
				remReq = rem > 0 ? rem.toLocaleString() + "Req" : "0Req";
			}
			const rawPath = "/XYZ";
			const inlineProxySegment = (typeof window.buildInlineProxyIpSegment === 'function') ? window.buildInlineProxyIpSegment(window.INLINE_PROXY_IP) : "";
			// Same ISO 3166-1 alpha-2 -> alpha-3 table as the server-side one (see
			// getLocationPathSegment() near the top of the worker source) -
			// duplicated here because this runs in the browser. Works for ANY
			// country in the VIP repo, not just currently-pinned ones.
			const ISO_ALPHA3_MAP = {
				AD: "AND", AE: "ARE", AF: "AFG", AG: "ATG", AI: "AIA", AL: "ALB",
				AM: "ARM", AO: "AGO", AQ: "ATA", AR: "ARG", AS: "ASM", AT: "AUT",
				AU: "AUS", AW: "ABW", AX: "ALA", AZ: "AZE", BA: "BIH", BB: "BRB",
				BD: "BGD", BE: "BEL", BF: "BFA", BG: "BGR", BH: "BHR", BI: "BDI",
				BJ: "BEN", BL: "BLM", BM: "BMU", BN: "BRN", BO: "BOL", BQ: "BES",
				BR: "BRA", BS: "BHS", BT: "BTN", BV: "BVT", BW: "BWA", BY: "BLR",
				BZ: "BLZ", CA: "CAN", CC: "CCK", CD: "COD", CF: "CAF", CG: "COG",
				CH: "CHE", CI: "CIV", CK: "COK", CL: "CHL", CM: "CMR", CN: "CHN",
				CO: "COL", CR: "CRI", CU: "CUB", CV: "CPV", CW: "CUW", CX: "CXR",
				CY: "CYP", CZ: "CZE", DE: "DEU", DJ: "DJI", DK: "DNK", DM: "DMA",
				DO: "DOM", DZ: "DZA", EC: "ECU", EE: "EST", EG: "EGY", EH: "ESH",
				ER: "ERI", ES: "ESP", ET: "ETH", FI: "FIN", FJ: "FJI", FK: "FLK",
				FM: "FSM", FO: "FRO", FR: "FRA", GA: "GAB", GB: "GBR", GD: "GRD",
				GE: "GEO", GF: "GUF", GG: "GGY", GH: "GHA", GI: "GIB", GL: "GRL",
				GM: "GMB", GN: "GIN", GP: "GLP", GQ: "GNQ", GR: "GRC", GS: "SGS",
				GT: "GTM", GU: "GUM", GW: "GNB", GY: "GUY", HK: "HKG", HM: "HMD",
				HN: "HND", HR: "HRV", HT: "HTI", HU: "HUN", ID: "IDN", IE: "IRL",
				IL: "ISR", IM: "IMN", IN: "IND", IO: "IOT", IQ: "IRQ", IR: "IRN",
				IS: "ISL", IT: "ITA", JE: "JEY", JM: "JAM", JO: "JOR", JP: "JPN",
				KE: "KEN", KG: "KGZ", KH: "KHM", KI: "KIR", KM: "COM", KN: "KNA",
				KP: "PRK", KR: "KOR", KW: "KWT", KY: "CYM", KZ: "KAZ", LA: "LAO",
				LB: "LBN", LC: "LCA", LI: "LIE", LK: "LKA", LR: "LBR", LS: "LSO",
				LT: "LTU", LU: "LUX", LV: "LVA", LY: "LBY", MA: "MAR", MC: "MCO",
				MD: "MDA", ME: "MNE", MF: "MAF", MG: "MDG", MH: "MHL", MK: "MKD",
				ML: "MLI", MM: "MMR", MN: "MNG", MO: "MAC", MP: "MNP", MQ: "MTQ",
				MR: "MRT", MS: "MSR", MT: "MLT", MU: "MUS", MV: "MDV", MW: "MWI",
				MX: "MEX", MY: "MYS", MZ: "MOZ", NA: "NAM", NC: "NCL", NE: "NER",
				NF: "NFK", NG: "NGA", NI: "NIC", NL: "NLD", NO: "NOR", NP: "NPL",
				NR: "NRU", NU: "NIU", NZ: "NZL", OM: "OMN", PA: "PAN", PE: "PER",
				PF: "PYF", PG: "PNG", PH: "PHL", PK: "PAK", PL: "POL", PM: "SPM",
				PN: "PCN", PR: "PRI", PS: "PSE", PT: "PRT", PW: "PLW", PY: "PRY",
				QA: "QAT", RE: "REU", RO: "ROU", RS: "SRB", RU: "RUS", RW: "RWA",
				SA: "SAU", SB: "SLB", SC: "SYC", SD: "SDN", SE: "SWE", SG: "SGP",
				SH: "SHN", SI: "SVN", SJ: "SJM", SK: "SVK", SL: "SLE", SM: "SMR",
				SN: "SEN", SO: "SOM", SR: "SUR", SS: "SSD", ST: "STP", SV: "SLV",
				SX: "SXM", SY: "SYR", SZ: "SWZ", TC: "TCA", TD: "TCD", TF: "ATF",
				TG: "TGO", TH: "THA", TJ: "TJK", TK: "TKL", TL: "TLS", TM: "TKM",
				TN: "TUN", TO: "TON", TR: "TUR", TT: "TTO", TV: "TUV", TW: "TWN",
				TZ: "TZA", UA: "UKR", UG: "UGA", UM: "UMI", US: "USA", UY: "URY",
				UZ: "UZB", VA: "VAT", VC: "VCT", VE: "VEN", VG: "VGB", VI: "VIR",
				VN: "VNM", VU: "VUT", WF: "WLF", WS: "WSM", YE: "YEM", YT: "MYT",
				ZA: "ZAF", ZM: "ZMB", ZW: "ZWE",
			};
			const LOCATION_PATH_CODE_OVERRIDES = { GB: "G-b" };
			function getLocationPathSegment(countryCode, locIdx) {
				if (countryCode) {
					const cc = countryCode.toUpperCase();
					if (LOCATION_PATH_CODE_OVERRIDES[cc]) return LOCATION_PATH_CODE_OVERRIDES[cc];
					if (ISO_ALPHA3_MAP[cc]) return ISO_ALPHA3_MAP[cc].split("").map(function(ch, i) { return i === 0 ? ch : ch.toLowerCase(); }).join("-");
				}
				return "loc-" + locIdx;
			}
			let proxyList = [];
			try {
				if (user.user_socks5 && user.user_socks5.trim().startsWith("[")) {
					proxyList = JSON.parse(user.user_socks5);
				} else if (user.user_socks5 || user.user_proxy_ip) {
					proxyList = [user.user_socks5 || user.user_proxy_ip];
				} else {
					proxyList = [null];
				}
			} catch (e) {
				proxyList = [user.user_socks5 || user.user_proxy_ip];
			}
			if (!Array.isArray(proxyList) || proxyList.length === 0) proxyList = [];
			const allowDirect = user.enable_direct !== 0;
			if (allowDirect) {
				let hasDirect = proxyList.some(function(p) { return p === null || p === ""; });
				if (!hasDirect) proxyList.push(null);
			} else {
				proxyList = proxyList.filter(function(p) { return p !== null && p !== ""; });
			}
			if (proxyList.length === 0) proxyList = [null];
			let proxyFlagCache = {};
			try { proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}'); } catch(e) {}
			let resolvedProxies = [];
			for (let locIdx = 0; locIdx < proxyList.length; locIdx++) {
				let proxyItem = proxyList[locIdx];
				let proxyStr = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.proxy : proxyItem;
				let countryCode = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.country : (user.user_proxy_iata || "");
				let flagEmoji = "🌐";
				if (countryCode && typeof getFlagEmojiText === 'function') {
					flagEmoji = getFlagEmojiText(countryCode);
				} else if (proxyStr && proxyFlagCache[proxyStr] && typeof getFlagEmojiText === 'function') {
					flagEmoji = getFlagEmojiText(proxyFlagCache[proxyStr]);
				}
				const currentDynPath = encodeURIComponent(rawPath + ((proxyItem !== null && proxyItem !== "") ? "/" + getLocationPathSegment(countryCode, locIdx) : inlineProxySegment) + edSuffix);
				resolvedProxies.push({ flagEmoji, currentDynPath });
			}
			const userConnType = String(user.connection_type || 'vless').toLowerCase();
			const enableVless = userConnType.includes('vless') || userConnType === 'vl' + 'e' + 'ss' || (!userConnType.includes('trojan'));
			const enableTrojan = userConnType.includes('trojan');
			ips.forEach((ip) => {
				ports.forEach((portStr) => {
					resolvedProxies.forEach((proxy) => {
						const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
						const tlsVal = isTlsPort ? "tls" : "none";
						let userFrag = "";
						if (user.frag_len && user.frag_int) userFrag += "&fragment=" + encodeURIComponent(user.frag_len + "," + user.frag_int + (isTlsPort ? ",tlshello" : ""));
						if (user.advanced_frag) userFrag += "&fm=" + encodeURIComponent(user.advanced_frag);
						if (isTlsPort && user.cipher_suites) userFrag += "&cs=" + encodeURIComponent(user.cipher_suites);
						if (user.tls_mask) userFrag += "&mask=" + encodeURIComponent(user.tls_mask);
						
						const tlsParams = isTlsPort ? ("&insecure=0&fp=" + fp + "&allowInsecure=0&sni=" + host) : "";

						if (enableVless) {
							const remark = proxy.flagEmoji;
							links.push('vle' + 'ss://' + (user.uuid || '') + '@' + ip + ':' + portStr + '?path=' + proxy.currentDynPath + '&security=' + tlsVal + '&encryption=none&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(remark));
						}
						if (enableTrojan) {
							const trojanRemark = proxy.flagEmoji;
							links.push('trojan://' + (user.uuid || '') + '@' + ip + ':' + portStr + '?path=' + proxy.currentDynPath + '&security=' + tlsVal + '&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(trojanRemark));
						}
					});
				});
			});
			const otherCleanIps = Array.isArray(window.OTHER_CLEAN_IPS) ? window.OTHER_CLEAN_IPS : [];
			if (otherCleanIps.length > 0) {
				const otherPortStr = ports[0] || '443';
				const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(otherPortStr);
				const tlsVal = isTlsPort ? "tls" : "none";
				let userFrag = "";
				if (user.frag_len && user.frag_int) userFrag += "&fragment=" + encodeURIComponent(user.frag_len + "," + user.frag_int + (isTlsPort ? ",tlshello" : ""));
				if (user.advanced_frag) userFrag += "&fm=" + encodeURIComponent(user.advanced_frag);
				if (isTlsPort && user.cipher_suites) userFrag += "&cs=" + encodeURIComponent(user.cipher_suites);
				if (user.tls_mask) userFrag += "&mask=" + encodeURIComponent(user.tls_mask);
				const tlsParams = isTlsPort ? ("&insecure=0&fp=" + fp + "&allowInsecure=0&sni=" + host) : "";
				const otherDynPath = encodeURIComponent(rawPath + inlineProxySegment + edSuffix);
				otherCleanIps.forEach(function(otherIp, otherIdx) {
					const remark = "🇩🇪 " + String(otherIdx + 1).padStart(2, "0");
					if (enableVless) {
						links.push('vle' + 'ss://' + (user.uuid || '') + '@' + otherIp + ':' + otherPortStr + '?path=' + otherDynPath + '&security=' + tlsVal + '&encryption=none&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(remark));
					}
					if (enableTrojan) {
						links.push('trojan://' + (user.uuid || '') + '@' + otherIp + ':' + otherPortStr + '?path=' + otherDynPath + '&security=' + tlsVal + '&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(remark));
					}
				});
			}
			return links.join('\\n');
		}
		function getSubLink(username) {
			return window.location.origin + '/notes/' + encodeURIComponent(username);
		}
		function getSingboxLink(username) {
			return window.location.origin + '/bundle/' + encodeURIComponent(username);
		}
		function getStatusLink(username) {
			return window.location.origin + '/profile/' + encodeURIComponent(username);
		}
		function copySubLink(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			navigator.clipboard.writeText(getSubLink(username)).then(() => {
				alert('✅ لینک ساب متنی با موفقیت کپی شد!');
			}).catch(() => {
				alert('خطا در کپی کردن لینک ساب!');
			});
		}
		function copySingboxLink(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			navigator.clipboard.writeText(getSingboxLink(username)).then(() => {
				alert('✅ لینک ساب Sing-box با موفقیت کپی شد!');
			}).catch(() => {
				alert('خطا در کپی کردن لینک ساب!');
			});
		}
		function toggleQrModal(show, text) {
			const container = document.getElementById('qrcode-container');
			if (show) {
				container.innerHTML = '';
				const isDark = document.documentElement.classList.contains('dark');
				const qrCode = new QRCodeStyling({
					width: 220,
					height: 220,
					data: text,
					margin: 5,
					qrOptions: { errorCorrectionLevel: 'M' },
					dotsOptions: {
						color: isDark ? "#bfdbfe" : "#1e3a8a",
						type: "rounded"
					},
					backgroundOptions: {
						color: isDark ? "#0f172a" : "#ffffff"
					},
					cornersSquareOptions: {
						color: isDark ? "#60a5fa" : "#1e40af",
						type: "extra-rounded"
					},
					cornersDotOptions: {
						color: isDark ? "#60a5fa" : "#1d4ed8",
						type: "dot"
					}
				});
				qrCode.append(container);
			}
			setModalState('qr-modal', show);
		}
		function downloadQrCode() {
			const container = document.getElementById('qrcode-container');
			if (!container) return;
			const canvas = container.querySelector('canvas');
			const img = container.querySelector('img');
			let dataUrl = '';
			if (canvas) {
				dataUrl = canvas.toDataURL("image/png");
			} else if (img && img.src) {
				dataUrl = img.src;
			}
			if (!dataUrl) {
				alert('⚠️ تصویر QR برای دانلود یافت نشد!');
				return;
			}
			const downloadAnchor = document.createElement('a');
			downloadAnchor.href = dataUrl;
			downloadAnchor.download = "zeus_qrcode_" + Date.now() + ".png";
			document.body.appendChild(downloadAnchor);
			downloadAnchor.click();
			downloadAnchor.remove();
		}
		function showSubQr(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			const link = getSubLink(username);
			toggleQrModal(true, link);
		}
		function showSingboxQr(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			const link = getSingboxLink(username);
			toggleQrModal(true, link);
		}
		function openStatusLink(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			const link = getStatusLink(username);
			window.open(link, '_blank');
		}
		function copyConfig(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			const link = getvIeesLink(username);
			if (!link) return;
			navigator.clipboard.writeText(link).then(() => {
				alert('✅ کـانفـیگ با موفقیت کپی شد!');
			}).catch(() => {
				alert('خطا در کپی کردن کـانفـیگ!');
			});
		}
function populateUserFormFields(user) {
	const userConnType = String(user.connection_type || 'vless').toLowerCase();
	const vlessCb = document.getElementById('input-proto-vless');
	const trojanCb = document.getElementById('input-proto-trojan');
	if (vlessCb) vlessCb.checked = userConnType.includes('vless') || userConnType === 'vl' + 'e' + 'ss' || (!userConnType.includes('trojan'));
	if (trojanCb) trojanCb.checked = userConnType.includes('trojan');
	document.getElementById('input-limit').value = user.limit_gb || '';
	document.getElementById('input-expiry').value = user.expiry_days || '';
	const startOnFirstConnectCheck = document.getElementById('input-start-on-first-connect');
	if (startOnFirstConnectCheck) startOnFirstConnectCheck.checked = (user.start_on_first_connect === 1);
	document.getElementById('input-req-limit').value = user.limit_req || '';
	const ipLimitInputEdit = document.getElementById('input-ip-limit');
	if (ipLimitInputEdit) ipLimitInputEdit.placeholder = 'نامحدود';
	document.getElementById('input-ip-limit').value = (user.ip_limit !== undefined && user.ip_limit !== null) ? user.ip_limit : (user.max_connections || '');
	document.getElementById('input-ips').value = user.ips || '';
	document.getElementById('fingerprint-select').value = user.fingerprint || 'chrome';
	const autoRotateIpToggle = document.getElementById('input-auto-rotate-ip-toggle');
	if (autoRotateIpToggle) autoRotateIpToggle.checked = (user.auto_rotate_ip === 1);
	document.getElementById('hidden-rotate-time').value = user.rotate_time || '';
	document.getElementById('hidden-ip-operator').value = user.ip_operator || 'all';
	document.getElementById('hidden-ip-count').value = user.ip_count || '999999';
	document.getElementById('input-block-porn').checked = (user.block_porn === 1);
	document.getElementById('input-block-ads').checked = (user.block_ads === 1);
	const fragLenInput = document.getElementById('input-frag-len');
	if (fragLenInput) fragLenInput.value = user.frag_len || '200-3000';
	const fragIntInput = document.getElementById('input-frag-int');
	if (fragIntInput) fragIntInput.value = user.frag_int || '1-2';
	document.querySelectorAll('.frag-preset-card').forEach(card => card.classList.remove('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40'));
	if (user.frag_len === '10-30' && user.frag_int === '2-5') { const b = document.querySelector('button[onclick*="mci"]'); if(b) b.classList.add('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40'); }
	else if (user.frag_len === '100-200' && user.frag_int === '5-10') { const b = document.querySelector('button[onclick*="irancell"]'); if(b) b.classList.add('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40'); }
	else if (user.frag_len === '50-100' && user.frag_int === '2-5') { const b = document.querySelector('button[onclick*="rightel"]'); if(b) b.classList.add('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40'); }
	else if (user.frag_len === '50-200' && user.frag_int === '1-3') { const b = document.querySelector('button[onclick*="tci"]'); if(b) b.classList.add('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40'); }
	else if (user.frag_len === '200-3000' && user.frag_int === '1-2') { const b = document.querySelector('button[onclick*="gaming"]'); if(b) b.classList.add('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40'); }
	const hasFrag = Boolean(user.frag_len || user.frag_int);
	const fragToggle = document.getElementById('input-frag-toggle');
	if (fragToggle) fragToggle.checked = hasFrag;
	if (typeof window.toggleFragInputs === 'function') window.toggleFragInputs(hasFrag);
	const edUserOn = Number(user.early_data_enabled) === 1;
	const edUserSize = parseInt(user.early_data_size, 10);
	const edToggleEdit = document.getElementById('input-early-data-toggle');
	if (edToggleEdit) edToggleEdit.checked = edUserOn;
	const edSizeEdit = document.getElementById('input-early-data-size');
	if (edSizeEdit) edSizeEdit.value = String((edUserSize >= 1 && edUserSize <= 8192) ? edUserSize : 2560);
	if (typeof window.toggleEarlyDataInputs === 'function') window.toggleEarlyDataInputs(edUserOn);
	const advFragInput = document.getElementById('input-advanced-frag');
	if (advFragInput) advFragInput.value = user.advanced_frag || '';
	const csInput = document.getElementById('input-cipher-suites');
	if (csInput) csInput.value = user.cipher_suites || '';
	const maskInput = document.getElementById('input-tls-mask');
	if (maskInput) maskInput.value = user.tls_mask || '';
	const hasAdvSettings = Boolean(user.advanced_frag || user.cipher_suites || user.tls_mask);
	const advSettingsToggle = document.getElementById('input-advanced-settings-toggle');
	if (advSettingsToggle) advSettingsToggle.checked = hasAdvSettings;
	if (typeof window.toggleAdvancedSettingsInputs === 'function') window.toggleAdvancedSettingsInputs(hasAdvSettings);
	const autoRotateUserProxyCheck = document.getElementById('input-auto-rotate-user-proxy');
	if (autoRotateUserProxyCheck) autoRotateUserProxyCheck.checked = (user.auto_rotate_user_proxy === 1);
	const enableDirectCheck = document.getElementById('input-enable-direct');
	if (enableDirectCheck) enableDirectCheck.checked = (user.enable_direct !== 0);
	const hasAutoReset = Boolean((user.auto_reset_vol_days && user.auto_reset_vol_days > 0) || (user.auto_reset_req_days && user.auto_reset_req_days > 0));
	const autoResetToggle = document.getElementById('input-auto-reset-toggle');
	if (autoResetToggle) autoResetToggle.checked = hasAutoReset;
	document.getElementById('input-auto-reset-vol').value = hasAutoReset && user.auto_reset_vol_days > 0 ? user.auto_reset_vol_days : '';
	document.getElementById('input-auto-reset-req').value = hasAutoReset && user.auto_reset_req_days > 0 ? user.auto_reset_req_days : '';
	window.toggleAutoResetInputs(hasAutoReset);
	
	const userPorts = String(user.port || '').split(',').map(p => p.trim());
	const predefinedPorts = [...tlsPorts, ...nonTlsPorts];
	const customPorts = userPorts.filter(p => !predefinedPorts.includes(p) && p !== '');
	document.querySelectorAll('input[name="ports"]').forEach(cb => {
		cb.checked = userPorts.includes(cb.value);
	});
	const customPortInput = document.getElementById('input-custom-ports');
	if (customPortInput) customPortInput.value = customPorts.join(' ');
	const userProxyToggle = document.getElementById('user-proxy-mode-toggle');
	const targetProxy = user.user_socks5 || user.user_proxy_ip;
	window.proxyFieldsData = [""];
	window.activeProxyIndex = 0;
	if (user.user_socks5) {
		if (userProxyToggle) userProxyToggle.checked = true;
		if (typeof window.toggleUserProxyMode === 'function') window.toggleUserProxyMode(true);
		try {
			if (user.user_socks5.trim().startsWith("[")) {
				const arr = JSON.parse(user.user_socks5);
				window.proxyFieldsData = arr.map(x => typeof x === "object" && x !== null ? x.proxy : x);
				// کشوری که همراه هر پروکسی توی رکورد کاربر ذخیره شده رو توی proxy_flag_cache_v2
				// می‌ریزیم تا موقع باز کردن/ویرایش کاربر، درست مثل همه‌ی جاهای دیگه، پرچم نشون
				// داده بشه نه خودِ آدرس خام پروکسی (قبلاً این کشور دور ریخته می‌شد).
				try {
					let cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
					let changed = false;
					arr.forEach(x => {
						if (x && typeof x === 'object' && x.proxy && x.country) {
							cache[x.proxy] = String(x.country).toUpperCase();
							changed = true;
						}
					});
					if (changed) localStorage.setItem('proxy_flag_cache_v2', JSON.stringify(cache));
				} catch(e) {}
			} else {
				window.proxyFieldsData = [user.user_socks5];
				if (user.user_proxy_iata) {
					try {
						let cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
						cache[user.user_socks5] = String(user.user_proxy_iata).toUpperCase();
						localStorage.setItem('proxy_flag_cache_v2', JSON.stringify(cache));
					} catch(e) {}
				}
			}
		} catch(e) {
			window.proxyFieldsData = [user.user_socks5];
		}
	} else {
		if (userProxyToggle) userProxyToggle.checked = false;
		if (typeof window.toggleUserProxyMode === 'function') window.toggleUserProxyMode(false);
	}
	if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
}
function editUser(encodedUsername) {
	const username = decodeURIComponent(encodedUsername);
	const user = window.allUsers.find(u => u.username === username);
	if (!user) {
		alert('کاربر یافت نشد!');
		return;
	}
	isEditMode = true;
	editingUsername = username;
	document.getElementById('modal-title').innerText = 'ویرایش کاربر: ' + username;
	updateSubmitBtnState('ذخیره تغییرات');
	const nameInput = document.getElementById('input-name');
	nameInput.value = username;
	nameInput.disabled = false;
	const uuidInputEdit = document.getElementById('input-uuid');
	if (uuidInputEdit) uuidInputEdit.value = user.uuid || '';
	populateUserFormFields(user);
	if (typeof window.syncResetUserUi === 'function') window.syncResetUserUi(true);
	toggleModal(true);
}
		async function deleteUser(encodedUsername) {
			const username = decodeURIComponent(encodedUsername);
			if (await customConfirm('آیا از حذف کاربر ' + username + ' مطمئن هستید؟')) {
				try {
					const response = await fetch('/api/users/' + encodeURIComponent(username), { method: 'DELETE' });
					if (response.ok) {
						alert('✅ کاربر با موفقیت حذف شد.');
						window.selectedUsernames.delete(username);
						await loadUsers(true);
					} else {
						const errData = await response.json();
						alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
					}
				} catch (err) {
					alert('خطا در برقراری ارتباط با سرور');
				}
			}
		}
		function getFlagEmoji(countryCode) {
			if (!countryCode) return '<span class="zeus-flag-globe">🌐</span>';
			const cc = String(countryCode).toLowerCase().replace(/[^a-z]/g, '');
			if (cc.length !== 2) return '<span class="zeus-flag-globe">🌐</span>';
			return '<span class="fi fi-' + cc + ' zeus-flag" title="' + cc.toUpperCase() + '"></span>';
		}
		function getFlagEmojiText(countryCode) {
			if (!countryCode) return '🌐';
			const cc = String(countryCode).toUpperCase().replace(/[^A-Z]/g, '');
			if (cc.length !== 2) return '🌐';
			try {
				return String.fromCodePoint(...cc.split('').map(char => 127397 + char.charCodeAt(0)));
			} catch (e) {
				return '🌐';
			}
		}
window.DEFAULT_GLOBAL_CLEAN_IP = '104.20.25.138';
window.GLOBAL_CLEAN_IP = window.DEFAULT_GLOBAL_CLEAN_IP;
window.loadGlobalCleanIpSetting = async function() {
	let value = window.DEFAULT_GLOBAL_CLEAN_IP;
	try {
		const res = await fetch('/api/settings/bulk');
		const data = await res.json();
		if (data && typeof data.global_clean_ip === 'string' && data.global_clean_ip.trim() !== '') {
			value = data.global_clean_ip.trim();
		}
	} catch (e) {}
	window.GLOBAL_CLEAN_IP = value;
	const input = document.getElementById('global-clean-ip-input');
	if (input) input.value = value;
	return value;
};
window.DEFAULT_GLOBAL_REQ_LIMIT = 75000;
window.GLOBAL_REQ_LIMIT = window.DEFAULT_GLOBAL_REQ_LIMIT;
window.loadGlobalReqLimitSetting = async function() {
	let value = window.DEFAULT_GLOBAL_REQ_LIMIT;
	try {
		const res = await fetch('/api/settings/bulk');
		const data = await res.json();
		if (data && data.global_req_limit !== undefined && data.global_req_limit !== null && String(data.global_req_limit).trim() !== '') {
			const parsed = parseInt(data.global_req_limit);
			if (!isNaN(parsed) && parsed >= 0) value = parsed;
		}
	} catch (e) {}
	window.GLOBAL_REQ_LIMIT = value;
	const input = document.getElementById('global-req-limit-input');
	if (input) input.value = value;
	return value;
};
window.DEFAULT_USER_LIMIT = 2;
window.USER_LIMIT = window.DEFAULT_USER_LIMIT;
window.loadUserLimitSetting = async function() {
	let value = window.DEFAULT_USER_LIMIT;
	try {
		const res = await fetch('/api/settings/bulk');
		const data = await res.json();
		if (data && data.user_limit !== undefined && data.user_limit !== null && String(data.user_limit).trim() !== '') {
			const parsed = parseInt(data.user_limit);
			if (!isNaN(parsed) && parsed >= 0) value = parsed;
		}
	} catch (e) {}
	window.USER_LIMIT = value;
	const input = document.getElementById('user-limit-input');
	if (input) input.value = value;
	return value;
};
window.DEFAULT_DEVICE_WARNING_THRESHOLD = 4;
window.DEVICE_WARNING_THRESHOLD = window.DEFAULT_DEVICE_WARNING_THRESHOLD;
window.loadDeviceWarningThresholdSetting = async function() {
	let value = window.DEFAULT_DEVICE_WARNING_THRESHOLD;
	try {
		const res = await fetch('/api/settings/bulk');
		const data = await res.json();
		if (data && data.device_warning_threshold !== undefined && data.device_warning_threshold !== null && String(data.device_warning_threshold).trim() !== '') {
			const parsed = parseInt(data.device_warning_threshold);
			if (!isNaN(parsed) && parsed >= 0) value = parsed;
		}
	} catch (e) {}
	window.DEVICE_WARNING_THRESHOLD = value;
	const input = document.getElementById('device-warning-threshold-input');
	if (input) input.value = value;
	return value;
};
window.OTHER_CLEAN_IPS = [];
window.DEFAULT_OTHER_CLEAN_IPS = '104.26.1.116\\n104.21.122.162\\n185.162.228.105\\n185.148.105.218\\n104.18.39.219\\n185.162.230.76';
window.loadOtherCleanIpsSetting = async function() {
	let raw = window.DEFAULT_OTHER_CLEAN_IPS;
	try {
		const res = await fetch('/api/settings/bulk');
		const data = await res.json();
		if (data && typeof data.other_clean_ips === 'string') {
			raw = data.other_clean_ips;
		}
	} catch (e) {}
	window.OTHER_CLEAN_IPS = raw.split('\\n').map(function(ip) { return ip.trim(); }).filter(function(ip) { return ip.length > 0; });
	const input = document.getElementById('other-clean-ips-input');
	if (input) input.value = raw;
	return window.OTHER_CLEAN_IPS;
};
window.PINNED_LOCATIONS_DEFAULT_FALLBACK = ["UZ", "KZ", "TR", "LY", "NL", "AL", "EE", "BG", "LV", "SE", "NO", "GB", "US", "ES", "BE"];
window.PINNED_LOCATIONS_CACHE = window.PINNED_LOCATIONS_DEFAULT_FALLBACK.slice();
window.ALL_ISO_COUNTRIES_LIST = [
	"AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ", "BA",
	"BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV",
	"BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU",
	"CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES",
	"ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM",
	"GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE",
	"IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM",
	"KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY",
	"MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT",
	"MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU",
	"NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA",
	"RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM",
	"SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL",
	"TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE",
	"VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"
];
window.loadPinnedLocationsSetting = async function() {
	let list = window.PINNED_LOCATIONS_DEFAULT_FALLBACK.slice();
	try {
		const res = await fetch('/api/settings/bulk');
		const data = await res.json();
		if (data && typeof data.pinned_locations === 'string' && data.pinned_locations.trim() !== '') {
			const parsed = JSON.parse(data.pinned_locations);
			// لیست خالیِ ذخیره‌شده یعنی ادمین عمداً همه را برداشته؛ به ۱۵ کشور پیش‌فرض برنمی‌گردد.
			if (Array.isArray(parsed)) list = parsed;
		}
	} catch (e) {}
	window.PINNED_LOCATIONS_CACHE = list;
	window.renderPinnedLocationsList();
	return list;
};
window.renderPinnedLocationsList = function() {
	const container = document.getElementById('pinned-locations-list');
	const countEl = document.getElementById('pinned-locations-count');
	if (countEl) countEl.innerText = window.PINNED_LOCATIONS_CACHE.length + ' کشور';
	if (!container) return;
	const lastIdx = window.PINNED_LOCATIONS_CACHE.length - 1;
	// اگر لیست VIP لود شده باشد، کشور پین‌شده‌ای که فایل VIP ندارد علامت ⚠ می‌گیرد
	// (برایش پروکسی واقعی وجود ندارد و اسلاتش خالی می‌ماند).
	const vipCodes = Array.isArray(window.VIP_COUNTRY_CODES) && window.VIP_COUNTRY_CODES.length > 0 ? window.VIP_COUNTRY_CODES : null;
	container.innerHTML = window.PINNED_LOCATIONS_CACHE.map(function(cc, i) {
		const flag = typeof getFlagEmojiText === 'function' ? getFlagEmojiText(cc) : '🌐';
		const noVip = vipCodes && vipCodes.indexOf(cc) === -1;
		const warn = noVip ? ' <span title="این کشور در لیست VIP نیست و پروکسی واقعی ندارد؛ بهتر است حذفش کنید" class="text-amber-500">⚠</span>' : '';
		return '<div class="flex items-center gap-2 py-1.5 px-2 border-b border-gray-100 dark:border-zinc-800 last:border-0">' +
			'<span class="flex-1 text-xs font-bold text-gray-800 dark:text-zinc-200">' + flag + ' ' + cc + warn + '</span>' +
			'<button type="button" onclick="pinnedLocationMoveUp(' + i + ')" ' + (i === 0 ? 'disabled' : '') + ' class="p-1 rounded text-gray-500 hover:text-blue-600 disabled:opacity-30 disabled:cursor-not-allowed">▲</button>' +
			'<button type="button" onclick="pinnedLocationMoveDown(' + i + ')" ' + (i === lastIdx ? 'disabled' : '') + ' class="p-1 rounded text-gray-500 hover:text-blue-600 disabled:opacity-30 disabled:cursor-not-allowed">▼</button>' +
			'<button type="button" onclick="pinnedLocationRemove(' + i + ')" class="p-1 rounded text-red-500 hover:text-red-700">✕</button>' +
			'</div>';
	}).join('');
	if (typeof renderGlobalLocationBadges === 'function') renderGlobalLocationBadges();
};
window.pinnedLocationMoveUp = function(i) {
	const arr = window.PINNED_LOCATIONS_CACHE;
	if (i <= 0 || i >= arr.length) return;
	const tmp = arr[i - 1];
	arr[i - 1] = arr[i];
	arr[i] = tmp;
	window.renderPinnedLocationsList();
};
window.pinnedLocationMoveDown = function(i) {
	const arr = window.PINNED_LOCATIONS_CACHE;
	if (i < 0 || i >= arr.length - 1) return;
	const tmp = arr[i + 1];
	arr[i + 1] = arr[i];
	arr[i] = tmp;
	window.renderPinnedLocationsList();
};
window.pinnedLocationRemove = function(i) {
	window.PINNED_LOCATIONS_CACHE.splice(i, 1);
	window.renderPinnedLocationsList();
};
window.pinnedLocationAdd = function() {
	const select = document.getElementById('pinned-location-add-select');
	if (!select) return;
	if (!select.value) {
		// لیست VIP هنوز لود نشده یا لود نشد: با زدن «افزودن» دوباره تلاش می‌کند.
		if (select.getAttribute('data-vip-state') !== 'ok') window.populatePinnedLocationSelects(true);
		return;
	}
	const cc = select.value;
	if (window.PINNED_LOCATIONS_CACHE.indexOf(cc) === -1) {
		window.PINNED_LOCATIONS_CACHE.push(cc);
		window.renderPinnedLocationsList();
	} else {
		showToast('این کشور از قبل توی لیست پین‌شده‌هاست.');
	}
};
window.savePinnedLocations = async function() {
	const btn = document.getElementById('save-pinned-locations-btn');
	if (btn) { btn.disabled = true; btn.innerText = 'در حال ذخیره...'; }
	try {
		const saveRes = await fetch('/api/settings/bulk', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ settings: { pinned_locations: JSON.stringify(window.PINNED_LOCATIONS_CACHE) } })
		});
		let saveData = null;
		try { saveData = await saveRes.json(); } catch (e) {}
		if (saveData && saveData.users_updated > 0) {
			showToast('✅ لیست ذخیره شد؛ کشور(های) حذف‌شده از کانفیگ ' + saveData.users_updated + ' کاربر پاک شد. در حال اعمال روی کاربرها...');
		} else {
			showToast('✅ لیست ذخیره شد؛ در حال اعمال روی کاربرها...');
		}
		await window.applyPinnedLocationsToAllUsers(btn);
	} catch (e) {
		showToast('❌ ذخیره‌سازی لوکیشن‌ها ناموفق بود.');
	} finally {
		if (btn) { btn.disabled = false; btn.innerText = 'ذخیره'; }
	}
};
// این تابع، دقیقاً همون کاری که دکمه‌ی حذف‌شده‌ی "بروزرسانی لوکیشن‌ها" برای
// کاربرهای انتخاب‌شده انجام می‌داد (reset_action: "locations" - افزایشی و
// غیرمخرب، فقط کشورهای گم‌شده اضافه می‌شن) رو حالا خودکار، بعد از هر بار
// «ذخیره»‌ی تنظیمات لوکیشن‌ها، روی همه‌ی کاربرهای موجود انجام می‌ده.
window.applyPinnedLocationsToAllUsers = async function(btn) {
	try {
		const res = await fetch('/api/users?t=' + Date.now());
		if (!res.ok) throw new Error('failed to load users');
		const data = await res.json();
		const usernames = (data.users || []).map(function(u) { return u.username; }).filter(Boolean);
		if (usernames.length === 0) return;
		if (btn) btn.innerText = 'در حال اعمال به ' + usernames.length + ' کاربر...';
		let successCount = 0;
		const cappedUsernames = [];
		await Promise.all(usernames.map(async function(uname) {
			try {
				const r = await fetch('/api/users/' + encodeURIComponent(uname), {
					method: 'PUT',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ reset_action: 'locations' })
				});
				if (r.ok) {
					successCount++;
					try {
						const d = await r.json();
						if (d && d.capped) cappedUsernames.push(uname);
					} catch (e) {}
				}
			} catch (e) {}
		}));
		showToast('✅ لوکیشن‌های پین‌شده روی ' + successCount + ' کاربر اعمال شد.');
		if (cappedUsernames.length > 0) {
			alert('⚠️ این کاربرا به سقف ' + MAX_LOCATIONS_PER_USER_CLIENT + ' لوکیشن رسیدن و بعضی کشورای جدید براشون اضافه نشد (برای جا باز کردن، یه کشور قدیمی رو دستی حذف کنید): ' + cappedUsernames.join('، '));
		}
		if (typeof loadUsers === 'function') await loadUsers(true);
	} catch (e) {
		showToast('⚠️ ذخیره شد ولی اعمال خودکار لوکیشن‌ها روی کاربرها با خطا مواجه شد.');
	}
};
// لیست کشورهای VIP (همان vip-list که initVipCache() هم می‌خواند؛ اینجا فقط کدهای کشور
// لازم است، نه خود فایل پروکسی‌ها). نتیجه در window.VIP_COUNTRY_CODES می‌ماند و یک
// درخواست هم‌زمان دوباره ارسال نمی‌شود. شکست، کش نمی‌شود تا دوباره بشود امتحان کرد.
window.VIP_COUNTRY_CODES = null;
window.vipCountryCodesPromise = null;
window.loadVipCountryCodes = function(force) {
	if (!force && Array.isArray(window.VIP_COUNTRY_CODES) && window.VIP_COUNTRY_CODES.length > 0) {
		return Promise.resolve(window.VIP_COUNTRY_CODES);
	}
	if (!force && window.vipCountryCodesPromise) return window.vipCountryCodesPromise;
	const task = (async function() {
		try {
			const res = await fetchWithFallbackUI('vip-list');
			if (!res.ok) throw new Error('vip-list HTTP ' + res.status);
			const files = await res.json();
			const codes = [];
			(Array.isArray(files) ? files : []).forEach(function(f) {
				const name = typeof f === 'string' ? f : (f && f.name);
				if (!name || typeof name !== 'string' || !name.toLowerCase().endsWith('.txt')) return;
				const cc = name.slice(0, -4).trim().toUpperCase();
				if (/^[A-Z]{2}$/.test(cc) && codes.indexOf(cc) === -1) codes.push(cc);
			});
			codes.sort();
			if (codes.length > 0) window.VIP_COUNTRY_CODES = codes;
			return codes;
		} catch (e) {
			return [];
		}
	})();
	window.vipCountryCodesPromise = task;
	task.then(function(codes) {
		if (!codes || codes.length === 0) window.vipCountryCodesPromise = null;
	});
	return task;
};
window.populatePinnedLocationSelects = async function(force) {
	const select = document.getElementById('pinned-location-add-select');
	if (!select) return;
	select.setAttribute('data-vip-state', 'loading');
	select.innerHTML = '<option value="">در حال بارگذاری لیست VIP...</option>';
	const codes = await window.loadVipCountryCodes(force === true);
	select.innerHTML = '';
	if (!codes || codes.length === 0) {
		select.setAttribute('data-vip-state', 'failed');
		select.innerHTML = '<option value="">لیست VIP در دسترس نیست - «افزودن» را بزنید تا دوباره تلاش شود</option>';
		return;
	}
	select.setAttribute('data-vip-state', 'ok');
	select.innerHTML = '<option value="">یک کشور VIP انتخاب کنید...</option>';
	codes.forEach(function(cc) {
		const option = document.createElement('option');
		option.value = cc;
		const flag = typeof getFlagEmojiText === 'function' ? getFlagEmojiText(cc) : '🌐';
		option.textContent = flag + ' ' + cc;
		select.appendChild(option);
	});
	// حالا که لیست VIP معلوم شد، ⚠ کشورهای پین‌شده‌ی بدون VIP را هم به‌روز کن.
	if (typeof window.renderPinnedLocationsList === 'function') window.renderPinnedLocationsList();
};

function generateInlineProxyJunkClient(len) {
	len = len || 10;
	const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	let out = '';
	for (let i = 0; i < len; i++) out += chars.charAt(Math.floor(Math.random() * chars.length));
	return out;
}
window.buildInlineProxyIpSegment = function(ip) {
	if (!ip || typeof ip !== 'string' || !ip.trim()) return '';
	try {
		const payload = { junk: generateInlineProxyJunkClient(10), protocol: 'vl', mode: 'proxyip', panelIPs: [ip.trim()] };
		return '/' + btoa(JSON.stringify(payload)).replace(/\\+/g, '-').replace(/\\//g, '_');
	} catch (e) {
		return '';
	}
};
window.DEFAULT_INLINE_PROXY_IP = '178.105.227.210';
window.INLINE_PROXY_IP = window.DEFAULT_INLINE_PROXY_IP;
window.loadInlineProxyIpSetting = async function() {
	let value = window.DEFAULT_INLINE_PROXY_IP;
	try {
		const res = await fetch('/api/settings/bulk');
		const data = await res.json();
		if (data && typeof data.inline_proxy_ip === 'string') {
			value = data.inline_proxy_ip;
		}
	} catch (e) {}
	window.INLINE_PROXY_IP = value;
	const input = document.getElementById('inline-proxy-ip-input');
	if (input) input.value = value;
	return value;
};
window.DEFAULT_PORT_SETTING_FALLBACK = '2083';
window.DEFAULT_PORT_SETTING = window.DEFAULT_PORT_SETTING_FALLBACK;
window.loadDefaultPortSetting = async function() {
	let value = window.DEFAULT_PORT_SETTING_FALLBACK;
	try {
		const res = await fetch('/api/settings/bulk');
		const data = await res.json();
		if (data && data.default_port !== undefined && data.default_port !== null && String(data.default_port).trim() !== '') {
			const parsed = parseInt(data.default_port);
			if (!isNaN(parsed) && parsed > 0 && parsed <= 65535) value = String(parsed);
		}
	} catch (e) {}
	window.DEFAULT_PORT_SETTING = value;
	const input = document.getElementById('default-port-input');
	if (input) input.value = value;
	// چک‌باکس‌های فرم افزودن کاربر رو با مقدار واقعیِ لود شده دوباره رندر می‌کنیم
	// (renderPortCheckboxes موقع DOMContentLoaded قبل از رسیدن این fetch صدا زده
	// می‌شه و تا اون موقع فقط از پیش‌فرضِ fallback استفاده می‌کنه).
	if (typeof renderPortCheckboxes === 'function') renderPortCheckboxes();
	return value;
};
window.NEW_USER_DEFAULTS_FALLBACK = {
	new_user_fingerprint: 'ios',
	new_user_auto_reset_vol_days: '1',
	new_user_auto_reset_req_days: '1',
	new_user_auto_rotate_user_proxy: '1',
	new_user_enable_direct: '0',
	new_user_block_porn: '0',
	new_user_block_ads: '0',
	new_user_frag_len: '',
	new_user_frag_int: '',
	new_user_ip_operator: 'all',
	new_user_ip_count: '999999', // no count cap
	new_user_auto_rotate_ip: '0',
	new_user_start_on_first_connect: '0',
	new_user_connection_type: 'vless',
	new_user_early_data_enabled: '0',
	new_user_early_data_size: '2560'
};
window.NEW_USER_DEFAULTS = Object.assign({}, window.NEW_USER_DEFAULTS_FALLBACK);
window.NEW_USER_INPUT_IDS = {
	new_user_fingerprint: 'nud-fingerprint',
	new_user_auto_reset_vol_days: 'nud-auto-reset-vol',
	new_user_auto_reset_req_days: 'nud-auto-reset-req',
	new_user_auto_rotate_user_proxy: 'nud-auto-rotate-user-proxy',
	new_user_enable_direct: 'nud-enable-direct',
	new_user_block_porn: 'nud-block-porn',
	new_user_block_ads: 'nud-block-ads',
	new_user_frag_len: 'nud-frag-len',
	new_user_frag_int: 'nud-frag-int',
	new_user_ip_operator: 'nud-ip-operator',
	new_user_ip_count: 'nud-ip-count',
	new_user_auto_rotate_ip: 'nud-auto-rotate-ip',
	new_user_start_on_first_connect: 'nud-start-on-first-connect',
	new_user_connection_type: 'nud-connection-type',
	new_user_early_data_enabled: 'nud-early-data-enabled',
	new_user_early_data_size: 'nud-early-data-size'
};
window.NEW_USER_EMPTY_OK = { new_user_frag_len: true, new_user_frag_int: true };
window.fillNewUserDefaultsInputs = function() {
	Object.keys(window.NEW_USER_INPUT_IDS).forEach(function(k) {
		const el = document.getElementById(window.NEW_USER_INPUT_IDS[k]);
		if (!el) return;
		const v = window.NEW_USER_DEFAULTS[k];
		el.value = (k === 'new_user_auto_reset_vol_days' || k === 'new_user_auto_reset_req_days') && (parseInt(v) || 0) <= 0 ? '0' : v;
	});
	// چک‌باکس «اعمال روی کاربرهای موجود» هیچ‌وقت ماندگار نیست: هر بار که فرم پر می‌شود (باز شدن Settings / بعد از ذخیره) خاموش برمی‌گردد.
	const applyEdEl = document.getElementById('nud-apply-early-data-existing');
	if (applyEdEl) applyEdEl.checked = false;
};
window.loadNewUserDefaultsSetting = async function() {
	let data = null;
	try {
		const res = await fetch('/api/settings/bulk');
		if (res.ok) data = await res.json();
	} catch (e) {}
	// A failed fetch keeps what is already known (the built-in fallbacks on the very
	// first load) instead of resetting it, but the form always ends up matching it -
	// otherwise the on/off selects would show their first option and a Save would write it.
	if (data && typeof data === 'object') {
		const merged = Object.assign({}, window.NEW_USER_DEFAULTS_FALLBACK);
		Object.keys(merged).forEach(function(k) {
			if (data[k] !== undefined && data[k] !== null) {
				const v = String(data[k]).trim();
				if (v !== '' || window.NEW_USER_EMPTY_OK[k]) merged[k] = v;
			}
		});
		window.NEW_USER_DEFAULTS = merged;
	}
	window.fillNewUserDefaultsInputs();
	return window.NEW_USER_DEFAULTS;
};
window.collectNewUserDefaultsFromInputs = function() {
	const out = {};
	Object.keys(window.NEW_USER_INPUT_IDS).forEach(function(k) {
		const el = document.getElementById(window.NEW_USER_INPUT_IDS[k]);
		let v = el ? String(el.value).trim() : window.NEW_USER_DEFAULTS[k];
		if (k === 'new_user_auto_reset_vol_days' || k === 'new_user_auto_reset_req_days') {
			v = String(Math.max(0, parseInt(v) || 0));
		} else if (k === 'new_user_ip_count') {
			v = String(Math.max(1, parseInt(v) || parseInt(window.NEW_USER_DEFAULTS_FALLBACK[k])));
		} else if (k === 'new_user_early_data_size') {
			v = String(Math.min(8192, Math.max(1, parseInt(v) || parseInt(window.NEW_USER_DEFAULTS_FALLBACK[k]))));
		} else if (v === '' && !window.NEW_USER_EMPTY_OK[k]) {
			v = window.NEW_USER_DEFAULTS_FALLBACK[k];
		}
		out[k] = v;
	});
	return out;
};
window.getNewUserDefaultsTyped = function() {
	const d = window.NEW_USER_DEFAULTS;
	const toInt = function(v, f) { const n = parseInt(v); return isNaN(n) ? f : n; };
	const ct = String(d.new_user_connection_type || 'vless');
	let protocols = ct.split(',').map(function(x) { return x.trim(); }).filter(function(x) { return x === 'vless' || x === 'trojan'; });
	if (protocols.length === 0) protocols = ['vless'];
	return {
		fingerprint: d.new_user_fingerprint || 'ios',
		auto_reset_vol_days: Math.max(0, toInt(d.new_user_auto_reset_vol_days, 0)),
		auto_reset_req_days: Math.max(0, toInt(d.new_user_auto_reset_req_days, 0)),
		auto_rotate_user_proxy: d.new_user_auto_rotate_user_proxy === '1',
		enable_direct: d.new_user_enable_direct === '1',
		block_porn: d.new_user_block_porn === '1',
		block_ads: d.new_user_block_ads === '1',
		frag_len: d.new_user_frag_len || '',
		frag_int: d.new_user_frag_int || '',
		ip_operator: d.new_user_ip_operator || 'all',
		ip_count: Math.max(1, toInt(d.new_user_ip_count, 15)),
		auto_rotate_ip: d.new_user_auto_rotate_ip === '1',
		start_on_first_connect: d.new_user_start_on_first_connect === '1',
		early_data_enabled: d.new_user_early_data_enabled === '1',
		early_data_size: (function() { const n = parseInt(d.new_user_early_data_size, 10); return (n >= 1 && n <= 8192) ? n : 2560; })(),
		connection_type: protocols.join(','),
		protocols: protocols
	};
};
window.generateMasterKey = async function() {
	if (!confirm('یک کلید مادر جدید ساخته می‌شود و کلید قبلی (اگه وجود داشت) بلافاصله از کار می‌افتد. ادامه می‌دی؟')) return;
	const btn = document.getElementById('generate-master-key-btn');
	if (btn) btn.disabled = true;
	try {
		const bytes = crypto.getRandomValues(new Uint8Array(32));
		const secret = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
		await fetch('/api/settings/bulk', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ settings: { master_api_key: secret } })
		});
		showToast('✅ کلید مادر جدید ساخته شد.');
		prompt('کلید مادر جدید — انتخاب کن و Ctrl+C بزن، بعد Enter یا Cancel (این کلید دیگه هیچ‌جا نمایش داده نمی‌شه):', secret);
	} catch (e) {
		showToast('❌ ساخت کلید مادر ناموفق بود.');
	} finally {
		if (btn) btn.disabled = false;
	}
};
window.fillPatternihaValues = function() {
	const fragInput = document.getElementById('input-advanced-frag');
	const csInput = document.getElementById('input-cipher-suites');
	if (fragInput) {
		fragInput.value = '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["5", "94", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["109", "1"], "delays": ["1"], "maxSplit": "355"}}]}';
	}
	if (csInput) {
		csInput.value = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256';
	}
	showToast('✅ مقادیر پیش‌فرض Patterniha با موفقیت اعمال شد.');
};
window.saveSettings = async function() {
	const cleanIpInput = document.getElementById('global-clean-ip-input');
	const reqLimitInput = document.getElementById('global-req-limit-input');
	const userLimitInput = document.getElementById('user-limit-input');
	const deviceWarningThresholdInput = document.getElementById('device-warning-threshold-input');
	const otherIpsInput = document.getElementById('other-clean-ips-input');
	const proxyIpInput = document.getElementById('inline-proxy-ip-input');
	const defaultPortInput = document.getElementById('default-port-input');

	const cleanIpVal = (cleanIpInput && cleanIpInput.value.trim()) ? cleanIpInput.value.trim() : window.DEFAULT_GLOBAL_CLEAN_IP;
	const reqLimitParsed = reqLimitInput ? parseInt(reqLimitInput.value) : NaN;
	const reqLimitVal = (!isNaN(reqLimitParsed) && reqLimitParsed >= 0) ? reqLimitParsed : window.DEFAULT_GLOBAL_REQ_LIMIT;
	const userLimitParsed = userLimitInput ? parseInt(userLimitInput.value) : NaN;
	const userLimitVal = (!isNaN(userLimitParsed) && userLimitParsed >= 0) ? userLimitParsed : window.DEFAULT_USER_LIMIT;
	const deviceWarningThresholdParsed = deviceWarningThresholdInput ? parseInt(deviceWarningThresholdInput.value) : NaN;
	const deviceWarningThresholdVal = (!isNaN(deviceWarningThresholdParsed) && deviceWarningThresholdParsed >= 0) ? deviceWarningThresholdParsed : window.DEFAULT_DEVICE_WARNING_THRESHOLD;
	const otherIpsRawVal = (otherIpsInput && otherIpsInput.value) ? otherIpsInput.value : '';
	const otherIpsParsed = otherIpsRawVal.split('\\n').map(function(ip) { return ip.trim(); }).filter(function(ip) { return ip.length > 0; });
	const otherIpsVal = otherIpsParsed.join('\\n');
	const proxyIpVal = (proxyIpInput && proxyIpInput.value.trim()) ? proxyIpInput.value.trim() : '';
	const defaultPortParsed = defaultPortInput ? parseInt(defaultPortInput.value) : NaN;
	const defaultPortVal = (!isNaN(defaultPortParsed) && defaultPortParsed > 0 && defaultPortParsed <= 65535) ? String(defaultPortParsed) : window.DEFAULT_PORT_SETTING_FALLBACK;
	const nudSettings = window.collectNewUserDefaultsFromInputs();
	const applyEarlyDataEl = document.getElementById('nud-apply-early-data-existing');
	const applyEarlyData = !!(applyEarlyDataEl && applyEarlyDataEl.checked);

	const buttons = [document.getElementById('save-settings-btn'), document.getElementById('save-settings-fab-btn')].filter(Boolean);
	buttons.forEach(function(b) { b.disabled = true; });

	try {
		const saveRes = await fetch('/api/settings/bulk', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				settings: Object.assign({
					global_clean_ip: cleanIpVal,
					global_req_limit: reqLimitVal,
					user_limit: userLimitVal,
					device_warning_threshold: deviceWarningThresholdVal,
					other_clean_ips: otherIpsVal,
					inline_proxy_ip: proxyIpVal,
					default_port: defaultPortVal
				}, nudSettings),
				apply_early_data_to_existing_users: applyEarlyData
			})
		});
		let saveData = null;
		try { saveData = await saveRes.json(); } catch (e) {}
		window.GLOBAL_CLEAN_IP = cleanIpVal;
		window.GLOBAL_REQ_LIMIT = reqLimitVal;
		window.USER_LIMIT = userLimitVal;
		window.DEVICE_WARNING_THRESHOLD = deviceWarningThresholdVal;
		window.OTHER_CLEAN_IPS = otherIpsParsed;
		window.INLINE_PROXY_IP = proxyIpVal;
		window.DEFAULT_PORT_SETTING = defaultPortVal;
		window.NEW_USER_DEFAULTS = Object.assign({}, window.NEW_USER_DEFAULTS, nudSettings);
		window.fillNewUserDefaultsInputs();
		if (cleanIpInput) cleanIpInput.value = cleanIpVal;
		if (reqLimitInput) reqLimitInput.value = reqLimitVal;
		if (userLimitInput) userLimitInput.value = userLimitVal;
		if (deviceWarningThresholdInput) deviceWarningThresholdInput.value = deviceWarningThresholdVal;
		if (otherIpsInput) otherIpsInput.value = otherIpsVal;
		if (proxyIpInput) proxyIpInput.value = proxyIpVal;
		if (defaultPortInput) defaultPortInput.value = defaultPortVal;
		if (typeof renderPortCheckboxes === 'function') renderPortCheckboxes();
		showToast('✅ تنظیمات ذخیره شد؛ پورت همه‌ی کاربرها روی ' + defaultPortVal + ' و محدودیت کاربر روی ' + userLimitVal + ' ست شد.');
		if (applyEarlyData) {
			if (saveData && saveData.early_data_applied) {
				showToast('✅ Early Data روی همه‌ی کاربرهای موجود هم اعمال شد.');
			} else {
				showToast('⚠️ تنظیمات ذخیره شد ولی اعمال Early Data روی کاربرهای موجود انجام نشد (نسخه‌ی پنل قدیمیه یا مقدار نامعتبره).', 'error');
			}
		}
		toggleSettingsModal(false);
		if (typeof loadUsers === 'function') await loadUsers(true);
	} catch (e) {
		showToast('❌ ذخیره‌سازی تنظیمات ناموفق بود.');
	} finally {
		buttons.forEach(function(b) { b.disabled = false; });
	}
};
window.syncVipProxies = async function() {
	const btn = document.getElementById('sync-vip-proxies-btn');
	const resultEl = document.getElementById('vip-sync-result');
	const originalLabel = 'دریافت کامل لیست پروکسی‌های VIP (همه‌ی کشورها)';
	if (btn) { btn.disabled = true; btn.innerText = 'در حال دریافت از مخزن...'; }
	if (resultEl) resultEl.innerText = '';
	try {
		const res = await fetch('/api/settings/sync-vip-proxies', { method: 'POST' });
		const data = await res.json();
		if (!res.ok || data.error) throw new Error(data.error || 'خطای نامشخص');
		if (resultEl) resultEl.innerText = '✅ ' + data.totalCountries + ' کشور - مجموعاً ' + data.totalProxies + ' پروکسی VIP دریافت و در سرور کش شد.';
		showToast('✅ مخزن VIP به‌روزرسانی شد (' + data.totalCountries + ' کشور).');
		// کش تازه شد؛ طبق درخواست، پاپ‌آپ لیست کش‌شده رو خودکار باز می‌کنیم.
		showVipProxiesCache();
	} catch (e) {
		if (resultEl) resultEl.innerText = '❌ ' + (e.message || 'دریافت مخزن VIP ناموفق بود.');
		showToast('❌ دریافت مخزن VIP ناموفق بود.', 'error');
	} finally {
		if (btn) { btn.disabled = false; btn.innerText = originalLabel; }
	}
};
// --- پاپ‌آپ «مشاهده لیست کش‌شده»: هر بار که باز می‌شود، وضعیت فعلی REPO_FILE_CACHE (سمت سرور) را
// از GET /api/settings/sync-vip-proxies می‌خواند و به تفکیک کشور (آکاردئون قابل باز/بسته‌شدن) نشان
// می‌دهد. با کلیک روی «دریافت کامل لیست» هم خودکار باز می‌شود (بالا).
let VIP_CACHE_DATA = {};
function toggleVipProxiesCacheModal(show) { setModalState('vip-proxies-cache-modal', show); }
window.showVipProxiesCache = async function() {
	toggleVipProxiesCacheModal(true);
	const listEl = document.getElementById('vip-cache-list');
	if (listEl) listEl.innerHTML = '<p class="text-xs text-gray-400 dark:text-zinc-500 text-center py-6">در حال بارگذاری...</p>';
	try {
		const res = await fetch('/api/settings/sync-vip-proxies', { method: 'GET' });
		const data = await res.json();
		if (!res.ok || data.error) throw new Error(data.error || 'خطای نامشخص');
		VIP_CACHE_DATA = data.perCountry || {};
		renderVipProxiesCache();
	} catch (e) {
		if (listEl) listEl.innerHTML = '<p class="text-xs text-red-500 text-center py-6">❌ ' + (e.message || 'خطا در خواندن کش') + '</p>';
	}
};
function escVipCacheText(s) {
	return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function renderVipProxiesCache() {
	const listEl = document.getElementById('vip-cache-list');
	const badgeEl = document.getElementById('vip-cache-total-badge');
	if (!listEl) return;
	const filterInput = document.getElementById('vip-cache-filter-input');
	const filterVal = filterInput ? filterInput.value.trim().toUpperCase() : '';
	const countries = Object.keys(VIP_CACHE_DATA).sort();
	const filtered = filterVal ? countries.filter(function(cc) { return cc.indexOf(filterVal) !== -1; }) : countries;
	const totalProxies = countries.reduce(function(sum, cc) { return sum + (VIP_CACHE_DATA[cc] || []).length; }, 0);
	if (badgeEl) badgeEl.innerText = countries.length ? ('(' + countries.length + ' کشور - ' + totalProxies + ' پروکسی)') : '';
	if (countries.length === 0) {
		listEl.innerHTML = '<p class="text-xs text-gray-400 dark:text-zinc-500 text-center py-6">چیزی کش نشده. اول از دکمه‌ی «دریافت کامل لیست پروکسی‌های VIP» استفاده کنید.</p>';
		return;
	}
	if (filtered.length === 0) {
		listEl.innerHTML = '<p class="text-xs text-gray-400 dark:text-zinc-500 text-center py-6">نتیجه‌ای برای این فیلتر نیست.</p>';
		return;
	}
	listEl.innerHTML = filtered.map(function(cc) {
		const proxies = VIP_CACHE_DATA[cc] || [];
		const flag = typeof getFlagEmoji === 'function' ? getFlagEmoji(cc) : '🌐';
		return '<div class="border border-gray-200 dark:border-amoled-border rounded-md overflow-hidden">' +
			'<button type="button" onclick="toggleVipCacheCountry(\\'' + cc + '\\')" class="w-full flex items-center justify-between px-3 py-2 bg-gray-50 dark:bg-zinc-900/40 hover:bg-gray-100 dark:hover:bg-zinc-800 transition text-xs font-bold text-gray-700 dark:text-zinc-200">' +
				'<span class="flex items-center gap-2">' + flag + ' ' + cc + '</span>' +
				'<span class="flex items-center gap-2 text-[10px] font-normal text-gray-400 dark:text-zinc-500">' + proxies.length + ' پروکسی' +
					'<svg id="vip-cache-chevron-' + cc + '" class="w-3.5 h-3.5 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>' +
				'</span>' +
			'</button>' +
			'<div id="vip-cache-country-' + cc + '" class="hidden px-3 py-2 border-t border-gray-200 dark:border-amoled-border bg-white dark:bg-amoled-input">' +
				'<textarea readonly dir="ltr" class="w-full text-[10px] font-mono text-left text-gray-700 dark:text-zinc-300 bg-transparent resize-none focus:outline-none" rows="' + Math.min(10, Math.max(2, proxies.length)) + '">' + escVipCacheText(proxies.join('\\n')) + '</textarea>' +
				'<button type="button" onclick="copyVipCacheCountry(\\'' + cc + '\\')" class="mt-1 w-full flex items-center justify-center gap-1.5 py-1.5 bg-gray-100 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 text-gray-600 dark:text-zinc-300 hover:bg-gray-200 dark:hover:bg-zinc-700/80 rounded text-[10px] font-bold transition">کپی همه‌ی پروکسی‌های ' + cc + '</button>' +
			'</div>' +
		'</div>';
	}).join('');
}
function toggleVipCacheCountry(cc) {
	const el = document.getElementById('vip-cache-country-' + cc);
	const chevron = document.getElementById('vip-cache-chevron-' + cc);
	if (!el) return;
	el.classList.toggle('hidden');
	if (chevron) chevron.classList.toggle('rotate-180');
}
function copyVipCacheCountry(cc) {
	const proxies = VIP_CACHE_DATA[cc] || [];
	const text = proxies.join('\\n');
	if (navigator.clipboard && navigator.clipboard.writeText) {
		navigator.clipboard.writeText(text).then(function() {
			showToast('✅ لیست ' + cc + ' کپی شد.');
		}).catch(function() {
			showToast('❌ کپی ناموفق بود.', 'error');
		});
	} else {
		showToast('❌ کپی خودکار در این مرورگر پشتیبانی نمی‌شود.', 'error');
	}
}
window.resetUserToDefaultPending = false;
window.syncResetUserUi = function(showBtn) {
	window.resetUserToDefaultPending = false;
	const wrap = document.getElementById('reset-user-default-wrap');
	const note = document.getElementById('reset-user-default-note');
	if (wrap) wrap.style.display = showBtn ? 'block' : 'none';
	if (note) note.style.display = 'none';
};
// Edit-user modal only: puts EVERY field of the form back to what a brand-new user gets (same
// defaults openCreateModal() uses, via applyNewUserFormDefaults) while keeping this user's
// username + UUID. Nothing is saved until the admin presses "ذخیره تغییرات"; closing the modal
// discards it. The saved request carries reset_user_to_default, which makes the server also
// rebuild the proxy list from the pinned locations. Usage counters are never part of the form.
window.resetUserToDefault = async function() {
	if (!isEditMode) return;
	const ok = await customConfirm('همه‌ی تنظیمات این کاربر (محدودیت حجم/زمان/ریکوئست، پورت‌ها، آی‌پی‌ها، فرگمنت، لوکیشن‌ها و پروکسی‌ها و ...) به حالت پیش‌فرض یک کاربر جدید برمی‌گردد. نام کاربری، UUID و آمار مصرف حفظ می‌شود. ادامه می‌دهید؟');
	if (!ok) return;
	const form = document.getElementById('create-user-form');
	const nameEl = document.getElementById('input-name');
	const uuidEl = document.getElementById('input-uuid');
	const keepName = nameEl ? nameEl.value : '';
	const keepUuid = uuidEl ? uuidEl.value : '';
	if (form) form.reset();
	if (nameEl) nameEl.value = keepName;
	if (uuidEl) uuidEl.value = keepUuid;
	window.applyNewUserFormDefaults();
	// چیزهایی که در حالت «ایجاد» از بسته‌شدن قبلی مودال (toggleModal(false)) پاک می‌ماند
	const advSettingsToggle = document.getElementById('input-advanced-settings-toggle');
	if (advSettingsToggle) advSettingsToggle.checked = false;
	const advFragInput = document.getElementById('input-advanced-frag');
	if (advFragInput) advFragInput.value = '';
	const csInput = document.getElementById('input-cipher-suites');
	if (csInput) csInput.value = '';
	const maskInput = document.getElementById('input-tls-mask');
	if (maskInput) maskInput.value = '';
	if (typeof window.toggleAdvancedSettingsInputs === 'function') window.toggleAdvancedSettingsInputs(false);
	const customPortInput = document.getElementById('input-custom-ports');
	if (customPortInput) customPortInput.value = '';
	document.querySelectorAll('.frag-preset-card').forEach(card => card.classList.remove('ring-2', 'ring-blue-500', 'border-blue-500', 'bg-blue-50/50', 'dark:bg-blue-950/40'));
	// کاربر جدید بدون مقدار صریح، ip_limit = «محدودیت کاربر» سراسری (user_limit) می‌گیرد؛ در ویرایش خالی یعنی نامحدود، پس صریح می‌نویسیم
	const ipLimitInputEl = document.getElementById('input-ip-limit');
	if (ipLimitInputEl) {
		ipLimitInputEl.placeholder = 'نامحدود';
		ipLimitInputEl.value = (window.USER_LIMIT !== undefined && window.USER_LIMIT !== null) ? window.USER_LIMIT : window.DEFAULT_USER_LIMIT;
	}
	// سرور همیشه برای لیست تازه‌ساخته‌شده auto-heal را روشن می‌کند (مثل کاربر جدید)
	const rotateCheck = document.getElementById('input-auto-rotate-user-proxy');
	if (rotateCheck) rotateCheck.checked = true;
	window.resetUserToDefaultPending = true;
	const note = document.getElementById('reset-user-default-note');
	if (note) note.style.display = 'block';
};
window.toggleUserProxyMode = function(isSocksMode) {
	const socksContainer = document.getElementById('user-socks5-container');
	if (isSocksMode) {
		if (socksContainer) socksContainer.classList.remove('opacity-50', 'pointer-events-none');
	} else {
		if (socksContainer) socksContainer.classList.add('opacity-50', 'pointer-events-none');
	}
};
async function testUserSocksProxy() {
	const btn = document.getElementById('test-user-proxy-btn');
	if (btn) {
		btn.disabled = true;
		btn.innerText = 'صبر کنید...';
	}
	window.proxyPingMap = {};
	const autoRotateCheck = document.getElementById('input-auto-rotate-user-proxy');
	const isAutoRotate = autoRotateCheck ? autoRotateCheck.checked : false;

	for (let idx = 0; idx < window.proxyFieldsData.length; idx++) {
		const resultSpan = document.getElementById('proxy-ping-label-' + idx);
		const proxyStr = (window.proxyFieldsData[idx] || "").trim();
		if (resultSpan) {
			if (!proxyStr) {
				resultSpan.innerText = 'وارد نشده!';
				resultSpan.className = 'text-[10px] font-bold text-red-500 block mt-0.5 text-center';
			} else {
				resultSpan.innerText = 'در صف تست...';
				resultSpan.className = 'text-[10px] font-bold text-gray-500 block mt-0.5 text-center';
			}
		}
	}

	const testTasks = window.proxyFieldsData.map(async (val, idx) => {
		let proxyStr = (val || "").trim();
		if (!proxyStr) return;

		let resultSpan = document.getElementById('proxy-ping-label-' + idx);
		if (resultSpan) {
			resultSpan.innerText = 'در حال تست...';
			resultSpan.className = 'text-[10px] font-bold text-amber-500 block mt-0.5 text-center';
		}

		const checkProxy = async (targetProxy) => {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 10000);
			try {
				const res = await fetch('/api/test-proxy', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ proxy: targetProxy }),
					signal: controller.signal
				});
				clearTimeout(timeoutId);
				const data = await res.json();
				return { ok: res.ok, data };
			} catch (e) {
				clearTimeout(timeoutId);
				return { ok: false, error: e.name === 'AbortError' ? 'تایم‌اوت' : 'خطا در ارتباط' };
			}
		};

		let testRes = await checkProxy(proxyStr);

		if (testRes.ok && testRes.data.success) {
			resultSpan = document.getElementById('proxy-ping-label-' + idx);
			const flag = typeof getFlagEmoji === 'function' ? getFlagEmoji(testRes.data.country) : '🌐';
			if (resultSpan) {
				resultSpan.innerHTML = flag + ' پینگ: ' + testRes.data.ping + 'ms';
				resultSpan.className = 'text-[10px] font-bold text-green-600 block mt-0.5 text-center';
				window.proxyPingMap[proxyStr] = { text: resultSpan.innerHTML, className: resultSpan.className };
			}
			if (testRes.data.country) {
				try {
					let cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
					cache[proxyStr] = testRes.data.country.toUpperCase();
					localStorage.setItem('proxy_flag_cache_v2', JSON.stringify(cache));
					if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
				} catch(e) {}
			}
		} else {
			if (isAutoRotate) {
				let swapSuccess = false;
				let maxSwaps = 15; 
				let currentBadProxy = proxyStr;
				for (let attempt = 1; attempt <= maxSwaps; attempt++) {
					resultSpan = document.getElementById('proxy-ping-label-' + idx);
					if (resultSpan) {
						resultSpan.innerText = 'خراب بود، تعویض (' + attempt + '/' + maxSwaps + ')...';
						resultSpan.className = 'text-[10px] font-bold text-blue-500 block mt-0.5 text-center';
					}
					
					await window.swapProxyFieldUI(idx, false);
					const newProxy = (window.proxyFieldsData[idx] || "").trim();
					
					if (newProxy && newProxy !== currentBadProxy) {
						resultSpan = document.getElementById('proxy-ping-label-' + idx);
						if (resultSpan) {
							resultSpan.innerText = 'تست پروکسی جدید (' + attempt + ')...';
							resultSpan.className = 'text-[10px] font-bold text-amber-500 block mt-0.5 text-center';
						}
						let newTestRes = await checkProxy(newProxy);
						resultSpan = document.getElementById('proxy-ping-label-' + idx);
						
						if (newTestRes.ok && newTestRes.data.success) {
							const flag = typeof getFlagEmoji === 'function' ? getFlagEmoji(newTestRes.data.country) : '🌐';
							if (resultSpan) {
								resultSpan.innerHTML = flag + ' پینگ: ' + newTestRes.data.ping + 'ms';
								resultSpan.className = 'text-[10px] font-bold text-green-600 block mt-0.5 text-center';
								window.proxyPingMap[newProxy] = { text: resultSpan.innerHTML, className: resultSpan.className };
							}
							
							if (newTestRes.data.country) {
								try {
									let cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
									cache[newProxy] = newTestRes.data.country.toUpperCase();
									localStorage.setItem('proxy_flag_cache_v2', JSON.stringify(cache));
									if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
								} catch(e) {}
							}
							swapSuccess = true;
							break; 
						} else {
							currentBadProxy = newProxy;
						}
					} else {
						break; 
					}
				}
				if (!swapSuccess) {
					resultSpan = document.getElementById('proxy-ping-label-' + idx);
					if (resultSpan) {
						resultSpan.innerText = 'چندین پروکسی جایگزین تست شد اما همه خراب بودند!';
						resultSpan.className = 'text-[10px] font-bold text-red-500 block mt-0.5 text-center';
						const finalProxy = (window.proxyFieldsData[idx] || "").trim();
						window.proxyPingMap[finalProxy] = { text: resultSpan.innerText, className: resultSpan.className };
					}
				}
			} else {
				resultSpan = document.getElementById('proxy-ping-label-' + idx);
				if (resultSpan) {
					const errMsg = testRes.data ? (testRes.data.error || 'ناموفق') : testRes.error;
					resultSpan.innerText = 'خطا: ' + errMsg;
					resultSpan.className = 'text-[10px] font-bold text-red-500 block mt-0.5 break-words text-center';
					window.proxyPingMap[proxyStr] = { text: resultSpan.innerText, className: resultSpan.className };
				}
			}
		}
	});

	await Promise.all(testTasks);

	if (btn) {
		btn.disabled = false;
		btn.innerText = 'تست پـروکـسـی';
	}
}
		async function exportUsersBackup() {
			if (!window.allUsers || window.allUsers.length === 0) {
				alert('⚠️ کاربری برای پشتیبان‌گیری وجود ندارد!');
				return;
			}
			try {
				const backupData = window.allUsers;
				const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(backupData, null, 2));
				const downloadAnchor = document.createElement('a');
				const host = window.location.hostname;
				const now = new Date();
				const dateTimeStr = now.getFullYear() + '-' + 
					String(now.getMonth() + 1).padStart(2, '0') + '-' + 
					String(now.getDate()).padStart(2, '0') + '_' + 
					String(now.getHours()).padStart(2, '0') + '-' + 
					String(now.getMinutes()).padStart(2, '0') + '-' + 
					String(now.getSeconds()).padStart(2, '0');
				downloadAnchor.setAttribute("href", dataStr);
				downloadAnchor.setAttribute("download", "zeus_users_backup_" + host + "_" + dateTimeStr + ".json");
				document.body.appendChild(downloadAnchor);
				downloadAnchor.click();
				downloadAnchor.remove();
			} catch (err) {
				alert('❌ خطا در تهیه نسخه پشتیبان.');
			}
		}
		function triggerImportBackup() {
			document.getElementById('backup-file-input').click();
		}
		async function importUsersBackup(event) {
			const file = event.target.files[0];
			if (!file) return;
			const reader = new FileReader();
			reader.onload = async function(e) {
				const importBtn = document.querySelector('button[onclick="triggerImportBackup()"]');
				const exportBtn = document.querySelector('button[onclick="exportUsersBackup()"]');
				const closeBtn = document.querySelector('#settings-modal button[onclick="toggleSettingsModal(false)"]');
				try {
					const parsedData = JSON.parse(e.target.result);
					let backupUsers = [];
					let backupSettings = null;
					if (Array.isArray(parsedData)) {
						backupUsers = parsedData;
					} else if (parsedData && parsedData.users && Array.isArray(parsedData.users)) {
						backupUsers = parsedData.users;
						backupSettings = parsedData.settings;
					} else {
						alert('❌ فایل پشتیبان نامعتبر است!');
						return;
					}
					const validBackupUsers = backupUsers.filter(u => u && typeof u === 'object' && u.username);
					if (validBackupUsers.length === 0 && !backupSettings) {
						alert('❌ هیچ داده معتبری در فایل یافت نشد!');
						return;
					}
					if (backupSettings && Object.keys(backupSettings).length > 0) {
						const restoreSettings = await customConfirm('⚙️ فایل بک‌آپ شامل تنظیمات پـنـل نیز می‌باشد. آیا می‌خواهید تنظیمات هم بازگردانی شوند؟');
						if (restoreSettings) {
							try {
								await fetch('/api/settings/bulk', {
									method: 'POST',
									headers: { 'Content-Type': 'application/json' },
									body: JSON.stringify({ settings: backupSettings })
								});
							} catch (err) {}
						}
					}
					const existingUsernames = new Set((window.allUsers || []).map(u => u.username));
					const duplicates = validBackupUsers.filter(u => existingUsernames.has(u.username));
					let overwrite = false;
					if (duplicates.length > 0) {
						overwrite = await customConfirm('⚠️ تعداد ' + duplicates.length + ' کاربر تکراری شناسایی شد. آیا می‌خواهید اطلاعات آن‌ها بازنویسی شود؟');
					}
					if (importBtn) importBtn.disabled = true;
					if (exportBtn) exportBtn.disabled = true;
					if (closeBtn) closeBtn.disabled = true;
					let successCount = 0;
					let currentStep = 0;
					for (const u of validBackupUsers) {
						currentStep++;
						if (importBtn) {
							importBtn.innerText = '⏳ بازیابی (' + currentStep + '/' + validBackupUsers.length + ')';
						}

						const userDataPayload = {
							username: u.username,
							uuid: u.uuid,
							limit_gb: u.limit_gb,
							expiry_days: u.expiry_days,
							limit_req: u.limit_req,
							ips: u.ips,
							tls: u.tls,
							port: u.port,
							fingerprint: u.fingerprint,
							ip_limit: u.ip_limit !== undefined ? u.ip_limit : u.max_connections,
							used_gb: u.used_gb,
							used_req: u.used_req,
							created_at: u.created_at,
							is_active: u.is_active,
							block_porn: u.block_porn,
							block_ads: u.block_ads,
							frag_len: u.frag_len,
							frag_int: u.frag_int,
							advanced_frag: u.advanced_frag,
							cipher_suites: u.cipher_suites,
							tls_mask: u.tls_mask,
							early_data_enabled: u.early_data_enabled,
							early_data_size: u.early_data_size,
							user_proxy_iata: u.user_proxy_iata,
							user_socks5: u.user_socks5,
							user_proxy_ip: u.user_proxy_ip,
							auto_reset_vol_days: u.auto_reset_vol_days,
							auto_reset_req_days: u.auto_reset_req_days,
							auto_rotate_ip: u.auto_rotate_ip,
							rotate_time: u.rotate_time,
							ip_operator: u.ip_operator,
							ip_count: u.ip_count,
							auto_rotate_user_proxy: u.auto_rotate_user_proxy,
							start_on_first_connect: u.start_on_first_connect,
							enable_direct: u.enable_direct !== undefined ? u.enable_direct : 1,
							connection_type: u.connection_type
						};

						const exists = existingUsernames.has(u.username);
						if (exists) {
							if (overwrite) {
								try {
									await fetch('/api/users/' + encodeURIComponent(u.username), { method: 'DELETE' });
									const res = await fetch('/api/users', {
										method: 'POST',
										headers: { 'Content-Type': 'application/json' },
										body: JSON.stringify(userDataPayload)
									});
									if (res.ok) successCount++;
								} catch(err) {}
							}
						} else {
							try {
								const res = await fetch('/api/users', {
									method: 'POST',
									headers: { 'Content-Type': 'application/json' },
									body: JSON.stringify(userDataPayload)
								});
								if (res.ok) successCount++;
							} catch(err) {}
						}
					}
					alert('✅ عملیات بازیابی با موفقیت انجام شد. صفحه رفرش می‌شود...');
					setTimeout(() => { window.location.reload(); }, 1500);
				} catch(err) {
					alert('❌ خطا در خواندن یا پردازش فایل پشتیبان!');
				} finally {
					if (importBtn) {
						importBtn.disabled = false;
						importBtn.innerText = '📥 بازیابی';
					}
					if (exportBtn) exportBtn.disabled = false;
					if (closeBtn) closeBtn.disabled = false;
					event.target.value = '';
				}
			};
			reader.readAsText(file);
		}
		async function changeAdminPassword() {
			const currentPwd = document.getElementById('change-pwd-current').value.trim();
			const newPwd = document.getElementById('change-pwd-new').value.trim();
			const btn = document.getElementById('change-pwd-btn');
			if (!currentPwd || !newPwd) {
				alert('⚠️ وارد کردن رمز عبور فعلی و جدید الزامی است!');
				return;
			}
			if (newPwd.length < 4) {
				alert('⚠️ رمز عبور جدید باید حداقل ۴ کاراکتر باشد!');
				return;
			}
			btn.disabled = true;
			btn.innerText = 'در حال تغییر...';
			try {
				const response = await fetch('/api/change-password', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ current_password: currentPwd, new_password: newPwd })
				});
				const data = await response.json();
				if (response.ok && data.success) {
					alert('✅ رمز عبور با موفقیت تغییر کرد.');
					document.getElementById('change-pwd-current').value = '';
					document.getElementById('change-pwd-new').value = '';
					toggleSettingsModal(false);
				} else {
					alert('❌ خطا: ' + (data.error || 'عملیات ناموفق بود'));
				}
			} catch (err) {
				alert('خطا در برقراری ارتباط با سرور');
			} finally {
				btn.disabled = false;
				btn.innerText = 'تغییر رمز عبور';
			}
		}
		async function logoutAdmin() {
			if (await customConfirm('آیا می‌خواهید از پـنـل خارج شوید؟ ⚠️ ')) {
				try {
					await fetch('/api/logout', { method: 'POST' });
				} catch (err) {}
				window.location.reload();
			}
		}
// قانون ورژن‌گذاری: هر بار که تغییر/ادیتی روی این فایل اعمال می‌شود، رقم سوم (patch) یک عدد
// افزایش پیدا می‌کند (مثلاً 3.32.0 -> 3.32.1). وقتی رقم patch به 9 برسه، تغییر بعدی رقم دوم
// (minor) رو یکی زیاد و patch رو صفر می‌کنه (مثلاً 3.32.9 -> 3.33.0). این قانون هم‌زمان در
// vip-proxy-changes.md مستند شده — هر تغییری در این md هم باید همراه با این ورژن ثبت بشه.
const CURRENT_VERSION = '3.32.8';
const UPDATE_FIX = "constsCURRENT_VERSION='d.d.d'";
		window.autoUpdateStatusCache = false;
		async function checkAutoUpdateSetup() {
			try {
				const res = await fetch('/api/auto-update-setup', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ action: 'check' })
				});
				const data = await res.json();
				window.autoUpdateStatusCache = data.auto_update;
				const toggle = document.getElementById('auto-update-toggle');
				if (toggle) toggle.checked = data.auto_update;
				return data;
			} catch(e) { return null; }
		}
		async function handleAutoUpdateToggle(el) {
			const isChecked = el.checked;
			el.disabled = true;
			try {
				if (isChecked) {
					const status = await checkAutoUpdateSetup();
					if (status && !status.has_token) {
						el.checked = false;
						window.pendingCoreAction = 'enable_auto_update';
						toggleTokenModal(true);
					} else {
						const res = await fetch('/api/auto-update-setup', {
							method: 'POST',
							headers: { 'Content-Type': 'application/json' },
							body: JSON.stringify({ action: 'enable' })
						});
						const data = await res.json();
						if (res.ok && data.success) {
							showToast('✅ آپدیت خودکار فعال شد.');
							window.autoUpdateStatusCache = true;
							el.checked = true;
						} else {
							el.checked = false;
							alert('❌ ' + (data.error || 'خطا در فعال‌سازی'));
						}
					}
				} else {
					const res = await fetch('/api/auto-update-setup', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({ action: 'disable' })
					});
					if (res.ok) {
						showToast('✅ آپدیت خودکار غیرفعال شد.');
						window.autoUpdateStatusCache = false;
					} else {
						el.checked = true;
					}
				}
			} finally {
				el.disabled = false;
			}
		}
		async function checkForUpdates(isManual = false) {
			try {
				if (isManual) {
					document.getElementById('update-toggle').classList.add('animate-pulse');
				}
				const res = await fetchWithFallbackUI('zeus.obfuscated.js?t=' + Date.now());
				if (!res.ok) throw new Error('Network response was not ok');
				const text = await res.text();
				const match = text.match(/CURRENT_VERSION.*?['"]([0-9]+\\.[0-9]+\\.[0-9]+)['"]/i);
				const latestVersion = match ? match[1] : null;
				if (isManual) {
					document.getElementById('update-toggle').classList.remove('animate-pulse');
				}
				
				let isUpdateAvailable = false;
				if (latestVersion && latestVersion !== CURRENT_VERSION) {
					const l = latestVersion.split('.').map(Number);
					const c = CURRENT_VERSION.split('.').map(Number);
					for (let i = 0; i < Math.max(l.length, c.length); i++) {
						if ((l[i] || 0) > (c[i] || 0)) { isUpdateAvailable = true; break; }
						if ((l[i] || 0) < (c[i] || 0)) break; 
					}
				}
				if (isUpdateAvailable) {
					document.getElementById('update-toggle').className = "flex-1 py-2 bg-red-600 hover:bg-red-700 dark:bg-red-600 border-2 border-white text-white font-bold rounded-md text-sm transition animate-violent-shake relative flex items-center justify-center gap-1.5 z-50";
					const badge = document.getElementById('update-badge');
					if (badge) badge.remove();
					if (window.autoUpdateStatusCache && !isManual) {
						const lastUp = parseInt(sessionStorage.getItem('zeus_last_update') || '0', 10);
						if (Date.now() - lastUp < 180000) return;
						showToast('نسخه جدید یافت شد. در حال آپدیت خودکار...');
						await applyUpdate();
						return;
					}
					if (isManual) {
						toggleUpdateModal(true, latestVersion);
					}
				} else {
					if (isManual) {
						alert('شما در حال استفاده از آخرین نسخه (v' + CURRENT_VERSION + ') هستید.');
					}
				}
			} catch (err) {
				if (isManual) {
					document.getElementById('update-toggle').classList.remove('animate-pulse');
					alert('خطا در بررسی آپدیت از گیت هاب.');
				}
			}
		}	
		function toggleTokenModal(show) {
			setModalState('token-modal', show);
			if (!show) document.getElementById('update-token-input').value = '';
		}
		async function submitTokenForUpdate() {
			const token = document.getElementById('update-token-input').value.trim();
			if (!token) {
				alert('لطفاً توکن را وارد کنید.');
				return;
			}
			toggleTokenModal(false);
			if (window.pendingCoreAction === 'enable_auto_update') {
				try {
					const res = await fetch('/api/auto-update-setup', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({ action: 'enable', token: token })
					});
					const data = await res.json();
					if (res.ok && data.success) {
						showToast('✅ آپدیت خودکار با موفقیت فعال شد.');
						window.autoUpdateStatusCache = true;
						const toggle = document.getElementById('auto-update-toggle');
						if (toggle) toggle.checked = true;
					} else {
						alert('❌ خطا در بررسی توکن: ' + (data.error || 'ناشناخته'));
					}
				} catch(e) {
					alert('❌ خطا در ارتباط با سرور');
				}
				window.pendingCoreAction = null;
				return;
			}
			handleCoreAction(window.pendingCoreAction || 'update', token);
		}
		async function applyUpdate(token = null) {
			await handleCoreAction('update', token);
		}
let cachedIpsData = {};
let cachedVipList = null;
let cachedVipProxies = {};
async function initVipCache() {
	try {
		const resVipList = await fetchWithFallbackUI('vip-list');
		if (resVipList.ok) {
			const files = await resVipList.json();
			cachedVipList = files.filter(f => f && f.name && f.name.endsWith('.txt')).map(f => f.name.replace('.txt', '').toUpperCase());
			
			if (cachedVipList && cachedVipList.length > 0) {
				await Promise.all(cachedVipList.map(async (country) => {
					try {
						const resVip = await fetchWithFallbackUI('proxy_vip/' + country + '.txt');
						if (resVip.ok) {
							const text = await resVip.text();
							const lines = text.split('\\n').map(l => l.trim()).filter(l => l.length > 5);
							if (lines.length > 0) {
								cachedVipProxies[country] = lines;
							}
						}
					} catch(e) {}
				}));
			}
		}
	} catch(e) {}
}
async function fetchIpsList() {
	try {
		const response = await fetchWithFallbackUI('ips.txt');
		if (!response.ok) throw new Error('Fetch failed');
		const text = await response.text();
		const blocks = text.split('----------');
		cachedIpsData = {};
		blocks.forEach(block => {
			const lines = block.trim().split('\\n').map(l => l.trim()).filter(l => l.length > 0);
			if (lines.length === 0) return;
			let opName = "Unknown";
			const ips = [];
			lines.forEach(line => {
				if (line.includes('#')) {
					opName = line.split('#')[1].trim();
				} else if (!line.startsWith('[source')) {
					ips.push(line);
				}
			});
			if (ips.length > 0) {
				cachedIpsData[opName] = ips;
			}
		});
		populateIpSelect();
	} catch (err) {
		alert('Failed to load IP list from GitHub.');
		toggleIpSelectorModal(false);
	}
}
function populateIpSelect() {
	const select = document.getElementById('ip-operator-select');
	select.innerHTML = '<option value="all">همه (توصیه شده)</option>';
	Object.keys(cachedIpsData).forEach(op => {
		const option = document.createElement('option');
		option.value = op;
		option.textContent = op;
		select.appendChild(option);
	});
}
function toggleIpSelectorModal(show) {
	setModalState('ip-selector-modal', show);
}
function toggleIpScannerModal(show) {
	setModalState('ip-scanner-modal', show);
}
function openIpScannerModal() {
	toggleIpScannerModal(true);
}
function copyScannerCode(text, btn) {
	navigator.clipboard.writeText(text).then(() => {
		const originalHtml = btn.innerHTML;
		const originalClasses = btn.className;
		
		btn.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"></path></svg><span>کپی شد!</span>';
		btn.className = 'w-full flex items-center justify-center gap-1.5 py-2 bg-green-50 dark:bg-green-900/30 border border-green-500 text-green-600 dark:text-green-400 rounded text-xs font-bold transition shadow-sm';
		
		setTimeout(() => { 
			btn.innerHTML = originalHtml;
			btn.className = originalClasses;
		}, 2000);
	}).catch(() => {
		alert('خطا در کپی متن!');
	});
}
async function openIpSelectorModal() {
	toggleIpSelectorModal(true);
	document.getElementById('ip-loading-state').classList.remove('hidden');
	document.getElementById('ip-selection-form').classList.add('hidden');
	await fetchIpsList();
	
	const op = document.getElementById('hidden-ip-operator').value;
	const selectOp = document.getElementById('ip-operator-select');
	if (selectOp.querySelector('option[value="' + op + '"]')) {
		selectOp.value = op;
	} else {
		selectOp.value = 'all';
	}
	document.getElementById('ip-count-input').value = document.getElementById('hidden-ip-count').value || 15;
	
	document.getElementById('ip-loading-state').classList.add('hidden');
	document.getElementById('ip-selection-form').classList.remove('hidden');
}
function applySelectedIps() {
	const operator = document.getElementById('ip-operator-select').value;
	let count = parseInt(document.getElementById('ip-count-input').value, 10);
	if (isNaN(count) || count < 1) count = 10;
	let availableIps = [];
	if (operator === 'all') {
		Object.values(cachedIpsData).forEach(ips => {
			availableIps = availableIps.concat(ips);
		});
	} else {
		availableIps = cachedIpsData[operator] || [];
	}
	availableIps = [...new Set(availableIps)];
	let selectedIps = [];
	if (count >= availableIps.length) {
		selectedIps = availableIps;
	} else {
		const shuffled = availableIps.slice();
		for (let i = shuffled.length - 1; i > 0; i--) {
			const j = Math.floor(Math.random() * (i + 1));
			[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
		}
		selectedIps = shuffled.slice(0, count);
	}
	document.getElementById('input-ips').value = selectedIps.join('\\n');
	document.getElementById('hidden-ip-operator').value = operator;
	document.getElementById('hidden-ip-count').value = count;
	toggleIpSelectorModal(false);
}
		window.isGlobalProxyTestRunning = false;
		// فاصله‌ی هر چرخه‌ی کامل اسکن سلامت پروکسی‌ها. قبلاً ۱۰ ثانیه بود که باعث می‌شد
		// برای هر کاربر با ۱۵ اسلات پروکسی (auto_rotate_user_proxy) هر ۱۰ ثانیه تا ۱۵ ریکوئست
		// جداگانه به /api/test-proxy زده شود - این ریکوئست‌ها هیچ‌کدام در used_req کاربر
		// حساب نمی‌شوند ولی همگی جزو سهمیه‌ی ۱۰۰هزارتایی Worker به‌حساب می‌آیند.
		// طبق تصمیم کاربر روی ۱۰ دقیقه تنظیم شد (کاهش ~۹۸٪ نسبت به حالت قبلی).
		const PROXY_SCANNER_INTERVAL_MS = 600000; // 10 دقیقه
		async function runGlobalProxyScanner() {
			if (window.isGlobalProxyTestRunning || document.hidden) {
				setTimeout(runGlobalProxyScanner, PROXY_SCANNER_INTERVAL_MS);
				return;
			}
			if (!window.allUsers || window.allUsers.length === 0) {
				setTimeout(runGlobalProxyScanner, PROXY_SCANNER_INTERVAL_MS);
				return;
			}
			window.isGlobalProxyTestRunning = true;
			const startTime = Date.now();
			let hasChanges = false;
			try {
				for (const user of window.allUsers) {
					if (user.auto_rotate_user_proxy !== 1 || !user.user_socks5) continue;
					let proxyList = [];
					try {
						if (user.user_socks5.trim().startsWith("[")) {
							proxyList = JSON.parse(user.user_socks5);
						} else {
							proxyList = [user.user_socks5];
						}
					} catch(e) {
						proxyList = [user.user_socks5];
					}
					for (const item of proxyList) {
						const proxyStr = typeof item === 'object' && item !== null ? item.proxy : item;
						if (!proxyStr) continue;
						try {
							const controller = new AbortController();
							const timeoutId = setTimeout(() => controller.abort(), 6000);
							const res = await fetch('/api/test-proxy', {
								method: 'POST',
								headers: { 'Content-Type': 'application/json' },
								body: JSON.stringify({ proxy: proxyStr, username: user.username, replace_on_fail: true }),
								signal: controller.signal
							});
							clearTimeout(timeoutId);
							const data = await res.json();
							if (!res.ok || !data.success) {
								hasChanges = true;
							}
						} catch (e) {
							hasChanges = true;
						}
						await new Promise(r => setTimeout(r, 200));
					}
				}
			} catch (e) {} finally {
				window.isGlobalProxyTestRunning = false;
				if (hasChanges && !document.hidden) await loadUsers(true);
				const elapsed = Date.now() - startTime;
				const waitTime = Math.max(0, PROXY_SCANNER_INTERVAL_MS - elapsed);
				setTimeout(runGlobalProxyScanner, waitTime);
			}
		}

		window.hasShownLoopWarning = false;
		async function checkLoopWarning() {
			if (window.hasShownLoopWarning) return;
			await new Promise(r => setTimeout(r, 1500)); 
			
			const testProxies = [
				"socks5://8.8.8.8:1080", 
				"socks5://1.1.1.1:1080"
			];
			const randomProxy = testProxies[Math.floor(Math.random() * testProxies.length)];
			
			try {
				const controller = new AbortController();
				const timeoutId = setTimeout(() => controller.abort(), 4000);
				const res = await fetch('/api/test-proxy', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ proxy: randomProxy, skip_country: true }),
					signal: controller.signal
				});
				clearTimeout(timeoutId);
				const data = await res.json();
				if (!res.ok || (data && data.error && data.error.includes("Loop"))) {
					window.hasShownLoopWarning = true;
					
					const showLoopModal = () => {
						const modal = document.getElementById('loop-warning-modal');
						const card = document.getElementById('loop-warning-card');
						if(modal && card) {
							modal.classList.replace('opacity-0', 'opacity-100');
							modal.classList.replace('pointer-events-none', 'pointer-events-auto');
							card.classList.replace('scale-95', 'scale-100');
						}
					};
					
					showLoopModal();
					setInterval(showLoopModal, 10000);
				}
			} catch (e) {
			}
		}

		document.addEventListener('DOMContentLoaded', () => {
			if (window.location.search.includes('t=')) {
				window.history.replaceState(null, '', window.location.pathname);
			}
			setTimeout(() => {
				if (typeof toggleInfoModal === 'function') {
					toggleInfoModal(true);
				}
			}, 36000000);
			
			const versionBadge = document.getElementById('panel-version');
			if (versionBadge) versionBadge.innerText = 'v' + CURRENT_VERSION + ' beta';
			renderPortCheckboxes();
			initVipCache();
			loadUsers();
			loadTrafficCardChart();
			window.loadGlobalCleanIpSetting();
			window.loadGlobalReqLimitSetting();
			window.loadUserLimitSetting();
			window.loadDeviceWarningThresholdSetting();
			window.loadOtherCleanIpsSetting();
			window.loadInlineProxyIpSetting();
			window.loadDefaultPortSetting();
			window.loadNewUserDefaultsSetting();
			window.populatePinnedLocationSelects();
			window.loadPinnedLocationsSetting();
			window.usersRefreshIntervalId = null;
			window.startRefreshInterval = function(intervalMs) {
				if (window.usersRefreshIntervalId) {
					clearInterval(window.usersRefreshIntervalId);
				}
				window.usersRefreshIntervalId = setInterval(() => {
					if (!document.hidden) loadUsers(true);
				}, intervalMs);
			};
			window.changeRefreshRate = function(val) {
				const ms = parseInt(val, 10);
				localStorage.setItem('zeus_refresh_rate', ms);
				window.startRefreshInterval(ms);
				showToast('نرخ رفرش پـنـل تغییر کرد');
			};
			if (!localStorage.getItem('zeus_rate_migrated_to_10m')) {
				localStorage.setItem('zeus_refresh_rate', '600000');
				localStorage.setItem('zeus_rate_migrated_to_10m', 'true');
			}
			const savedRate = localStorage.getItem('zeus_refresh_rate');
			const initialRate = savedRate ? parseInt(savedRate, 10) : 600000;
			const selectEl = document.getElementById('refresh-rate-select');
			if (selectEl) {
				selectEl.value = String(initialRate);
			}
			window.startRefreshInterval(initialRate);
			checkAutoUpdateSetup();
			setTimeout(() => checkLoopWarning(), 3000);
			setTimeout(runGlobalProxyScanner, 10000);
			window.addEventListener('mousedown', (e) => {
				window._modalMouseDownTarget = e.target;
			});

			const formContainer = document.getElementById('create-user-form');
			if (formContainer) {
				let touchStartX = 0;
				let touchStartY = 0;
				const tabNames = ['tab-user-info', 'tab-ports-network', 'tab-proxy-settings'];
				
				formContainer.addEventListener('touchstart', (e) => {
					touchStartX = e.changedTouches[0].screenX;
					touchStartY = e.changedTouches[0].screenY;
				}, {passive: true});
				
				formContainer.addEventListener('touchend', (e) => {
					if (window.innerWidth > 768) return;
					
					let touchEndX = e.changedTouches[0].screenX;
					let touchEndY = e.changedTouches[0].screenY;
					
					let diffX = touchStartX - touchEndX;
					let diffY = Math.abs(touchStartY - touchEndY);
					
					if (Math.abs(diffX) > diffY && Math.abs(diffX) > 50) {
						let currentIndex = 0;
						for (let i = 0; i < tabNames.length; i++) {
							const el = document.getElementById(tabNames[i]);
							if (el && !el.classList.contains('hidden')) {
								currentIndex = i;
								break;
							}
						}
						
						let nextIndex = currentIndex;
						
						if (diffX > 50) {
							nextIndex--; 
						} else if (diffX < -50) {
							nextIndex++; 
						}
						
						if (nextIndex >= 0 && nextIndex < tabNames.length && nextIndex !== currentIndex) {
							if (typeof window.switchUserTab === 'function') {
								window.switchUserTab(tabNames[nextIndex]);
							}
						}
					}
				}, {passive: true});
			}
			window.addEventListener('click', (e) => {
				if (window._modalMouseDownTarget && window._modalMouseDownTarget !== e.target) return;
				if (e.target.id === 'user-modal') toggleModal(false);
				if (e.target.id === 'ip-selector-modal') toggleIpSelectorModal(false);
				if (e.target.id === 'ip-scanner-modal') toggleIpScannerModal(false);
				if (e.target.id === 'settings-modal') toggleSettingsModal(false);
				if (e.target.id === 'update-modal') toggleUpdateModal(false);
				if (e.target.id === 'token-modal') toggleTokenModal(false);
				if (e.target.id === 'qr-modal') toggleQrModal(false);
				if (e.target.id === 'usage-warning-modal') closeUsageWarning();
				if (e.target.id === 'usage-chart-modal') closeUsageChart();
				if (e.target.id === 'online-counter-warning-modal') closeOnlineCounterWarning();
				if (e.target.id === 'pattng-info-modal') togglePattNgModal(false);
				
				if (e.target.id === 'proxy-selector-modal') toggleProxySelectorModal(false);
				if (e.target.id === 'donate-modal') toggleDonateModal(false);
				if (e.target.id === 'support-modal') toggleSupportModal(false);
				if (e.target.id === 'pwa-install-modal') togglePwaModal(false);
				if (e.target.id === 'custom-confirm-modal') {
					const cancelBtn = document.getElementById('custom-confirm-cancel');
					if (cancelBtn) cancelBtn.click();
				}
				if (e.target.id === 'vip-proxies-cache-modal') toggleVipProxiesCacheModal(false);
			});
		});
function toggleProxySelectorModal(show) { setModalState('proxy-selector-modal', show); }
		async function loadVipCountries() {
			const select = document.getElementById('vip-country-select');
			const btn = document.getElementById('vip-fetch-btn');
			select.innerHTML = '<option value="">در حال بررسی مخزن...</option>';
			
			if (cachedVipList && cachedVipList.length > 0) {
				select.innerHTML = '<option value="">یک کشور VIP انتخاب کنید...</option>';
				cachedVipList.forEach(function(country) {
					const option = document.createElement('option');
					option.value = country;
					const flag = typeof getFlagEmojiText === 'function' ? getFlagEmojiText(country) : '🌐';
					option.textContent = flag + ' ' + country;
					select.appendChild(option);
				});
				btn.disabled = false;
			} else {
				select.innerHTML = '<option value="">پـروکـسـی اختصاصی موجود نیست</option>';
				btn.disabled = true;
			}
		}
		async function loadVipProxy() {
			const select = document.getElementById('vip-country-select');
			const country = select.value;
			const btn = document.getElementById('vip-fetch-btn');
			if (!country) return;
			btn.disabled = true;
			btn.innerText = '...';
			
			const lines = cachedVipProxies[country] || [];
			if (lines.length > 0) {
				const randomProxy = lines[Math.floor(Math.random() * lines.length)];
				window.proxyFieldsData[window.activeProxyIndex || 0] = randomProxy;
				if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
				toggleProxySelectorModal(false);
				showToast('✅ پـروکـسـی اختصاصی با موفقیت اعمال شد.');
				testUserSocksProxy();
			} else {
				alert('فایل پـروکـسـی این کشور خالی است یا هنوز در کش بارگذاری نشده است.');
			}
			
			btn.disabled = false;
			btn.innerText = 'دریافت';
		}
		async function openProxySelectorModal() {
			toggleProxySelectorModal(true);
			const select = document.getElementById('proxy-country-select');
			const fetchBtn = document.getElementById('proxy-fetch-btn');
			const countriesList = [
		  "AA", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR",
		  "AS", "AT", "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE",
		  "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ",
		  "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD",
		  "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR",
		  "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM",
		  "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI",
		  "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
		  "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS",
		  "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU",
		  "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT",
		  "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN",
		  "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK",
		  "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME",
		  "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ",
		  "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
		  "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU",
		  "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM",
		  "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS",
		  "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI",
		  "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV",
		  "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK",
		  "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA",
		  "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
		  "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"
			];
			select.innerHTML = '';
			countriesList.forEach(function(country) {
				const option = document.createElement('option');
				option.value = country;
				const flag = typeof getFlagEmojiText === 'function' ? getFlagEmojiText(country) : '🌐';
				option.textContent = flag + ' ' + country;
				select.appendChild(option);
			});
			fetchBtn.disabled = false;
			loadVipCountries();
		}
async function fetchAndLoadProxy() {
	const select = document.getElementById("proxy-country-select");
	const country = select.value;
	if (!country) return;
	const loadingState = document.getElementById("proxy-loading-state");
	const formState = document.getElementById("proxy-selection-form");
	const fetchBtn = document.getElementById("proxy-fetch-btn");
	loadingState.classList.remove("hidden");
	loadingState.innerText = "در حال دریافت لیست پـروکـسـی‌ها...";
	formState.classList.add("hidden");
	fetchBtn.disabled = true;
	try {
		const sources = [
			{ url: "proxy/" + country.toUpperCase() + ".txt", prefix: "" }
		];
		const responses = await Promise.allSettled(sources.map(src => 
			fetchWithFallbackUI(src.url).then(async res => {
				if (!res.ok) throw new Error();
				const text = await res.text();
				return { text: text, prefix: src.prefix };
			})
		));
		let combinedProxies = [];
		for (const res of responses) {
			if (res.status === "fulfilled" && res.value && res.value.text) {
				const rawLines = res.value.text.split("\\n");
				for (let line of rawLines) {
					line = line.trim();
					if (line.length > 5) {
						combinedProxies.push(line);
					}
				}
			}
		}
		let lines = [...new Set(combinedProxies.map(l => {
			if (l.match(new RegExp("^(socks4|socks5|socks|http|https|tg)://", "i")) || l.includes("t.me/socks")) {
				return l;
			}
			return "socks5://" + l;
		}))];
		if (lines.length > 0) {
			for (let i = lines.length - 1; i > 0; i--) {
				const j = Math.floor(Math.random() * (i + 1));
				[lines[i], lines[j]] = [lines[j], lines[i]];
			}
			let bestProxy = null;
			let fallbackProxy = null;
			const BATCH_SIZE = 5;
			for (let i = 0; i < lines.length; i += BATCH_SIZE) {
				const batch = lines.slice(i, i + BATCH_SIZE);
				loadingState.innerText = "تعداد " + lines.length + " پـروکـسـی پیدا شد درحال اسکن\\nاسکن گروه " + (Math.floor(i / BATCH_SIZE) + 1) + " (۵ تست برای هر کدام)...";
				const testResults = await Promise.allSettled(batch.map(async (candidate) => {
					let successCount = 0;
					let totalPing = 0;
					let failCount = 0;
					for(let t = 0; t < 5; t++) {
						const controller = new AbortController();
						const timeoutId = setTimeout(() => controller.abort(), 3500);
						try {
							const testRes = await fetch("/api/test-proxy", {
								method: "POST",
								headers: { "Content-Type": "application/json" },
								body: JSON.stringify({ proxy: candidate }),
								signal: controller.signal
							});
							clearTimeout(timeoutId);
							const testData = await testRes.json();
							if (testRes.ok && testData.success) {
								successCount++;
								totalPing += testData.ping;
							} else {
								failCount++;
							}
						} catch (err) {
							clearTimeout(timeoutId);
							failCount++;
						}
						if (failCount > 2) break;
					}
					if (successCount > 0) {
						return { proxy: candidate, successCount: successCount, avgPing: totalPing / successCount };
					}
					throw new Error();
				}));
				const successfulProxies = testResults
					.filter(r => r.status === "fulfilled")
					.map(r => r.value)
					.sort((a, b) => {
						if (b.successCount !== a.successCount) {
							return b.successCount - a.successCount;
						}
						return a.avgPing - b.avgPing;
					});
				if (successfulProxies.length > 0) {
					const topCandidate = successfulProxies[0];
					if (topCandidate.successCount >= 3) {
						bestProxy = topCandidate.proxy;
						break;
					} else if (!fallbackProxy || topCandidate.successCount > fallbackProxy.successCount) {
						fallbackProxy = topCandidate;
					}
				}
			}
			if (!bestProxy && fallbackProxy) {
				bestProxy = fallbackProxy.proxy;
			}
			if (bestProxy) {
				window.proxyFieldsData[window.activeProxyIndex || 0] = bestProxy;
				if (typeof window.renderProxyFieldsUI === 'function') window.renderProxyFieldsUI();
				toggleProxySelectorModal(false);
				showToast("پـروکـسـی با بهترین امتیاز لود شد.");
				testUserSocksProxy();
			} else {
				alert("هیچ پـروکـسـی سالمی (حتی با یک پینگ موفق) یافت نشد.");
			}
		} else {
			alert("پـروکـسـی برای این کشور یافت نشد.");
		}
	} catch (e) {
		alert("خطا در دریافت لیست پـروکـسـی‌ها از سرور.");
	} finally {
		loadingState.classList.add("hidden");
		formState.classList.remove("hidden");
		fetchBtn.disabled = false;
	}
}
const WORKER_DONATE_URL = "https://si-491177.taile4bcbb.ts.net/donate";
		function toggleDonateModal(show) {
			setModalState('donate-modal', show);
			if (!show) {
				document.getElementById('donate-proxy-input').value = '';
				const resultSpan = document.getElementById('donate-result');
				if (resultSpan) {
					resultSpan.innerText = '';
					resultSpan.className = 'inline-block mt-1 text-[11px] font-bold transition-colors break-words leading-relaxed empty:hidden';
				}
			}
		}
		async function testAndDonateProxy() {
			const proxyInput = document.getElementById('donate-proxy-input').value.trim();
			const btn = document.getElementById('donate-submit-btn');
			const resultSpan = document.getElementById('donate-result');
			if (!proxyInput) {
				resultSpan.innerText = 'لطفاً پـروکـسـی را وارد کنید!';
				resultSpan.className = 'text-[11px] font-bold text-red-500 w-full mt-1';
				return;
			}
			if (!proxyInput.includes('@') || !proxyInput.split('@')[0].includes(':')) {
				resultSpan.innerText = '❌ پـروکـسـی باید دارای نام کاربری و رمز عبور باشد';
				resultSpan.className = 'text-[11px] font-bold text-red-500 w-full mt-1 break-words';
				return;
			}
			btn.disabled = true;
			btn.innerText = 'صبر کنید...';
			resultSpan.innerText = 'در حال تست با اسکنر پـنـل...';
			resultSpan.className = 'text-[11px] font-bold text-emerald-500 w-full mt-1';
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 6000);
			try {
				const testRes = await fetch('/api/test-proxy', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ proxy: proxyInput }),
					signal: controller.signal
				});
				clearTimeout(timeoutId);
				const testData = await testRes.json();
				if (!testRes.ok || !testData.success) {
					throw new Error(testData.error || 'پـروکـسـی مسدود یا خاموش است');
				}
				resultSpan.innerText = 'در حال بررسی اختصاصی بودن پـروکـسـی...';
				let protocol = "";
				const protoMatch = proxyInput.match(new RegExp("^(socks4|socks5|socks|http|https)://", "i"));
				if (protoMatch) protocol = protoMatch[0];
				const hostPort = proxyInput.substring(proxyInput.lastIndexOf('@') + 1);
				const noAuthProxy = protocol + hostPort;
				let isOpenProxy = false;
				try {
					const ctlNoAuth = new AbortController();
					const tidNoAuth = setTimeout(() => ctlNoAuth.abort(), 4000);
					const resNoAuth = await fetch('/api/test-proxy', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({ proxy: noAuthProxy }),
						signal: ctlNoAuth.signal
					});
					clearTimeout(tidNoAuth);
					const dataNoAuth = await resNoAuth.json();
					if (resNoAuth.ok && dataNoAuth.success) {
						isOpenProxy = true;
					}
				} catch(e) {}
				if (isOpenProxy) {
					throw new Error('این پـروکـسـی عمومی و بدون رمز است (الکی یوزرنیم و پسورد نزن!)');
				}
				const countryCode = testData.country || 'UN';
				resultSpan.innerText = 'پـروکـسـی سالم و اختصاصی است! در حال ارسال (' + countryCode + ')...';
				const donateResponse = await fetch(WORKER_DONATE_URL, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({
						proxy: proxyInput,
						country: countryCode
					})
				});
				const donateData = await donateResponse.json();
				if (donateData.success) {
					resultSpan.innerText = '✅ ' + donateData.message;
					resultSpan.className = 'text-[11px] font-bold text-green-600 w-full mt-1';
					document.getElementById('donate-proxy-input').value = '';
				} else {
					resultSpan.innerText = ' ❌ خطا لطفا از ربات اهدا کنید : ' + donateData.error;
					resultSpan.className = 'text-[11px] font-bold text-red-500 w-full mt-1 break-words';
				}
			} catch (error) {
				clearTimeout(timeoutId);
				let errorMsg = error.message;
				if (error.name === 'AbortError') errorMsg = 'تایم‌اوت در تست پـروکـسـی';
				resultSpan.innerText = ' ❌ خطا لطفا در ربات اهدا کنید : ' + errorMsg;
				resultSpan.className = 'text-[11px] font-bold text-red-500 w-full mt-1 break-words';
			} finally {
				btn.disabled = false;
				btn.innerText = 'تست و اهدا';
			}
		}
		function toggleSupportModal(show) {
			const modal = document.getElementById('support-modal');
			const content = modal.firstElementChild;
			if (show) {
				modal.classList.remove('opacity-0', 'pointer-events-none');
				content.classList.remove('opacity-0', 'scale-95');
			} else {
				modal.classList.add('opacity-0', 'pointer-events-none');
				content.classList.add('opacity-0', 'scale-95');
			}
		}
		function toggleImportModal(show) {
			setModalState('import-modal', show);
			if (show) {
				const statusArea = document.getElementById('import-status-area');
				const logEl = document.getElementById('import-log');
				const progressBar = document.getElementById('import-progress-bar');
				if (statusArea) statusArea.classList.add('hidden');
				if (logEl) logEl.innerHTML = '';
				if (progressBar) progressBar.style.width = '0%';
			}
		}
		window.toggleImportModal = toggleImportModal;
		// Import Users: reads a pasted JSON array of x-ui-style client objects
		// and creates one panel user per client. Only client.email (-> username)
		// and client.id (-> uuid) are used; every other field is created with
		// the exact same defaults openCreateModal() applies for a manual
		// "add user" (fingerprint ios, port = default_port setting (2083
		// fallback), auto-reset on, pinned 5-country proxy list via the
		// backend, etc.) so this stays in sync with whatever those defaults
		// happen to be.
		async function startImportUsers() {
			const raw = document.getElementById('import-json-input').value.trim();
			if (!raw) { alert('⚠️ لطفا کد JSON را پیست کنید!'); return; }
			let parsed;
			try {
				parsed = JSON.parse(raw);
			} catch (e) {
				alert('⚠️ JSON نامعتبر است: ' + e.message);
				return;
			}
			const items = Array.isArray(parsed) ? parsed : [parsed];
			const usernameRegex = /^[a-zA-Z0-9_-]+$/;
			const uuidFormatRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
			const seenUsernames = new Set();
			const uuidOwners = {};
			const candidates = [];
			const preWarnings = [];
			items.forEach((item, i) => {
				const client = (item && item.client) ? item.client : item;
				const username = (client && client.email) ? String(client.email).trim() : '';
				const uuid = (client && client.id) ? String(client.id).trim().toLowerCase() : '';
				if (!username || !uuid) { preWarnings.push({ level: 'skip', text: '#' + (i + 1) + ': فیلد email یا id موجود نیست، رد شد' }); return; }
				if (!usernameRegex.test(username)) { preWarnings.push({ level: 'skip', text: username + ': نام کاربری نامعتبر (فقط حروف انگلیسی/عدد/-/_)، رد شد' }); return; }
				if (!uuidFormatRegex.test(uuid)) { preWarnings.push({ level: 'skip', text: username + ': فرمت UUID نامعتبر، رد شد' }); return; }
				if (seenUsernames.has(username)) { preWarnings.push({ level: 'skip', text: username + ': نام کاربری تکراری در همین فایل، رد شد' }); return; }
				seenUsernames.add(username);
				(uuidOwners[uuid] = uuidOwners[uuid] || []).push(username);
				candidates.push({ username, uuid });
			});
			Object.keys(uuidOwners).forEach((uuid) => {
				if (uuidOwners[uuid].length > 1) {
					preWarnings.push({ level: 'warn', text: 'UUID یکسان بین ' + uuidOwners[uuid].join('، ') + ' — فقط یکی از این کانفیگ‌ها عملا وصل می‌شود' });
				}
			});
			if (candidates.length === 0) {
				alert('⚠️ هیچ کلاینت معتبری برای ایمپورت پیدا نشد.');
				return;
			}
			if (!await customConfirm(candidates.length + ' کاربر با تنظیمات پیش‌فرض «ایجاد کاربر جدید» ساخته می‌شود. ادامه می‌دهید؟')) return;
			const startBtn = document.getElementById('import-start-btn');
			startBtn.disabled = true;
			startBtn.innerText = 'در حال ایمپورت...';
			const statusArea = document.getElementById('import-status-area');
			const progressText = document.getElementById('import-progress-text');
			const progressBar = document.getElementById('import-progress-bar');
			const logEl = document.getElementById('import-log');
			statusArea.classList.remove('hidden');
			logEl.innerHTML = '';
			preWarnings.forEach((w) => {
				const color = w.level === 'warn' ? 'text-amber-600 dark:text-amber-400' : 'text-gray-500 dark:text-zinc-400';
				logEl.innerHTML += '<div class="' + color + '">⚠️ ' + w.text + '</div>';
			});
			let done = 0, ok = 0, failed = 0;
			const nudImp = window.getNewUserDefaultsTyped();
			for (const c of candidates) {
				progressText.innerText = 'در حال ایجاد (' + (done + 1) + '/' + candidates.length + '): ' + c.username;
				try {
					const response = await fetch('/api/users', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({
							username: c.username,
							uuid: c.uuid,
							limit_gb: null,
							expiry_days: null,
							limit_req: null,
							tls: 'on',
							port: window.DEFAULT_PORT_SETTING || '2083',
							ips: window.GLOBAL_CLEAN_IP || window.DEFAULT_GLOBAL_CLEAN_IP || '104.20.25.138',
							fingerprint: nudImp.fingerprint,
							ip_limit: null,
							block_porn: nudImp.block_porn ? 1 : 0,
							block_ads: nudImp.block_ads ? 1 : 0,
							frag_len: nudImp.frag_len,
							frag_int: nudImp.frag_int,
							advanced_frag: null,
							cipher_suites: null,
							tls_mask: null,
							user_proxy_iata: null,
							user_socks5: null,
							user_proxy_ip: null,
							auto_reset_vol_days: nudImp.auto_reset_vol_days,
							auto_reset_req_days: nudImp.auto_reset_req_days,
							auto_rotate_ip: nudImp.auto_rotate_ip ? 1 : 0,
							rotate_time: 0,
							ip_operator: nudImp.ip_operator,
							ip_count: nudImp.ip_count,
							auto_rotate_user_proxy: nudImp.auto_rotate_user_proxy ? 1 : 0,
							start_on_first_connect: nudImp.start_on_first_connect ? 1 : 0,
							enable_direct: nudImp.enable_direct,
							connection_type: nudImp.connection_type,
							protocols: nudImp.protocols
						})
					});
					if (response.ok) {
						ok++;
						logEl.innerHTML += '<div class="text-green-600 dark:text-green-400">✅ ' + c.username + '</div>';
					} else {
						failed++;
						let errMsg = 'خطای نامشخص';
						try { const errData = await response.json(); errMsg = errData.error || errMsg; } catch (e) {}
						logEl.innerHTML += '<div class="text-red-600 dark:text-red-400">❌ ' + c.username + ': ' + errMsg + '</div>';
					}
				} catch (e) {
					failed++;
					logEl.innerHTML += '<div class="text-red-600 dark:text-red-400">❌ ' + c.username + ': خطا در ارتباط با سرور</div>';
				}
				done++;
				progressBar.style.width = Math.round((done / candidates.length) * 100) + '%';
				logEl.scrollTop = logEl.scrollHeight;
			}
			progressText.innerText = 'پایان: ' + ok + ' موفق، ' + failed + ' ناموفق از ' + candidates.length;
			startBtn.disabled = false;
			startBtn.innerText = 'شروع ایمپورت';
			await loadUsers(true);
		}
		window.startImportUsers = startImportUsers;
		window.testDirectPing = async function() {
			const btn = document.getElementById('test-direct-btn');
			const clientPingEl = document.getElementById('client-to-server-ping');
			const serverPingEl = document.getElementById('server-to-net-ping');

			if (btn) {
				btn.disabled = true;
				btn.innerHTML = '<svg class="w-3.5 h-3.5 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg><span> در حال تست...</span>';
			}
			clientPingEl.innerText = 'تست...';
			clientPingEl.className = 'text-[10px] font-bold text-amber-500';
			serverPingEl.innerText = 'تست...';
			serverPingEl.className = 'text-[10px] font-bold text-amber-500';

			let clientPing = '-';
			try {
				const startClient = Date.now();
				await fetch('/icon.svg?t=' + startClient, { method: 'HEAD', cache: 'no-store' });
				const elapsed = Date.now() - startClient;
				clientPing = elapsed;
				
				let cColor = "text-red-500";
				if (elapsed <= 150) cColor = "text-green-500";
				else if (elapsed <= 300) cColor = "text-amber-500";
				
				clientPingEl.innerText = elapsed + ' ms';
				clientPingEl.className = 'text-[10px] font-bold ' + cColor;
			} catch (e) {
				clientPingEl.innerText = 'خطا';
				clientPingEl.className = 'text-[10px] font-bold text-red-500';
			}

			try {
				const controller = new AbortController();
				const timeoutId = setTimeout(() => controller.abort(), 6000);
				const res = await fetch('/api/test-proxy', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ proxy: 'direct', skip_country: true }),
					signal: controller.signal
				});
				clearTimeout(timeoutId);
				const data = await res.json();
				
				if (res.ok && data.success) {
					const sPing = data.ping;
					let sColor = "text-red-500";
					if (sPing <= 50) sColor = "text-green-500";
					else if (sPing <= 150) sColor = "text-amber-500";
					
					serverPingEl.innerText = sPing + ' ms';
					serverPingEl.className = 'text-[10px] font-bold ' + sColor;
				} else {
					serverPingEl.innerText = 'خطا';
					serverPingEl.className = 'text-[10px] font-bold text-red-500 text-center';
				}
			} catch (e) {
				serverPingEl.innerText = 'خطا';
				serverPingEl.className = 'text-[10px] font-bold text-red-500 text-center';
			}

			if (btn) {
				btn.disabled = false;
				btn.innerHTML = '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg><span>تست اتصال مستقیم</span>';
			}
		};
	</script>
	  </body>
</html>`,
	status: `<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>وضعیت اشتراک کاربر</title>
	${COMMON_HEAD}
	<style>
		body { font-family: 'Vazirmatn', sans-serif; }
		.glass {
			background: rgba(17, 26, 46, 0.75);
			border: 1px solid rgba(255, 255, 255, 0.06);
		}
		.zeus-flag {
			display: inline-block;
			width: 1.35em;
			height: 1em;
			vertical-align: -0.15em;
			border-radius: 2px;
			background-size: cover;
			background-position: 50%;
			background-repeat: no-repeat;
		}
		.zeus-flag-globe {
			font-size: 1.1em;
			line-height: 1;
			vertical-align: -0.05em;
		}
		.req-ring-svg { transform: rotate(-90deg); }
		.req-ring-track { stroke: currentColor; }
		.req-ring-bar {
			stroke-linecap: round;
			animation: reqRingReach 2.2s ease-in-out infinite;
		}
		@keyframes reqRingReach {
			0%, 100% { stroke-dashoffset: var(--req-offset); filter: drop-shadow(0 0 0 transparent); }
			50% { stroke-dashoffset: var(--req-offset-reach); filter: drop-shadow(0 0 3px currentColor); }
		}
	</style>
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex flex-col items-center py-12 px-4 overflow-x-hidden">
	<div class="w-full max-w-xl glass rounded-md shadow-2xl p-6 md:p-8 relative overflow-hidden z-10">
		<div class="text-center mb-8 relative z-10">
			<div class="inline-flex items-center justify-center p-3 bg-navy-800/60 border border-navy-500 text-navy-100 rounded-md mb-4">
				<svg class="w-8 h-8 text-navy-100" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
			</div>
			<h1 class="text-xl font-bold tracking-tight text-gray-900 dark:text-white mb-1">پـنـل زئــوس - وضعیت اشتراک</h1>
			<p id="display-username" class="text-sm font-bold text-navy-400 tracking-wide font-mono mb-2"></p>
			<p id="display-flag" class="text-2xl font-bold tracking-wide mb-3" style="display:none;"></p>
			<div id="live-connections-badge" style="display: none !important;">
				<span class="w-2 h-2 rounded-full bg-green-600 animate-pulse"></span>
				<span id="live-connections-text" dir="rtl">۰ دستگاه متصل</span>
			</div>
		</div>
		<div id="status-card" class="mb-6 rounded-md p-4 text-center border font-bold relative z-10 transition duration-300">
			<span id="status-text" class="text-sm">در حال بارگذاری وضعیت...</span>
		</div>
		<div class="grid grid-cols-2 gap-3 mb-8 relative z-10" style="direction:ltr;">
			<div dir="rtl" class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-md p-3 shadow-sm flex flex-col justify-between">
				<div class="flex justify-between items-center mb-2">
					<span class="text-[10px] font-semibold text-gray-600 dark:text-zinc-400 flex items-center gap-1">
						<svg class="w-3.5 h-3.5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
						حجم مصرفی
					</span>
					<span id="volume-pct" class="text-[10px] font-bold text-gray-800 dark:text-zinc-200">۰٪</span>
				</div>
				<div id="volume-progress-wrap" class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-1.5 overflow-hidden mb-2">
					<div id="volume-progress" class="h-1.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
				</div>
				<div id="volume-amounts-row" class="flex justify-between text-[9px] text-gray-500 dark:text-zinc-400 font-medium">
					<span id="used-vol" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">-</span>
					<span id="limit-vol" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">-</span>
				</div>
			</div>
			<div dir="rtl" class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-md p-3 shadow-sm flex flex-col justify-between">
				<div class="flex justify-between items-center mb-2">
					<span class="text-[10px] font-semibold text-gray-600 dark:text-zinc-400 flex items-center gap-1">
						<svg class="w-3.5 h-3.5 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
						زمان باقی‌مانده
					</span>
					<span id="expiry-pct" class="text-[10px] font-bold text-gray-800 dark:text-zinc-200">۰٪</span>
				</div>
				<div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-1.5 overflow-hidden mb-2 flex justify-end">
					<div id="expiry-progress" class="h-1.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
				</div>
				<div class="flex justify-between text-[9px] text-gray-500 dark:text-zinc-400 font-medium">
					<span id="days-remaining" class="font-bold text-gray-800 dark:text-zinc-200" dir="rtl">-</span>
					<span id="total-days" class="font-bold text-gray-800 dark:text-zinc-200" dir="rtl">-</span>
				</div>
			</div>
			<div dir="rtl" class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-md p-3 shadow-sm flex flex-col justify-between">
				<div class="flex justify-between items-center mb-2">
					<span class="text-[10px] font-semibold text-gray-600 dark:text-zinc-400 flex items-center gap-1">
						<svg class="w-3.5 h-3.5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
						ریکوئست‌ها
					</span>
				</div>
				<div id="req-progress-wrap" class="flex items-center justify-center mb-1">
					<div class="relative w-[48.4px] h-[48.4px] shrink-0">
						<svg class="req-ring-svg w-[48.4px] h-[48.4px]" viewBox="0 0 40 40">
							<circle class="req-ring-track text-gray-200 dark:text-zinc-800" cx="20" cy="20" r="16" fill="none" stroke-width="3.5"></circle>
							<circle id="req-progress" class="req-ring-bar" cx="20" cy="20" r="16" fill="none" stroke-width="3.5" stroke-dasharray="100.53" style="--req-offset:100.53; --req-offset-reach:100.53; stroke-dashoffset:100.53;"></circle>
						</svg>
						<span id="req-pct" class="absolute inset-0 flex items-center justify-center text-[9px] font-bold text-gray-800 dark:text-zinc-200">۰٪</span>
					</div>
					<div id="req-amounts-row" class="hidden flex-col justify-center gap-1 text-[9px] text-gray-500 dark:text-zinc-400 font-medium">
						<span dir="ltr">مصرف: <span id="used-req" class="font-bold text-gray-800 dark:text-zinc-200">-</span></span>
						<span dir="ltr">سقف: <span id="limit-req" class="font-bold text-gray-800 dark:text-zinc-200">-</span></span>
					</div>
				</div>
			</div>
			<div dir="rtl" class="bg-white/40 dark:bg-zinc-900/30 border border-gray-200 dark:border-amoled-border rounded-md p-3 shadow-sm flex flex-col justify-between">
				<div class="flex justify-between items-center mb-2">
					<span class="text-[10px] font-semibold text-gray-600 dark:text-zinc-400 flex items-center gap-1">
						<svg class="w-3.5 h-3.5 text-sky-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
						دستگاه متصل
					</span>
					<span id="online-pct" class="text-[10px] font-bold text-gray-800 dark:text-zinc-200">۰٪</span>
				</div>
				<div class="w-full bg-gray-200 dark:bg-zinc-800 rounded-full h-1.5 overflow-hidden mb-2">
					<div id="online-progress" class="h-1.5 rounded-full transition-all duration-1000" style="width: 0%"></div>
				</div>
				<div class="flex justify-between text-[9px] text-gray-500 dark:text-zinc-400 font-medium">
					<span id="online-count" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">۰</span>
					<span id="limit-online" class="font-bold text-gray-800 dark:text-zinc-200" dir="ltr">-</span>
				</div>
			</div>
		</div>
		<div class="border-t border-gray-100 dark:border-zinc-800 pt-6 relative z-10">
			<h2 class="text-sm font-bold mb-4 flex items-center gap-2">
				<svg class="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
				دریافت کـانفـیگ و اشتراک‌ها
			</h2>
			<div class="space-y-3">
				<button onclick="copyTextSub()" class="w-full flex justify-between items-center px-4 py-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border hover:border-indigo-500 dark:hover:border-indigo-500 rounded-md text-xs font-medium transition shadow-sm">
					<span class="flex items-center gap-2"><svg class="w-4 h-4 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg> کپی لینک ساب‌اسکریپشن متنی</span>
					<span class="text-indigo-500">کپی</span>
				</button>
				<button onclick="showSubQr()" class="w-full flex justify-between items-center px-4 py-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border hover:border-amber-500 dark:hover:border-amber-500 rounded-md text-xs font-medium transition shadow-sm">
					<span class="flex items-center gap-2"><svg class="w-4 h-4 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm14 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 19h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"></path></svg> دریافت کیوآر کد ساب</span>
					<span class="text-amber-500">نمایش</span>
				</button>
				<button onclick="copySingboxSub()" class="!hidden w-full flex justify-between items-center px-4 py-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border hover:border-purple-500 dark:hover:border-purple-500 rounded-md text-xs font-medium transition shadow-sm">
					<span class="flex items-center gap-2"><svg class="w-4 h-4 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"></path></svg> کپی لینک ساب‌اسکریپشن Sing-box</span>
					<span class="text-purple-500">کپی</span>
				</button>
				<button onclick="showSingboxQr()" class="!hidden w-full flex justify-between items-center px-4 py-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border hover:border-pink-500 dark:hover:border-pink-500 rounded-md text-xs font-medium transition shadow-sm">
					<span class="flex items-center gap-2"><svg class="w-4 h-4 text-pink-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm14 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 19h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"></path></svg> دریافت کیوآر کد ساب Sing-box</span>
					<span class="text-pink-500">نمایش</span>
				</button>
				<button onclick="copyvIeesConfig()" class="w-full flex justify-between items-center px-4 py-3 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border hover:border-blue-500 dark:hover:border-blue-500 rounded-md text-xs font-medium transition shadow-sm">
					<span class="flex items-center gap-2"><svg class="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg> کپی کـانفـیگ‌های اتصال (مستقیم)</span>
					<span class="text-blue-500">کپی</span>
				</button>
			</div>
		</div>
		<div class="border-t border-gray-100 dark:border-zinc-800 pt-6 mt-6 relative z-10 w-full">
			<button onclick="document.getElementById('software-downloads-content').classList.toggle('hidden'); document.getElementById('software-downloads-icon').classList.toggle('rotate-180');" class="w-full flex items-center justify-between text-sm font-bold mb-4 cursor-pointer focus:outline-none">
				<div class="flex items-center gap-2">
					<svg class="w-4 h-4 text-pink-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
					<span>دانلود نرم افزار ها</span>
				</div>
				<svg id="software-downloads-icon" class="w-4 h-4 text-gray-500 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
			</button>
			<div id="software-downloads-content" class="hidden grid grid-cols-1 sm:grid-cols-3 gap-3">
				<div class="bg-green-50/50 dark:bg-green-950/20 border border-green-200/50 dark:border-green-800/30 rounded-md p-2.5">
					<div class="flex items-center gap-1.5 mb-2.5 text-green-700 dark:text-green-500 font-bold text-[11px]">
						<svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M17.523 15.3414c-.5511 0-.9993-.4486-.9993-.9997s.4482-.9993.9993-.9993c.5511 0 .9993.4482.9993.9993.0004.5511-.4482.9997-.9993.9997m-11.046 0c-.5511 0-.9993-.4486-.9993-.9997s.4482-.9993.9993-.9993c.5511 0 .9993.4482.9993.9993 0 .5511-.4482.9997-.9993.9997m11.4045-6.02L19.695 6.183c.1568-.2716.0637-.6182-.2079-.7754-.2716-.1564-.6183-.0633-.775.2082l-1.8584 3.2185c-1.3853-.6328-2.9697-.9881-4.6644-.9881-1.6946 0-3.279.3553-4.664.9881L5.6664 5.6158c-.1567-.2715-.5038-.3646-.775-.2082-.2716.1572-.3647.5038-.2079.7754l1.8136 3.1385C2.963 11.2384 1.1571 14.5422 1 18.4234h22c-.1572-3.8812-1.963-7.185-5.4955-9.102"/></svg>
						اندروید
					</div>
					<div class="flex flex-col gap-1.5">
						<a href="https://github.com/patterniha/PattNG/releases/latest" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-green-300 dark:border-green-800 px-2 py-1.5 rounded text-[10px] font-bold text-green-700 dark:text-green-400 hover:border-green-500 dark:hover:border-green-500 transition shadow-sm"><span>PattNG (پیشنهادی)</span><span class="text-green-500 text-[12px]">📥</span></a>
						<a href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>v2rayNG</span><span class="text-green-500 text-[12px]">📥</span></a>
						<a href="https://github.com/Happ-proxy/happ-android/releases/latest/download/Happ.apk" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>happ</span><span class="text-green-500 text-[12px]">📥</span></a>
						<a href="https://github.com/hiddify/hiddify-app/releases/latest/download/Hiddify-Android-universal.apk" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>Hiddify</span><span class="text-green-500 text-[12px]">📥</span></a>
						<a href="https://play.google.com/store/apps/details?id=com.napsternetlabs.napsternetv" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>Npv Tunnel</span><span class="text-green-500 text-[12px]">📥</span></a>
						<a href="https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>V2Box</span><span class="text-green-500 text-[12px]">📥</span></a>
						<a href="https://github.com/KaringX/karing/releases/latest" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>Karing</span><span class="text-green-500 text-[12px]">📥</span></a>
						<a href="https://github.com/ExclaveNetwork/Exclave/releases/latest" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-green-400 dark:hover:border-green-500 transition shadow-sm"><span>Exclave</span><span class="text-green-500 text-[12px]">📥</span></a>
					</div>
				</div>
				<div class="bg-blue-50/50 dark:bg-blue-950/20 border border-blue-200/50 dark:border-blue-800/30 rounded-md p-2.5">
					<div class="flex items-center gap-1.5 mb-2.5 text-blue-700 dark:text-blue-500 font-bold text-[11px]">
						<svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-13.051-1.801"/></svg>
						ویندوز
					</div>
					<div class="flex flex-col gap-1.5">
						<a href="https://github.com/patterniha/PattN/releases/latest/download/PattN-windows-64.zip" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-blue-300 dark:border-blue-800 px-2 py-1.5 rounded text-[10px] font-bold text-blue-700 dark:text-blue-400 hover:border-blue-500 dark:hover:border-blue-500 transition shadow-sm"><span>PattN (پیشنهادی)</span><span class="text-blue-500 text-[12px]">📥</span></a>
						<a href="https://github.com/2dust/v2rayN/releases/latest/download/v2rayN-windows-64.zip" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-blue-400 dark:hover:border-blue-500 transition shadow-sm"><span>v2rayN</span><span class="text-blue-500 text-[12px]">📥</span></a>
						<a href="https://github.com/Happ-proxy/happ-desktop/releases/latest/download/setup-Happ.x64.exe" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-blue-400 dark:hover:border-blue-500 transition shadow-sm"><span>happ</span><span class="text-blue-500 text-[12px]">📥</span></a>
						<a href="https://github.com/hiddify/hiddify-app/releases/latest/download/Hiddify-Windows-Setup-x64.exe" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-blue-400 dark:hover:border-blue-500 transition shadow-sm"><span>Hiddify</span><span class="text-blue-500 text-[12px]">📥</span></a>
						<a href="https://github.com/KaringX/karing/releases/latest" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-blue-400 dark:hover:border-blue-500 transition shadow-sm"><span>Karing</span><span class="text-blue-500 text-[12px]">📥</span></a>
					</div>
				</div>
				<div class="bg-gray-50/50 dark:bg-zinc-800/30 border border-gray-200/50 dark:border-gray-700/50 rounded-md p-2.5">
					<div class="flex items-center gap-1.5 mb-2.5 text-gray-700 dark:text-gray-300 font-bold text-[11px]">
						<svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.05 2.95.72 3.88 1.84-3.46 2.06-2.89 6.18.54 7.42-.85 1.58-1.54 2.82-3.07 3.75zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z"/></svg>
						آیفون
					</div>
					<div class="flex flex-col gap-1.5">
						<a href="https://apps.apple.com/us/app/v2box-v2ray-client/id6446814690" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm"><span>V2Box</span><span class="text-gray-500 text-[12px]">📥</span></a>
						<a href="https://apps.apple.com/us/app/streisand/id6450534064" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm"><span>Streisand</span><span class="text-gray-500 text-[12px]">📥</span></a>
						<a href="https://apps.apple.com/us/app/npv-tunnel/id1629465476" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm"><span>NapsternetV</span><span class="text-gray-500 text-[12px]">📥</span></a>
						<a href="https://apps.apple.com/us/app/happ-proxy-utility/id6504287215" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm"><span>happ</span><span class="text-gray-500 text-[12px]">📥</span></a>
						<a href="https://apps.apple.com/us/app/hiddify-proxy-vpn/id6596777532" target="_blank" class="flex justify-between items-center bg-white dark:bg-amoled-card border border-gray-100 dark:border-zinc-800 px-2 py-1.5 rounded text-[10px] font-semibold text-gray-700 dark:text-zinc-300 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm"><span>Hiddify</span><span class="text-gray-500 text-[12px]">📥</span></a>
					</div>
				</div>
			</div>
		</div>
	</div>
<div id="qr-modal" class="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
	<div id="qr-modal-card" class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-md shadow-2xl p-6 transform transition-all scale-95 opacity-0 duration-200 text-center">
		<div class="flex justify-between items-center mb-4">
			<h3 class="text-lg font-bold text-gray-900 dark:text-white">QR Code</h3>
			<button onclick="toggleQrModal(false)" class="p-1.5 rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-500 hover:bg-red-100 dark:hover:bg-red-900/50 transition-all duration-200 shadow-sm">
				<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
			</button>
		</div>
		<div class="flex justify-center bg-gray-100 dark:bg-amoled-bg p-4 rounded-md mb-4 border border-gray-200 dark:border-zinc-800">
			<div id="qrcode-container"></div>
		</div>
		<button onclick="downloadQrCode()" class="w-full py-2.5 bg-green-700 hover:bg-green-800 dark:bg-green-600 dark:hover:bg-green-700 text-white font-bold rounded-md text-sm transition duration-200 shadow-sm flex items-center justify-center gap-2">
			<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
			دانلود تصویر QR
		</button>
	</div>
</div>
<div class="flex flex-col gap-4 mt-6 relative z-10">
	<div class="flex flex-wrap items-center gap-3 sm:gap-4 justify-center">
		<a href="https://github.com/panel-zeus/Z-E-U-S" target="_blank" class="flex items-center gap-2 px-4 py-2 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-full shadow-sm hover:shadow-md transition text-sm font-bold text-gray-700 dark:text-zinc-300 hover:text-black dark:hover:text-white group">
			<svg class="w-5 h-5 group-hover:scale-110 transition" viewBox="0 0 24 24" fill="currentColor">
				<path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.87 8.17 6.84 9.5.5.08.66-.23.66-.5v-1.69c-2.77.6-3.36-1.34-3.36-1.34-.46-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.87 1.52 2.34 1.07 2.91.83.09-.65.35-1.09.63-1.34-2.22-.25-4.55-1.11-4.55-4.92 0-1.11.38-2 1.03-2.71-.1-.25-.45-1.29.1-2.64 0 0 .84-.27 2.75 1.02.79-.22 1.65-.33 2.5-.33.85 0 1.71.11 2.5.33 1.91-1.29 2.75-1.02 2.75-1.02.55 1.35.2 2.39.1 2.64.65.71 1.03 1.6 1.03 2.71 0 3.82-2.34 4.66-4.57 4.91.36.31.69.92.69 1.85V21c0 .27.16.59.67.5C19.14 20.16 22 16.42 22 12A10 10 0 0012 2z"/>
			</svg>
			گیت‌هاب
		</a>
		<a href="https://t.me/PANEL_ZEUS" target="_blank" class="flex items-center gap-2 px-4 py-2 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-full shadow-sm hover:shadow-md transition text-sm font-bold text-gray-700 dark:text-zinc-300 hover:text-sky-500 dark:hover:text-sky-400 group">
			<svg class="w-5 h-5 text-sky-500 group-hover:scale-110 transition" viewBox="0 0 24 24" fill="currentColor">
				<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69a.2.2 0 00-.05-.18c-.06-.05-.14-.03-.21-.02-.09.02-1.49.94-4.22 2.79-.4.27-.76.41-1.08.4-.36-.01-1.04-.2-1.55-.37-.63-.2-1.12-.31-1.08-.66.02-.18.27-.36.74-.55 2.92-1.27 4.86-2.11 5.83-2.51 2.78-1.16 3.35-1.36 3.73-1.37.08 0 .27.02.39.12.1.08.13.19.14.27-.01.06.01.24 0 .24z"/>
			</svg>
			@
		</a>
	</div>
	<div class="flex flex-wrap items-center gap-3 sm:gap-4 justify-center">
		<a href="https://t.me/ZEUS_PANEL_BOT" target="_blank" class="flex items-center gap-2 px-4 py-2 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-full shadow-sm hover:shadow-md transition text-sm font-bold text-amber-600 dark:text-amber-400 hover:text-amber-500 dark:hover:text-amber-300 group">
			<svg class="w-5 h-5 text-amber-500 dark:text-amber-400 group-hover:scale-110 transition" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z"/>
			</svg>
			ساخت رایگان پـنـل
		</a>
		<a href="https://donatonion.ir-netlify.workers.dev" target="_blank" class="flex items-center gap-2 px-4 py-2 bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-full shadow-sm hover:shadow-md transition text-sm font-bold text-red-600 dark:text-red-400 hover:text-red-500 dark:hover:text-red-300 group">
			<svg class="w-5 h-5 text-red-500 dark:text-red-400 group-hover:scale-110 transition" fill="currentColor" viewBox="0 0 24 24">
				<path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3 9.24 3 10.91 3.81 12 5.08 13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/>
			</svg>
			دونیت
		</a>
	</div>
</div>
${COMMON_TOAST_HTML}
	<script>
		/* {{USER_DATA_PLACEHOLDER}} */
		${COMMON_TOAST_JS}
		function getHost() {
			return window.location.host;
		}
		function generateInlineProxyJunkClient(len) {
			len = len || 10;
			const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
			let out = '';
			for (let i = 0; i < len; i++) out += chars.charAt(Math.floor(Math.random() * chars.length));
			return out;
		}
		function buildInlineProxyIpSegment(ip) {
			if (!ip || typeof ip !== 'string' || !ip.trim()) return '';
			try {
				const payload = { junk: generateInlineProxyJunkClient(10), protocol: 'vl', mode: 'proxyip', panelIPs: [ip.trim()] };
				return '/' + btoa(JSON.stringify(payload)).replace(/\\+/g, '-').replace(/\\//g, '_');
			} catch (e) {
				return '';
			}
		}
		function getvIeesLink() {
			const u = window.statusUser;
			if (!u) return '';
			const host = getHost();
			var ips = [host];
			if (u.ips) {
				const parsedIps = u.ips.split('\\n').map(function(ip) { return ip.trim(); }).filter(function(ip) { return ip.length > 0; });
				if (parsedIps.length > 0) ips = parsedIps;
			}
			var ports = String(u.port || '443').split(',').map(function(p) { return p.trim(); }).filter(function(p) { return p.length > 0; });
			var fp = u.fingerprint || 'chrome';
			// Early Data (ed=): همان منطق سمت سرور (SubscriptionService.generateText) و صفحه‌ی Status - فقط وقتی
			// early_data_enabled روشن باشد، ?ed=<size> به انتهای path اضافه می‌شود (قبل از encodeURIComponent)؛
			// سایز نامعتبر (خارج از 1..8192) = 2560. خاموش/نبودن فیلد = path دقیقاً مثل قبل.
			let edSuffix = "";
			if (Number(u.early_data_enabled) === 1) {
				const edSizeRaw = parseInt(u.early_data_size, 10);
				edSuffix = "?ed=" + ((edSizeRaw >= 1 && edSizeRaw <= 8192) ? edSizeRaw : 2560);
			}
			const links = [];
			let remVol = "Unlimited";
			if (u.limit_gb) {
				let rem = u.limit_gb - (u.used_gb || 0);
				remVol = rem > 0 ? rem.toFixed(2) + "GB" : "0GB";
			}
			let remTime = "Unlimited";
			if (u.expiry_days && u.created_at) {
				const created = new Date(u.created_at);
				const expiryDate = new Date(created.getTime() + u.expiry_days * 24 * 60 * 60 * 1000);
				const diffDays = Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
				remTime = diffDays > 0 ? diffDays + "Days" : "0Days";
			}
			let remReq = "Unlimited";
			if (u.limit_req) {
				let rem = u.limit_req - (u.used_req || 0);
				remReq = rem > 0 ? rem.toLocaleString() + "Req" : "0Req";
			}
			const rawPath = "/XYZ";
			const inlineProxySegment = buildInlineProxyIpSegment(window.INLINE_PROXY_IP);
			// Same ISO 3166-1 alpha-2 -> alpha-3 table as the server-side one (see
			// getLocationPathSegment() near the top of the worker source) -
			// duplicated here because this runs in the browser. Works for ANY
			// country in the VIP repo, not just currently-pinned ones.
			const ISO_ALPHA3_MAP = {
				AD: "AND", AE: "ARE", AF: "AFG", AG: "ATG", AI: "AIA", AL: "ALB",
				AM: "ARM", AO: "AGO", AQ: "ATA", AR: "ARG", AS: "ASM", AT: "AUT",
				AU: "AUS", AW: "ABW", AX: "ALA", AZ: "AZE", BA: "BIH", BB: "BRB",
				BD: "BGD", BE: "BEL", BF: "BFA", BG: "BGR", BH: "BHR", BI: "BDI",
				BJ: "BEN", BL: "BLM", BM: "BMU", BN: "BRN", BO: "BOL", BQ: "BES",
				BR: "BRA", BS: "BHS", BT: "BTN", BV: "BVT", BW: "BWA", BY: "BLR",
				BZ: "BLZ", CA: "CAN", CC: "CCK", CD: "COD", CF: "CAF", CG: "COG",
				CH: "CHE", CI: "CIV", CK: "COK", CL: "CHL", CM: "CMR", CN: "CHN",
				CO: "COL", CR: "CRI", CU: "CUB", CV: "CPV", CW: "CUW", CX: "CXR",
				CY: "CYP", CZ: "CZE", DE: "DEU", DJ: "DJI", DK: "DNK", DM: "DMA",
				DO: "DOM", DZ: "DZA", EC: "ECU", EE: "EST", EG: "EGY", EH: "ESH",
				ER: "ERI", ES: "ESP", ET: "ETH", FI: "FIN", FJ: "FJI", FK: "FLK",
				FM: "FSM", FO: "FRO", FR: "FRA", GA: "GAB", GB: "GBR", GD: "GRD",
				GE: "GEO", GF: "GUF", GG: "GGY", GH: "GHA", GI: "GIB", GL: "GRL",
				GM: "GMB", GN: "GIN", GP: "GLP", GQ: "GNQ", GR: "GRC", GS: "SGS",
				GT: "GTM", GU: "GUM", GW: "GNB", GY: "GUY", HK: "HKG", HM: "HMD",
				HN: "HND", HR: "HRV", HT: "HTI", HU: "HUN", ID: "IDN", IE: "IRL",
				IL: "ISR", IM: "IMN", IN: "IND", IO: "IOT", IQ: "IRQ", IR: "IRN",
				IS: "ISL", IT: "ITA", JE: "JEY", JM: "JAM", JO: "JOR", JP: "JPN",
				KE: "KEN", KG: "KGZ", KH: "KHM", KI: "KIR", KM: "COM", KN: "KNA",
				KP: "PRK", KR: "KOR", KW: "KWT", KY: "CYM", KZ: "KAZ", LA: "LAO",
				LB: "LBN", LC: "LCA", LI: "LIE", LK: "LKA", LR: "LBR", LS: "LSO",
				LT: "LTU", LU: "LUX", LV: "LVA", LY: "LBY", MA: "MAR", MC: "MCO",
				MD: "MDA", ME: "MNE", MF: "MAF", MG: "MDG", MH: "MHL", MK: "MKD",
				ML: "MLI", MM: "MMR", MN: "MNG", MO: "MAC", MP: "MNP", MQ: "MTQ",
				MR: "MRT", MS: "MSR", MT: "MLT", MU: "MUS", MV: "MDV", MW: "MWI",
				MX: "MEX", MY: "MYS", MZ: "MOZ", NA: "NAM", NC: "NCL", NE: "NER",
				NF: "NFK", NG: "NGA", NI: "NIC", NL: "NLD", NO: "NOR", NP: "NPL",
				NR: "NRU", NU: "NIU", NZ: "NZL", OM: "OMN", PA: "PAN", PE: "PER",
				PF: "PYF", PG: "PNG", PH: "PHL", PK: "PAK", PL: "POL", PM: "SPM",
				PN: "PCN", PR: "PRI", PS: "PSE", PT: "PRT", PW: "PLW", PY: "PRY",
				QA: "QAT", RE: "REU", RO: "ROU", RS: "SRB", RU: "RUS", RW: "RWA",
				SA: "SAU", SB: "SLB", SC: "SYC", SD: "SDN", SE: "SWE", SG: "SGP",
				SH: "SHN", SI: "SVN", SJ: "SJM", SK: "SVK", SL: "SLE", SM: "SMR",
				SN: "SEN", SO: "SOM", SR: "SUR", SS: "SSD", ST: "STP", SV: "SLV",
				SX: "SXM", SY: "SYR", SZ: "SWZ", TC: "TCA", TD: "TCD", TF: "ATF",
				TG: "TGO", TH: "THA", TJ: "TJK", TK: "TKL", TL: "TLS", TM: "TKM",
				TN: "TUN", TO: "TON", TR: "TUR", TT: "TTO", TV: "TUV", TW: "TWN",
				TZ: "TZA", UA: "UKR", UG: "UGA", UM: "UMI", US: "USA", UY: "URY",
				UZ: "UZB", VA: "VAT", VC: "VCT", VE: "VEN", VG: "VGB", VI: "VIR",
				VN: "VNM", VU: "VUT", WF: "WLF", WS: "WSM", YE: "YEM", YT: "MYT",
				ZA: "ZAF", ZM: "ZMB", ZW: "ZWE",
			};
			const LOCATION_PATH_CODE_OVERRIDES = { GB: "G-b" };
			function getLocationPathSegment(countryCode, locIdx) {
				if (countryCode) {
					const cc = countryCode.toUpperCase();
					if (LOCATION_PATH_CODE_OVERRIDES[cc]) return LOCATION_PATH_CODE_OVERRIDES[cc];
					if (ISO_ALPHA3_MAP[cc]) return ISO_ALPHA3_MAP[cc].split("").map(function(ch, i) { return i === 0 ? ch : ch.toLowerCase(); }).join("-");
				}
				return "loc-" + locIdx;
			}
			let proxyList = [];
			try {
				if (u.user_socks5 && u.user_socks5.trim().startsWith("[")) {
					proxyList = JSON.parse(u.user_socks5);
				} else if (u.user_socks5 || u.user_proxy_ip) {
					proxyList = [u.user_socks5 || u.user_proxy_ip];
				} else {
					proxyList = [null];
				}
			} catch (e) {
				proxyList = [u.user_socks5 || u.user_proxy_ip];
			}
			if (!Array.isArray(proxyList) || proxyList.length === 0) proxyList = [];
			const allowDirect = u.enable_direct !== 0;
			if (allowDirect) {
				let hasDirect = proxyList.some(function(p) { return p === null || p === ""; });
				if (!hasDirect) proxyList.push(null);
			} else {
				proxyList = proxyList.filter(function(p) { return p !== null && p !== ""; });
			}
			if (proxyList.length === 0) proxyList = [null];
			let proxyFlagCache = {};
			try { proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}'); } catch(e) {}
			let resolvedProxies = [];
			for (let locIdx = 0; locIdx < proxyList.length; locIdx++) {
				let proxyItem = proxyList[locIdx];
				let proxyStr = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.proxy : proxyItem;
				let countryCode = typeof proxyItem === "object" && proxyItem !== null ? proxyItem.country : (u.user_proxy_iata || "");
				let flagEmoji = "🌐";
				if (countryCode && typeof getFlagEmojiText === 'function') {
					flagEmoji = getFlagEmojiText(countryCode);
				} else if (proxyStr && proxyFlagCache[proxyStr] && typeof getFlagEmojiText === 'function') {
					flagEmoji = getFlagEmojiText(proxyFlagCache[proxyStr]);
				}
				const currentDynPath = encodeURIComponent(rawPath + ((proxyItem !== null && proxyItem !== "") ? "/" + getLocationPathSegment(countryCode, locIdx) : inlineProxySegment) + edSuffix);
				resolvedProxies.push({ flagEmoji, currentDynPath });
			}
			const userConnType = String(u.connection_type || 'vless').toLowerCase();
			const enableVless = userConnType.includes('vless') || userConnType === 'vl' + 'e' + 'ss' || (!userConnType.includes('trojan'));
			const enableTrojan = userConnType.includes('trojan');
			ips.forEach((ip) => {
				ports.forEach((portStr) => {
					resolvedProxies.forEach((proxy) => {
						const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
						const tlsVal = isTlsPort ? "tls" : "none";
						let userFrag = "";
						if (u.frag_len && u.frag_int) userFrag += "&fragment=" + encodeURIComponent(u.frag_len + "," + u.frag_int + (isTlsPort ? ",tlshello" : ""));
						if (u.advanced_frag) userFrag += "&fm=" + encodeURIComponent(u.advanced_frag);
						if (isTlsPort && u.cipher_suites) userFrag += "&cs=" + encodeURIComponent(u.cipher_suites);
						if (u.tls_mask) userFrag += "&mask=" + encodeURIComponent(u.tls_mask);
						
						const tlsParams = isTlsPort ? ("&insecure=0&fp=" + fp + "&allowInsecure=0&sni=" + host) : "";

						if (enableVless) {
							const remark = proxy.flagEmoji;
							links.push('vle' + 'ss://' + (u.uuid || '') + '@' + ip + ':' + portStr + '?path=' + proxy.currentDynPath + '&security=' + tlsVal + '&encryption=none&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(remark));
						}
						if (enableTrojan) {
							const trojanRemark = proxy.flagEmoji;
							links.push('trojan://' + (u.uuid || '') + '@' + ip + ':' + portStr + '?path=' + proxy.currentDynPath + '&security=' + tlsVal + '&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(trojanRemark));
						}
					});
				});
			});
			const otherCleanIps = Array.isArray(window.OTHER_CLEAN_IPS) ? window.OTHER_CLEAN_IPS : [];
			if (otherCleanIps.length > 0) {
				const otherPortStr = ports[0] || '443';
				const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(otherPortStr);
				const tlsVal = isTlsPort ? "tls" : "none";
				let userFrag = "";
				if (u.frag_len && u.frag_int) userFrag += "&fragment=" + encodeURIComponent(u.frag_len + "," + u.frag_int + (isTlsPort ? ",tlshello" : ""));
				if (u.advanced_frag) userFrag += "&fm=" + encodeURIComponent(u.advanced_frag);
				if (isTlsPort && u.cipher_suites) userFrag += "&cs=" + encodeURIComponent(u.cipher_suites);
				if (u.tls_mask) userFrag += "&mask=" + encodeURIComponent(u.tls_mask);
				const tlsParams = isTlsPort ? ("&insecure=0&fp=" + fp + "&allowInsecure=0&sni=" + host) : "";
				const otherDynPath = encodeURIComponent(rawPath + inlineProxySegment + edSuffix);
				otherCleanIps.forEach(function(otherIp, otherIdx) {
					const remark = "🇩🇪 " + String(otherIdx + 1).padStart(2, "0");
					if (enableVless) {
						links.push('vle' + 'ss://' + (u.uuid || '') + '@' + otherIp + ':' + otherPortStr + '?path=' + otherDynPath + '&security=' + tlsVal + '&encryption=none&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(remark));
					}
					if (enableTrojan) {
						links.push('trojan://' + (u.uuid || '') + '@' + otherIp + ':' + otherPortStr + '?path=' + otherDynPath + '&security=' + tlsVal + '&host=' + host + '&type=ws' + tlsParams + userFrag + '#' + encodeURIComponent(remark));
					}
				});
			}
			return links.join('\\n');
		}
		function copyvIeesConfig() {
			navigator.clipboard.writeText(getvIeesLink()).then(() => alert('✅ کـانفـیگ با موفقیت کپی شد!'));
		}
		function copyTextSub() {
			const link = window.location.protocol + '//' + getHost() + '/notes/' + encodeURIComponent(window.statusUser.username);
			navigator.clipboard.writeText(link).then(() => alert('✅ لینک ساب متنی کپی شد!'));
		}
		function copySingboxSub() {
			const link = window.location.protocol + '//' + getHost() + '/bundle/' + encodeURIComponent(window.statusUser.username);
			navigator.clipboard.writeText(link).then(() => alert('✅ لینک ساب Sing-box کپی شد!'));
		}
		function toggleQrModal(show, text) {
			const modal = document.getElementById('qr-modal');
			const card = document.getElementById('qr-modal-card');
			const container = document.getElementById('qrcode-container');
			if (show) {
				container.innerHTML = '';
				const isDark = document.documentElement.classList.contains('dark');
				const qrCode = new QRCodeStyling({
					width: 220,
					height: 220,
					data: text,
					margin: 5,
					qrOptions: { errorCorrectionLevel: 'M' },
					dotsOptions: {
						color: isDark ? "#bfdbfe" : "#1e3a8a",
						type: "rounded"
					},
					backgroundOptions: {
						color: isDark ? "#0f172a" : "#ffffff"
					},
					cornersSquareOptions: {
						color: isDark ? "#60a5fa" : "#1e40af",
						type: "extra-rounded"
					},
					cornersDotOptions: {
						color: isDark ? "#60a5fa" : "#1d4ed8",
						type: "dot"
					}
				});
				qrCode.append(container);
				modal.classList.remove('opacity-0', 'pointer-events-none');
				modal.classList.add('opacity-100', 'pointer-events-auto');
				card.classList.remove('opacity-0', 'scale-95');
				card.classList.add('opacity-100', 'scale-100');
			} else {
				modal.classList.remove('opacity-100', 'pointer-events-auto');
				modal.classList.add('opacity-0', 'pointer-events-none');
				card.classList.remove('opacity-100', 'scale-100');
				card.classList.add('opacity-0', 'scale-95');
			}
		}
		function downloadQrCode() {
			const container = document.getElementById('qrcode-container');
			if (!container) return;
			const canvas = container.querySelector('canvas');
			const img = container.querySelector('img');
			let dataUrl = '';
			if (canvas) {
				dataUrl = canvas.toDataURL("image/png");
			} else if (img && img.src) {
				dataUrl = img.src;
			}
			if (!dataUrl) {
				alert('⚠️ تصویر QR برای دانلود یافت نشد!');
				return;
			}
			const downloadAnchor = document.createElement('a');
			downloadAnchor.href = dataUrl;
			downloadAnchor.download = "zeus_qrcode_" + Date.now() + ".png";
			document.body.appendChild(downloadAnchor);
			downloadAnchor.click();
			downloadAnchor.remove();
		}
		function showSubQr() {
			const link = window.location.protocol + '//' + getHost() + '/notes/' + encodeURIComponent(window.statusUser.username);
			toggleQrModal(true, link);
		}
		function showSingboxQr() {
			const link = window.location.protocol + '//' + getHost() + '/bundle/' + encodeURIComponent(window.statusUser.username);
			toggleQrModal(true, link);
		}
		function getFlagEmoji(countryCode) {
			if (!countryCode) return '<span class="zeus-flag-globe">🌐</span>';
			const cc = String(countryCode).toLowerCase().replace(/[^a-z]/g, '');
			if (cc.length !== 2) return '<span class="zeus-flag-globe">🌐</span>';
			return '<span class="fi fi-' + cc + ' zeus-flag" title="' + cc.toUpperCase() + '"></span>';
		}
		function getFlagEmojiText(countryCode) {
			if (!countryCode) return '🌐';
			const cc = String(countryCode).toUpperCase().replace(/[^A-Z]/g, '');
			if (cc.length !== 2) return '🌐';
			try {
				return String.fromCodePoint(...cc.split('').map(char => 127397 + char.charCodeAt(0)));
			} catch (e) {
				return '🌐';
			}
		}
		document.addEventListener('DOMContentLoaded', () => {
			const u = window.statusUser;
			if (!u) return;
			const limit = u.ip_limit !== undefined ? u.ip_limit : u.max_connections;
			document.getElementById('display-username').innerText = u.username;
const flagContainer = document.getElementById('display-flag');
	if (u.user_proxy_iata) {
		const flag = getFlagEmoji(u.user_proxy_iata);
		flagContainer.innerHTML = flag + " " + u.user_proxy_iata.toUpperCase();
		flagContainer.style.display = 'block';
} else if (u.user_socks5 || u.user_proxy_ip) {
	flagContainer.style.display = 'block';
	let proxyList = [];
	try {
		if (u.user_socks5 && u.user_socks5.trim().startsWith("[")) {
			proxyList = JSON.parse(u.user_socks5);
		} else {
			proxyList = [u.user_socks5 || u.user_proxy_ip];
		}
	} catch(e) {
		proxyList = [u.user_socks5 || u.user_proxy_ip];
	}
	let initialFlags = proxyList.map(item => {
		let targetProxy = typeof item === 'object' && item !== null ? item.proxy : item;
		let targetCountry = typeof item === 'object' && item !== null ? item.country : null;
		if (targetCountry) return getFlagEmoji(targetCountry);
		try {
			const proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
			const cached = proxyFlagCache[targetProxy];
			if (cached && typeof cached === 'string' && /^[a-zA-Z]{2}$/.test(cached)) return getFlagEmoji(cached);
		} catch(e) {}
		return '⏳';
	});
	flagContainer.innerHTML = initialFlags.join(' ');
	Promise.all(proxyList.map((item, index) => {
		let targetProxy = typeof item === 'object' && item !== null ? item.proxy : item;
		let targetCountry = typeof item === 'object' && item !== null ? item.country : null;
		if (targetCountry) return Promise.resolve(getFlagEmoji(targetCountry));
		try {
			const proxyFlagCache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
			const cached = proxyFlagCache[targetProxy];
			if (cached && typeof cached === 'string' && /^[a-zA-Z]{2}$/.test(cached)) return Promise.resolve(getFlagEmoji(cached));
		} catch(e) {}
		return fetch('/api/test-proxy', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ proxy: targetProxy })
		})
		.then(res => res.json())
		.then(data => {
			if (data.success && data.country) {
				const flagSvg = getFlagEmoji(data.country);
				try {
					const cache = JSON.parse(localStorage.getItem('proxy_flag_cache_v2') || '{}');
					cache[targetProxy] = data.country.toUpperCase();
					localStorage.setItem('proxy_flag_cache_v2', JSON.stringify(cache));
				} catch(e) {}
				return flagSvg;
			}
			return '<span class="zeus-flag-globe">🌐</span>';
		})
		.catch(() => '<span class="zeus-flag-globe">🌐</span>');
	})).then(flags => {
		flagContainer.innerHTML = flags.join(' ');
	});
}
			const badge = document.getElementById('live-connections-badge');
			badge.classList.remove('hidden');
			if (u.online_count && u.online_count > 0) {
				document.getElementById('live-connections-text').innerText = u.online_count + (limit ? '/' + limit : '') + ' دستگاه متصل';
				badge.className = 'inline-flex items-center gap-1.5 px-3 py-1 bg-green-600/10 border border-green-600/20 text-green-600 rounded-full text-xs font-bold shadow-sm';
				badge.querySelector('span.w-2').className = 'w-2 h-2 rounded-full bg-green-600 animate-pulse';
			} else {
				document.getElementById('live-connections-text').innerText = '۰ دستگاه متصل';
				badge.className = 'inline-flex items-center gap-1.5 px-3 py-1 bg-gray-500/10 border border-gray-500/20 text-gray-500 dark:text-zinc-400 rounded-full text-xs font-bold shadow-sm';
				badge.querySelector('span.w-2').className = 'w-2 h-2 rounded-full bg-gray-500';
			}
			const usedGb = u.used_gb || 0;
			const limitGb = u.limit_gb;
			const formattedUsed = usedGb < 1 ? (usedGb * 1024).toFixed(0) + ' MB' : usedGb.toFixed(2) + ' GB';
			document.getElementById('used-vol').innerText = formattedUsed;
			let isVolumeExpired = false;
			if (limitGb) {
				document.getElementById('limit-vol').innerText = limitGb + ' GB';
				const pct = Math.min((usedGb / limitGb) * 100, 100);
				document.getElementById('volume-pct').innerText = pct.toFixed(0) + '٪';
				document.getElementById('volume-progress').style.width = pct + '%';
				const hue = 120 - (pct * 1.2);
				document.getElementById('volume-progress').style.backgroundColor = 'hsl(' + hue + ', 80%, 45%)';
				if (usedGb >= limitGb) isVolumeExpired = true;
			} else {
				document.getElementById('limit-vol').innerText = 'نامحدود';
				document.getElementById('volume-pct').innerText = '۰٪';
				document.getElementById('volume-progress').style.width = '100%';
				document.getElementById('volume-progress').style.backgroundColor = '#3b82f6';
			}
			const volumeHasUsage = usedGb > 0;
			document.getElementById('volume-pct').classList.toggle('invisible', !volumeHasUsage);
			document.getElementById('volume-progress-wrap').classList.toggle('invisible', !volumeHasUsage);
			document.getElementById('volume-amounts-row').classList.toggle('invisible', !volumeHasUsage);
			let daysRemaining = 'نامحدود';
			let totalDays = 'نامحدود';
			let isTimeExpired = false;
			if (u.expiry_days) {
				totalDays = u.expiry_days + ' روز';
				if (u.start_on_first_connect === 1 && !u.first_connection_time) {
					daysRemaining = u.expiry_days + ' روز (شروع از اولین اتصال)';
					document.getElementById('expiry-pct').innerText = '۱۰۰٪';
					document.getElementById('expiry-progress').style.width = '100%';
					document.getElementById('expiry-progress').style.backgroundColor = '#3b82f6';
				} else if (u.start_on_first_connect === 1 && u.first_connection_time) {
					const expiryDate = new Date(u.first_connection_time + (u.expiry_days * 86400000));
					const diffDays = Math.ceil((expiryDate - new Date()) / (86400000));
					daysRemaining = (diffDays > 0 ? diffDays : 0) + ' روز';
					const pct = Math.max(0, Math.min(100, (Math.max(0, diffDays) / u.expiry_days) * 100));
					document.getElementById('expiry-pct').innerText = pct.toFixed(0) + '٪';
					document.getElementById('expiry-progress').style.width = pct + '%';
					const hue = pct * 1.2;
					document.getElementById('expiry-progress').style.backgroundColor = 'hsl(' + hue + ', 80%, 45%)';
					if (new Date() > expiryDate) isTimeExpired = true;
				} else if (u.created_at) {
					const created = new Date(u.created_at);
					const expiryDate = new Date(created.getTime() + (u.expiry_days * 86400000));
					const diffDays = Math.ceil((expiryDate - new Date()) / (86400000));
					daysRemaining = (diffDays > 0 ? diffDays : 0) + ' روز';
					const pct = Math.max(0, Math.min(100, (Math.max(0, diffDays) / u.expiry_days) * 100));
					document.getElementById('expiry-pct').innerText = pct.toFixed(0) + '٪';
					document.getElementById('expiry-progress').style.width = pct + '%';
					const hue = pct * 1.2;
					document.getElementById('expiry-progress').style.backgroundColor = 'hsl(' + hue + ', 80%, 45%)';
					if (new Date() > expiryDate) isTimeExpired = true;
				}
			} else {
				document.getElementById('expiry-pct').innerText = '۰٪';
				document.getElementById('expiry-progress').style.width = '100%';
				document.getElementById('expiry-progress').style.backgroundColor = '#3b82f6';
			}
			document.getElementById('days-remaining').innerText = daysRemaining === 'نامحدود' ? 'نامحدود' : (daysRemaining.includes('روز') ? daysRemaining : daysRemaining + ' روز');
			document.getElementById('total-days').innerText = totalDays;
			const usedReq = u.used_req || 0;
			const limitReq = u.limit_req;
			document.getElementById('used-req').innerText = usedReq.toLocaleString();
			const reqCirc = 2 * Math.PI * 16;
			const reqRing = document.getElementById('req-progress');
			let isReqExpired = false;
			if (limitReq) {
				document.getElementById('limit-req').innerText = limitReq.toLocaleString();
				const rPct = Math.min((usedReq / limitReq) * 100, 100);
				// درصد «تلاش برای پر شدن بیشتر» در انیمیشن پالس - چند درصد جلوتر از مقدار واقعی
				const rPctReach = Math.min(rPct + 4, 100);
				document.getElementById('req-pct').innerText = rPct.toFixed(0) + '٪';
				const rHue = 120 - (rPct * 1.2);
				const rColor = 'hsl(' + rHue + ', 80%, 45%)';
				reqRing.style.stroke = rColor;
				reqRing.style.color = rColor;
				reqRing.style.setProperty('--req-offset', reqCirc - (reqCirc * rPct / 100));
				reqRing.style.setProperty('--req-offset-reach', reqCirc - (reqCirc * rPctReach / 100));
				if (usedReq >= limitReq) isReqExpired = true;
			} else {
				document.getElementById('limit-req').innerText = 'نامحدود';
				document.getElementById('req-pct').innerText = '۰٪';
				reqRing.style.stroke = '#3b82f6';
				reqRing.style.color = '#3b82f6';
				reqRing.style.setProperty('--req-offset', 0);
				reqRing.style.setProperty('--req-offset-reach', 0);
			}
			const reqHasUsage = usedReq > 0;
			document.getElementById('req-pct').classList.toggle('invisible', !reqHasUsage);
			document.getElementById('req-progress-wrap').classList.toggle('invisible', !reqHasUsage);
			document.getElementById('req-amounts-row').classList.toggle('invisible', !reqHasUsage);
			const onlineCount = u.online_count || 0;
			document.getElementById('online-count').innerText = onlineCount;
			if (limit) {
				document.getElementById('limit-online').innerText = limit;
				const oPct = Math.min((onlineCount / limit) * 100, 100);
				document.getElementById('online-pct').innerText = oPct.toFixed(0) + '٪';
				document.getElementById('online-progress').style.width = oPct + '%';
				const oHue = 120 - (oPct * 1.2);
				document.getElementById('online-progress').style.backgroundColor = 'hsl(' + oHue + ', 80%, 45%)';
			} else {
				document.getElementById('limit-online').innerText = 'نامحدود';
				document.getElementById('online-pct').innerText = '۰٪';
				document.getElementById('online-progress').style.width = '100%';
				document.getElementById('online-progress').style.backgroundColor = onlineCount > 0 ? '#16a34a' : '#9ca3af'; 
			}
			const statusCard = document.getElementById('status-card');
			const statusText = document.getElementById('status-text');
			if (u.is_active === 0) {
				statusCard.className = 'mb-6 rounded-md p-4 text-center border font-bold relative z-10 bg-red-500/10 border-red-500/30 text-red-500 shadow-md shadow-red-500/5';
				statusCard.style.boxShadow = 'inset 0 0 12px rgba(239, 68, 68, 0.1)';
				statusText.innerText = '❌ وضعیت اشتراک: غیرفعال / مسدود دستی';
			} else if (isVolumeExpired || isReqExpired || isTimeExpired) {
				statusCard.className = 'mb-6 rounded-md p-4 text-center border font-bold relative z-10 bg-yellow-500/10 border-yellow-500/30 text-yellow-500 shadow-md shadow-yellow-500/5';
				if (isVolumeExpired) statusText.innerText = '⚠️ وضعیت اشتراک: تمام شدن حجم مجاز';
				else if (isReqExpired) statusText.innerText = '📈 وضعیت اشتراک: تمام شدن ریکوئست مجاز';
				else if (isTimeExpired) statusText.innerText = '⏳ وضعیت اشتراک: منقضی شده (پایان زمان اعتبار)';
			} else {
				statusCard.className = 'mb-6 rounded-md p-4 text-center border font-bold relative z-10 bg-green-600/10 border-green-600/30 text-green-600 shadow-md shadow-green-600/5';
				statusText.innerText = '✅ وضعیت اشتراک: فعال و متصل';
			}
		});
		window.addEventListener('click', (e) => {
			if (e.target.id === 'qr-modal') toggleQrModal(false);
		});
	</script>
</body>
</html>`,
};

return __WORKER_EXPORT__;

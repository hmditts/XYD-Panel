// worker.template.js
//
// این فایل باید دقیقاً همان "ساختار stub" فعلی worker.js شما را داشته باشد
// (همان بخش‌های utils, score, view, و خط new Function("connect", view)(connect))
// با یک تفاوت: به‌جای کل بلوک "const payload = function(a,k){...}([...], 69);"
// فقط همین نشانگر زیر را قرار دهید:
//
//   /*__PAYLOAD_BLOCK__*/
//
// اسکریپت scripts/build-worker.js در زمان اجرا این نشانگر را با آرایه‌ی
// تازه‌ساخته‌شده (بر اساس محتوای جدید normal.js) جایگزین می‌کند و خروجی را
// در worker.js ذخیره می‌کند.
//
// ⚠️ این فایل فعلاً فقط یک اسکلت نمونه است — چون من به محتوای دقیق
// worker.js فعلی شما (بخش utils/score/view) دسترسی نداشتم. لطفاً محتوای
// واقعی آن بخش‌ها را جایگزین قسمت‌های زیر کنید.

/*__PAYLOAD_BLOCK__*/

// نمونه‌ی خیلی کلی از ساختاری که شما توضیح دادید (باید با نسخه‌ی واقعی خودتان جایگزین شود):
//
// function utils(...) { ... }
// function score(...) { ... }
// const view = payload; // یا هر تبدیلی که قبلاً روی payload انجام می‌دادید
// export default {
//   async fetch(request, env, ctx) {
//     const connect = ...;
//     return new Function("connect", view)(connect);
//   }
// };

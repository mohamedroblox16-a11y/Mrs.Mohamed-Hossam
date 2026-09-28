# منصة مستر محمد حسام — الواجهة القديمة + Cloudflare

تم الحفاظ على واجهة المنصة القديمة والاختيارات الموجودة في ملف `public/index.html`، مع استخدام Cloudflare Workers + D1 في الخلفية.

الملفات المهمة:
- `public/index.html` — الواجهة القديمة بنفس الأقسام والاختيارات.
- `public/styles.css` — تنسيق الواجهة.
- `public/app.js` — تشغيل تسجيل الدخول والتسجيل والطالب ولوحة المدرس والحضور.
- `server.js` — API يعمل على Cloudflare Workers.
- `wrangler.jsonc` — ربط D1 باسم DB.

المتغيرات السرية:
ADMIN_LOGIN
ADMIN_PASSWORD
SESSION_SECRET

قاعدة البيانات:
`mr-mohamed-hossam-db`

تشغيل:
npm install
npx wrangler dev

تطبيق الجداول على D1 البعيدة:
npx wrangler d1 execute mr-mohamed-hossam-db --remote --file=schema.sql

النشر:
npx wrangler deploy

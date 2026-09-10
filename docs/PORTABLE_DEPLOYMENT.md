# نقل وتشغيل المنصة على Windows أوLinux/Ubuntu

المشروع لا يعتمد على اسم مستخدم أوعنوان IP أومسار تثبيت ثابت. نقطة التشغيل الفعلية هي `platform_launcher.py`، وتستخدم أغلفة صغيرة مناسبة لكل نظام.

## ما ينتقل مع المشروع

انقل مجلد المشروع كاملًا. إذا أردت المحافظة على المستخدمين والإعدادات والنتائج والكاش، انقل كذلك:

- `storage/security_auth.json`
- `storage/platform_config.json`
- `storage/learning.sqlite3`
- `flowscope/storage/`
- `threatscope/storage/`

لا تنقل `storage/runtime/` من جهاز ما زالت المنصة تعمل عليه. يمكن حذف أوعدم حزم `frontend/node_modules`, `gateway/node_modules`, `frontend/.next` و`gateway/dist`؛ يعيد المشغل إنشاءها.

إذا نُقلت `node_modules` على أي حال، يقارن المشغل نظام التشغيل والمعمارية وإصدار Node ببصمة التثبيت. عند اختلافها ينفذ `npm ci` تلقائيًا من lockfiles.

## المتطلبات المشتركة

- Python 3.11 أوأحدث.
- Node.js 20.9 أوأحدث وnpm.
- صلاحية كتابة داخل مجلد المشروع.
- اتصال npm في أول تشغيل إذا كانت الاعتماديات غير موجودة أومن نظام آخر.

## Windows 11

1. ثبّت Python وNode وأضف كليهما إلى PATH.
2. استخدم Microsoft Word أوLibreOffice لمعاينة التقارير. يستطيع المشروع اكتشاف نسخته المرفقة داخل `.tools`.
3. شغّل:

```cmd
start.cmd
```

للإيقاف:

```cmd
stop.cmd
```

للسماح بالوصول من الشبكة، افتح PowerShell كمسؤول مرة واحدة:

```powershell
.\start_nextjs.ps1 -ConfigureFirewall
```

## Ubuntu 22.04/24.04

ثبّت المتطلبات النظامية:

```bash
sudo apt update
sudo apt install -y python3 libreoffice fonts-noto-core fonts-noto-extra
```

ثبّت Node.js 20.9 أوأحدث من المصدر المعتمد داخل بيئتك، ثم تحقق:

```bash
python3 --version
node --version
npm --version
```

شغّل من جذر المشروع:

```bash
bash start.sh
```

للإيقاف:

```bash
bash stop.sh
```

لا يعتمد التشغيل على executable bit للملفين عند استخدام `bash start.sh`. إذا رغبت في تشغيلهما مباشرة:

```bash
chmod +x start.sh stop.sh
./start.sh
```

إذا كان UFW فعالًا وتريد الوصول من الشبكة:

```bash
sudo bash start.sh --configure-firewall
```

يستخدم المشغل `ufw` على Ubuntu، أو`firewall-cmd` على توزيعات firewalld. لا يفتح إلا منفذ الواجهة؛ يبقى Gateway ومحرك Python على loopback.

## اختيار الأدوات حسب النظام

| الوظيفة | Windows | Linux/Ubuntu |
|---|---|---|
| تشغيل العمليات | Windows process groups وعمليات مخفية | POSIX sessions/process groups |
| الإيقاف | `taskkill /T` للعملية وأبنائها | `SIGTERM` ثم `SIGKILL` عند الحاجة |
| جدار الحماية | Windows Firewall | UFW أوfirewalld |
| معاينة Word | Microsoft Word ثم LibreOffice | LibreOffice |
| فتح المتصفح | المتصفح الافتراضي عند توفر سطح مكتب | يفتح فقط عند وجود DISPLAY/Wayland |
| أوامر Node | `npm.cmd` | `npm` |

إذا احتفظت إعدادات من Windows بمحرك معاينة `word` ثم نقلت المشروع إلى Linux، تتحول المعاينة تلقائيًا إلى LibreOffice بدل الفشل.

## الشبكة ومتغيرات البيئة

الافتراضات الآمنة:

- الواجهة: `0.0.0.0:3000`.
- Gateway: `127.0.0.1:8081`.
- Python: `127.0.0.1:8082`.
- المتصفح يستخدم `/api` على عنوان الواجهة ولا يعرف المنافذ الداخلية.

يقرأ المشغل `.env` الجذري على النظامين، ثم الإعدادات المحفوظة. متغير البيئة له الأولوية. راجع `.env.example`.

عنوان خدمة خارجية مثل Ollama لا يتغير تلقائيًا إذا تغير جهاز تلك الخدمة. استخدم اسم DNS ثابتًا أوحدّث الرابط من الإعدادات بعد النقل.

## الفحص قبل وبعد التشغيل

قبل التشغيل:

```bash
python3 platform_launcher.py doctor
```

بعد التشغيل:

```bash
python3 scripts/verify_portability.py --running
```

على Windows استخدم `python` إذا كان هذا هو اسم الأمر المتاح. يفحص الأمر:

- الإصدارات والملفات الأساسية.
- Word/LibreOffice والخطوط على Linux.
- قابلية الكتابة.
- ربط الواجهة بالشبكة وحصر الخلفيات على loopback.
- صحة الخدمات الثلاث.
- سلسلة Frontend → Gateway → Python كاملة.

## ملاحظات الصلاحيات والملكية على Linux

بعد نسخ المشروع بحساب root ثم تشغيله بحساب خدمة عادي، أصلح الملكية قبل التشغيل:

```bash
sudo chown -R <service-user>:<service-group> /path/to/project
```

لا تشغّل المنصة كـroot بصورة دائمة. تحتاج root فقط عند تثبيت الحزم أوتعديل firewall.

## النسخ الاحتياطي

أوقف المنصة قبل نسخ قواعد SQLite وملفات المهام:

```bash
bash stop.sh
```

ثم انسخ مجلدات التخزين المطلوبة. لا تنشر ملفات المستخدمين أوAPI keys أوالملفات الخام ضمن حزمة مصدر عامة.

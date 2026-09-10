"""Arabic message templates for platform events."""

MESSAGES_AR: dict[str, str] = {
    "SYS_START": "بدء تشغيل خادم المنصة الموحد بنجاح على {host}:{port}.",
    "SYS_SHUTDOWN": "تم إيقاف خادم المنصة الموحد بنجاح.",
    "LOG_LEVEL_CHANGED": "تم تغيير مستوى تسجيل المنصة من {old_level} إلى {new_level}.",
    "GENERAL_ERROR": "حدث خطأ غير متوقع في خادم المنصة: {message}.",
    "SERVICE_STARTED": "تم تشغيل الخدمة بنجاح على {host}:{port}.",
    "SERVICE_STOPPED": "تم إيقاف الخدمة {service}.",
    "DB_CONNECTION_FAILED": "تعذر الاتصال بقاعدة بيانات المنصة ({database}).",
    "DB_WRITE_FAILED": "تعذر على محرك {component} حفظ نتيجة التحليل في قاعدة البيانات.",
    "DB_SLOW_QUERY": "تم رصد استعلام بطيء في قاعدة البيانات استغرق {duration_ms} مللي ثانية.",
    "ANALYSIS_STARTED": "بدأ تحليل المهمة {job_id} عبر محرك {component}.",
    "ANALYSIS_COMPLETED": "اكتمل تحليل المهمة {job_id} بنجاح خلال {duration_ms} مللي ثانية (تمت معالجة {events_processed} حدث).",
    "ANALYSIS_FAILED": "فشلت عملية تحليل المهمة {job_id}: {reason}.",
    "AUTH_LOGIN_SUCCESS": "تم تسجيل الدخول بنجاح للمستخدم {username}.",
    "AUTH_LOGIN_FAILED": "فشلت محاولة تسجيل الدخول للمستخدم {username}: {reason}.",
    "AUTH_LOGOUT": "تم تسجيل خروج المستخدم {username}.",
    "DETECTION_RULE_LOADED": "تم تحميل {count} من قواعد الكشف بنجاح.",
    "DETECTION_MATCH": "تم رصد تطابق أمني للمهمة {job_id} عبر القاعدة {rule_name}.",
    "SIGMA_COMPILATION_ERROR": "تعذر على محرك Sigma ترجمة القاعدة {rule_id}: {error}.",
    "API_REQUEST_PROCESSED": "تمت معالجة طلب API {method} {path} برمز {status_code} خلال {duration_ms} مللي ثانية.",
    "API_REQUEST_ERROR": "حدث خطأ أثناء معالجة طلب API {path}: {error}.",
    "CONFIG_UPDATED": "تم تحديث إعدادات المنصة بنجاح بواسطة {username}.",
    "SYSTEM_HEALTH_CHECK": "تم فحص حالة النظام: الحالة الحالية {status}.",
    "QUEUE_OVERFLOW": "تم تجاوز سعة طابور السجلات وتطبيق سياسة الضغط العكسي لإسقاط الرسائل منخفضة الأولوية.",
    "GENERAL_EVENT": "{message}",
}


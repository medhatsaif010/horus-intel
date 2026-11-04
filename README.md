# Horus Intel Builder

ده الجزء اللي **عندك إنت بس**، مش بيتوزّع مع حورس. بيبني "قاعدة التهديدات" الموقّعة اللي حورس بينزّلها.

## بيجمع إيه
| المصدر | حورس بيستخدمه في |
|---|---|
| CISA KEV + سجلات NVD (+ EPSS) | البرامج المتسطبة اللي نسختها فيها ثغرات بتتستغل فعلًا |
| endoflife.date | البرامج وإصدارات Windows اللي دعمها انتهى |
| Microsoft Windows release health | مستوى تحديث Windows (ناقصه تحديثات بقاله قد إيه) |
| LOLDrivers | الدرايفرات الضعيفة أو الضارة المعروفة (BYOVD) |
| Echap stalkerware-indicators | برامج التجسس على الموبايل (أسماء الحزم والشهادات) |
| CISA KEV (Android, Qualcomm, Mali, Samsung) | ثغرات الموبايل المستغلة |

## المفتاح
- `keys/horus-intel-private.pem` هو **المفتاح السري**. أي حد معاه يقدر يعمل قاعدة مزيفة وحورس هيصدّقها، فـ**متشاركهوش ومترفعهوش على GitHub**. خد منه نسخة احتياطية في مكان آمن.
- `keys/horus-intel-public.json` هو المفتاح العام، وهو نفسه اللي جوه `Horus-Intel.ps1` في حورس.

## التشغيل بإيدك
```
pip install -r requirements.txt
python build_intel.py --out out
```
وبعدين انسخ `out/horus-intel.json` و`out/horus-intel.sig` لفولدر `intel` في حورس.

## التحديث اليومي التلقائي من GitHub
1. اعمل repo **Private** على GitHub، وارفع الفولدر ده من غير فولدر `keys`. ملف `.gitignore` بيمنع رفع المفتاح السري.
2. في الـ repo: Settings > Secrets and variables > Actions > New repository secret. اسمه `HORUS_INTEL_KEY`، وقيمته محتوى ملف `horus-intel-private.pem` كله.
3. من Actions شغّل "Horus threat-intel pack" بإيدك أول مرة. بعد كده هيشتغل لوحده كل يوم الساعة 3:17 UTC.
4. الـ release اسمه `intel`. حط اللينك ده في `horus-settings.json` عند كل مستخدم، أو في النسخة اللي بتوزّعها:
   ```json
   { "profile": "standard", "intelUrl": "https://github.com/<OWNER>/<REPO>/releases/download/intel/" }
   ```
   لو الـ repo Private، الـ release مش هيتنزّل من غير تسجيل دخول. في الحالة دي إمّا تخلّي repo تاني Public للـ releases بس، أو ترفع الملفين على أي استضافة عامة.

## التراخيص
- CISA KEV وNVD: بيانات حكومية أمريكية عامة. NVD بيطلب الجملة دي: "This product uses data from the NVD API but is not endorsed or certified by the NVD."
- EPSS: مجاني بشرط ذكر FIRST كمصدر.
- endoflife.date: رخصة MIT.
- Echap stalkerware-indicators: رخصة CC-BY 4.0، فلازم تذكرهم كمصدر.
- LOLDrivers: راجع رخصة الـ repo بتاعهم قبل البيع التجاري، واذكرهم كمصدر.

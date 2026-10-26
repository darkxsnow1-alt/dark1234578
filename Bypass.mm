#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <string.h>

// دالة الحماية اللي بتشتغل أول ما الملف يتحمل
__attribute__((constructor)) void InitProtection() {
    // هنا هيتحط كود الحماية اللي بيتخطى الفحص
    // ملاحظة: عشان نستخدم دالة زي dyld_get_image_name، محتاجين مكتبة fishhook
    // عشان الكود يبني بنجاح من غير أخطاء، إحنا بنسيب التعريف هنا
}

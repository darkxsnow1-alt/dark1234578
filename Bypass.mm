#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <string.h>
#import <unistd.h>
#import <sys/sysctl.h>

// 1. إخفاء الـ Dylib من قائمة الصور المحملة (Image Hiding)
// دالة بتخفي اسم الملف من أي فحص
int (*orig_dyld_get_image_name)(uint32_t image_index);
const char* my_dyld_get_image_name(uint32_t image_index) {
    const char* name = orig_dyld_get_image_name(image_index);
    if (name && (strstr(name, ".dylib") || strstr(name, "Cydia") || strstr(name, "Substrate"))) {
        return ""; // بنرجع اسم فاضي عشان اللعبة تتجاهله
    }
    return name;
}

// 2. تعطيل دوال فحص الملفات (File Checks Bypass)
// الدالة دي بتمنع اللعبة من قراءة ملفاتنا
int (*orig_open)(const char *path, int oflag, ...);
int my_open(const char *path, int oflag, ...) {
    if (path && (strstr(path, ".dylib") || strstr(path, "Info.plist"))) {
        return -1; // الملف مش موجود
    }
    return orig_open(path, oflag);
}

// 3. تفعيل الحماية (Constructor)
__attribute__((constructor)) void InitProtection() {
    // هنحتاج نستخدم مكتبة fishhook عشان نربط الدوال دي
    // rebind_symbols((struct rebinding[1]){{"_dyld_get_image_name", my_dyld_get_image_name, (void**)&orig_dyld_get_image_name}}, 1);
    // rebind_symbols((struct rebinding[1]){{"open", my_open, (void**)&orig_open}}, 1);
}
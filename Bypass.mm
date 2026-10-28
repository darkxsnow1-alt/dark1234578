#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <string.h>
#import <sys/stat.h>
#import <stdio.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import "fishhook.h"

// ==========================================
// 1. حجب ملفات التوقيع (Anti-Provision Check)
// ==========================================
// اللعبة بتحاول تفتح ملف embedded.mobileprovision عشان تشوف مين وقع اللعبة
int (*orig_stat)(const char *path, struct stat *buf);
int my_stat(const char *path, struct stat *buf) {
    if (path) {
        // لو اللعبة بتحاول تقرأ ملفات التوقيع أو ملفات الجيلبريك
        if (strstr(path, "embedded.mobileprovision") || 
            strstr(path, "Info.plist") || 
            strstr(path, "_CodeSignature") ||
            strstr(path, "Cydia") ||
            strstr(path, "Substrate") ||
            strstr(path, "/var/jb")) {
            return -1; // قولها الملف مش موجود
        }
    }
    return orig_stat(path, buf);
}

FILE* (*orig_fopen)(const char *path, const char *mode);
FILE* my_fopen(const char *path, const char *mode) {
    if (path) {
        if (strstr(path, "embedded.mobileprovision") || 
            strstr(path, "Info.plist") || 
            strstr(path, "_CodeSignature") ||
            strstr(path, "Cydia") ||
            strstr(path, "Substrate")) {
            return NULL; // الملف مش موجود
        }
    }
    return orig_fopen(path, mode);
}

// ==========================================
// 2. تزوير مسار التطبيق (Path Spoofing)
// ==========================================
// اللعبة بتسأل على الـ HOME عشان تعرف مسارها، إحنا هنرجع مسار App Store
char* (*orig_getenv)(const char* name);
char* my_getenv(const char* name) {
    if (name && strcmp(name, "HOME") == 0) {
        // تزوير مسار التطبيق ليكون مسار نظام
        return "/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000";
    }
    return orig_getenv(name);
}

// ==========================================
// 3. تعطيل فحص الـ ptrace (Anti-Debugging)
// ==========================================
int (*orig_ptrace)(int request, pid_t pid, caddr_t addr, int data);
int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    // منع أي أداة تحليل إنها تلتصق باللعبة
    return 0; 
}

// ==========================================
// 4. حجب فحص العمليات (sysctl Bypass)
// ==========================================
int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    // لو اللعبة بتسأل عن عمليات النظام (عشان تلاقي أدوات تحليل)
    if (name && namelen > 0 && name[0] == CTL_KERN && name[1] == KERN_PROC) {
        return -1; // ارفض الإجابة
    }
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

// ==========================================
// 5. تفعيل الحماية
// ==========================================
__attribute__((constructor)) void InitProtection() {
    // حجب الملفات
    struct rebinding stat_rebind = {"stat", my_stat, (void **)&orig_stat};
    rebind_symbols(&stat_rebind, 1);

    struct rebinding fopen_rebind = {"fopen", my_fopen, (void **)&orig_fopen};
    rebind_symbols(&fopen_rebind, 1);

    // تزوير المسار
    struct rebinding getenv_rebind = {"getenv", my_getenv, (void **)&orig_getenv};
    rebind_symbols(&getenv_rebind, 1);

    // منع الديباجر
    struct rebinding ptrace_rebind = {"ptrace", my_ptrace, (void **)&orig_ptrace};
    rebind_symbols(&ptrace_rebind, 1);

    // حجب فحص النظام
    struct rebinding sysctl_rebind = {"sysctl", my_sysctl, (void **)&orig_sysctl};
    rebind_symbols(&sysctl_rebind, 1);
}

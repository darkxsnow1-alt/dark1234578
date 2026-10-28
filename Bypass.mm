#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <string.h>
#import <sys/stat.h>
#import <stdio.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <sys/ptrace.h>
#import "fishhook.h"

// ==========================================
// 1. حجب الملفات (File Hiding)
// ==========================================
int (*orig_stat)(const char *path, struct stat *buf);
int my_stat(const char *path, struct stat *buf) {
    if (path) {
        if (strstr(path, "embedded.mobileprovision") || 
            strstr(path, "Info.plist") || 
            strstr(path, "_CodeSignature") ||
            strstr(path, "Cydia") ||
            strstr(path, "Substrate") ||
            strstr(path, "/var/jb")) {
            return -1; 
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
            return NULL; 
        }
    }
    return orig_fopen(path, mode);
}

// ==========================================
// 2. تزوير المسار (Path Spoofing)
// ==========================================
char* (*orig_getenv)(const char* name);
char* my_getenv(const char* name) {
    if (name && strcmp(name, "HOME") == 0) {
        // تحويل النص لـ char* عشان نمنع التحذير
        return (char*)"/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000";
    }
    return orig_getenv(name);
}

// ==========================================
// 3. منع التتبع (Anti-Debugging)
// ==========================================
int (*orig_ptrace)(int request, pid_t pid, caddr_t addr, int data);
int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    return 0; 
}

// ==========================================
// 4. حجب فحص النظام (Sysctl Bypass)
// ==========================================
int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && namelen > 0 && name[0] == CTL_KERN && name[1] == KERN_PROC) {
        return -1; 
    }
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

// ==========================================
// 5. تفعيل الحماية (مع تحويل المؤشرات)
// ==========================================
__attribute__((constructor)) void InitProtection() {
    // تحويل المؤشرات لـ (void**) عشان نرضي الكومبايلر
    struct rebinding stat_rebind = {"stat", (void*)my_stat, (void**)&orig_stat};
    rebind_symbols(&stat_rebind, 1);

    struct rebinding fopen_rebind = {"fopen", (void*)my_fopen, (void**)&orig_fopen};
    rebind_symbols(&fopen_rebind, 1);

    struct rebinding getenv_rebind = {"getenv", (void*)my_getenv, (void**)&orig_getenv};
    rebind_symbols(&getenv_rebind, 1);

    struct rebinding ptrace_rebind = {"ptrace", (void*)my_ptrace, (void**)&orig_ptrace};
    rebind_symbols(&ptrace_rebind, 1);

    struct rebinding sysctl_rebind = {"sysctl", (void*)my_sysctl, (void**)&orig_sysctl};
    rebind_symbols(&sysctl_rebind, 1);
}

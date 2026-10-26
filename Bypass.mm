#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <sys/stat.h>
#import <string.h>
#import <stdio.h>
#import <unistd.h>
#import <sys/sysctl.h>

// --- Anti-Debugging ---
int anti_debug() {
    int junk;
    if (sysctl((int[]){CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()}, 4, NULL, &junk, NULL, 0) == 0) {
        struct kinfo_proc info;
        size_t size = sizeof(info);
        info.kp_proc.p_flag = 0;
        sysctl((int[]){CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()}, 4, &info, &size, NULL, 0);
        if (info.kp_proc.p_flag & P_TRACED) return 1;
    }
    return 0;
}

// --- Protection Initialization ---
__attribute__((constructor)) void InitProtection() {
    if (anti_debug()) exit(0);
    
    // ملاحظة: الحماية بالهوكس (Hooks) محتاجة مكتبة fishhook عشان تشتغل
    // الكود الحالي بيبني بنجاح بدون مكتبات خارجية عشان ميكسرش الـ Build
}

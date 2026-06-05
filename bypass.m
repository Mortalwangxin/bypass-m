#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import "fishhook.h"

static void* (*original_CFNetworkCopySystemProxySettings)(void);
static void* replaced_CFNetworkCopySystemProxySettings(void) {
    return NULL;
}

static id (*original_yx_headerEncryptString)(id self, SEL _cmd);
static id replaced_yx_headerEncryptString(id self, SEL _cmd) {
    return @"root/0;debug/0;proxy/0;inject/0";
}

__attribute__((constructor)) void init() {
    @autoreleasepool {
        NSLog(@"[Bypass] Loading...");
        
        // 使用 fishhook rebind C 函数
        struct rebinding cf_rebind = {"CFNetworkCopySystemProxySettings", replaced_CFNetworkCopySystemProxySettings, (void*)&original_CFNetworkCopySystemProxySettings};
        rebind_symbols(&cf_rebind, 1);
        
        // Hook Objective-C 方法
        Class cls = NSClassFromString(@"MTLibEncry");
        if (cls) {
            SEL sel = NSSelectorFromString(@"yx_headerEncryptString");
            Method method = class_getClassMethod(cls, sel);
            if (method) {
                original_yx_headerEncryptString = (id (*)(id, SEL))method_setImplementation(method, (IMP)replaced_yx_headerEncryptString);
                NSLog(@"[Bypass] Hooked yx_headerEncryptString");
            } else {
                NSLog(@"[Bypass] Method not found");
            }
        } else {
            NSLog(@"[Bypass] Class MTLibEncry not found");
        }
        
        // 还可以 Hook 其他检测函数，例如检测 VPN 的函数
        // 文章中提到也有 VPN 检测，可以类似地 rebind 相关函数（如 NEVPNManager 的相关方法），
        // 但上述两个 Hook 通常足够。
        NSLog(@"[Bypass] Loaded.");
    }
}
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import "fishhook.h"

// 原始函数指针
static void* (*original_CFNetworkCopySystemProxySettings)(void);
static id (*original_yx_headerEncryptString)(id self, SEL _cmd);

// 替换函数：返回 NULL 表示无代理
static void* replaced_CFNetworkCopySystemProxySettings(void) {
    return NULL;
}

// 替换方法：返回干净的字符串
static id replaced_yx_headerEncryptString(id self, SEL _cmd) {
    // 文章中的固定值
    return @"root/0;debug/0;proxy/0;inject/0";
}

__attribute__((constructor)) void init() {
    @autoreleasepool {
        NSLog(@"[Bypass] Loading dylib...");
        
        // 1. Hook C 函数 CFNetworkCopySystemProxySettings
        struct rebinding rebind_proxy = {
            "CFNetworkCopySystemProxySettings",
            replaced_CFNetworkCopySystemProxySettings,
            (void*)&original_CFNetworkCopySystemProxySettings
        };
        rebind_symbols(&rebind_proxy, 1);
        NSLog(@"[Bypass] Hooked CFNetworkCopySystemProxySettings");
        
        // 2. Hook Objective-C 方法 yx_headerEncryptString
        Class cls = NSClassFromString(@"MTLibEncry");
        if (cls) {
            SEL sel = NSSelectorFromString(@"yx_headerEncryptString");
            Method m = class_getClassMethod(cls, sel);
            if (m) {
                original_yx_headerEncryptString = (id (*)(id, SEL))method_setImplementation(m, (IMP)replaced_yx_headerEncryptString);
                NSLog(@"[Bypass] Hooked yx_headerEncryptString");
            } else {
                NSLog(@"[Bypass] Method yx_headerEncryptString not found");
            }
        } else {
            NSLog(@"[Bypass] Class MTLibEncry not found");
        }
    }
}
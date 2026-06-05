/*
 * MTPlugin.m - i茅台抢购插件 v5 (反检测版)
 *
 * 闪退根因: app 启动时用 __dyld_image_count + __dyld_get_image_name 枚举所有
 * 已加载 image，检测到非系统 dylib 就闪退。
 *
 * 修复:
 *   1. constructor 中同步 fishhook (不延迟!) → 在 app 检测前就隐藏 dylib
 *   2. hook __dyld_get_image_name → 跳过本 dylib，返回下一个 image 名
 *   3. hook __dyld_image_count → 返回 count-1 (隐藏最后一个)
 *   4. hook CFNetworkCopySystemProxySettings → 绕过代理检测
 *   5. 延迟 hook ObjC 方法 (yx_headerEncryptString + WebView JS注入)
 *
 * 编译:
 *   SDK=$(xcrun --sdk iphoneos --show-sdk-path)
 *   clang -dynamiclib -arch arm64 -miphoneos-version-min=14.0 \
 *         -isysroot "$SDK" -framework Foundation -framework UIKit \
 *         -framework WebKit -o MTPlugin.dylib MTPlugin.m fishhook.c \
 *         -fobjc-arc -Wno-deprecated-declarations
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import "fishhook.h"

// ============================================================================
// 0. 本 dylib 路径 (在 constructor 中查找)
// ============================================================================

static const char *_self_dylib_path = NULL;
static uint32_t _self_image_index = UINT32_MAX;

// ============================================================================
// 1. hook dyld 函数 — 隐藏本 dylib
//
// app 的环境检测用 _dyld_image_count + _dyld_get_image_name 遍历所有 image。
// 我们让这两个函数"跳过"本 dylib，使 app 看不到它。
// ============================================================================

static uint32_t (*orig_dyld_image_count)(void);
static const char *(*orig_dyld_get_image_name)(uint32_t image_index);

static uint32_t my_dyld_image_count(void) {
    uint32_t count = orig_dyld_image_count ? orig_dyld_image_count() : 0;
    if (_self_image_index != UINT32_MAX && count > 0) {
        return count - 1;  // 隐藏一个 image
    }
    return count;
}

static const char *my_dyld_get_image_name(uint32_t image_index) {
    if (!orig_dyld_get_image_name) return NULL;

    if (_self_image_index == UINT32_MAX) {
        return orig_dyld_get_image_name(image_index);
    }

    // 跳过本 dylib: 如果请求的 index >= 隐藏位置，返回下一个
    if (image_index >= _self_image_index) {
        uint32_t real_index = image_index + 1;
        uint32_t real_count = orig_dyld_image_count ? orig_dyld_image_count() : 0;
        if (real_index < real_count) {
            return orig_dyld_get_image_name(real_index);
        }
        return NULL;  // 超出范围
    }
    return orig_dyld_get_image_name(image_index);
}

// ============================================================================
// 2. 绕过代理/VPN 检测
// ============================================================================

static CFDictionaryRef (*orig_CFNetworkCopySystemProxySettings)(void);

static CFDictionaryRef my_CFNetworkCopySystemProxySettings(void) {
    return (__bridge CFDictionaryRef)[NSDictionary dictionary];
}

// ============================================================================
// 3. 绕过注入检测 - hook yx_headerEncryptString (延迟)
// ============================================================================

static id (*orig_yx_headerEncryptString)(id self, SEL _cmd);

static id fake_yx_headerEncryptString(id self, SEL _cmd) {
    return @"root/0;debug/0;proxy/0;inject/0";
}

// ============================================================================
// 4. WebView JS 注入 (延迟)
// ============================================================================

static NSString *getInjectionJS(void) {
    static NSString *js = nil;
    if (js) return js;
    js = @"(function(){"
    "var o=window.fetch;"
    "window.fetch=function(i,n){"
    "return o.apply(this,[i,n]).then(function(r){"
    "return r.clone().text().then(function(t){"
    "var x=t;try{"
    "var j=JSON.parse(t);"
    "if(j.data&&j.data.itemId==='IMTP1000313'&&"
    "((j.data.purchaseInfoMap&&Object.keys(j.data.purchaseInfoMap).length===0)"
    "||j.data.forbiddenBuyDesc)){"
    "x=JSON.stringify({code:2000,data:{itemId:'IMTP1000313',offline:false,"
    "purchaseInfoMap:{'1001017':{defaultSkuFlag:true,"
    "purchaseInfo:{skuId:'741',inventory:12,presellInventory:12,canAddCart:false,"
    "limitCount:6,inDeliveryArea:true,showSelfPickUpBtn:false,disable:false,"
    "defaultSkuFlag:false}}},showSaleUnit:true,nationWide:false}});}"
    "else if(j.data&&j.data.purchaseInfoMap){"
    "var m=j.data.purchaseInfoMap;Object.keys(m).forEach(function(k){"
    "var p=m[k]&&m[k].purchaseInfo;if(!p)return;"
    "if('forbiddenBuyDesc' in p)delete p.forbiddenBuyDesc;"
    "p.inventory=12;p.presellInventory=12;});x=JSON.stringify(j);}"
    "else if(j===2||(j.code&&(j.code===4293||j.code===4030||j.code===4031))){"
    "var h=new Headers(n&&n.headers||{});h.set('MT-K',Date.now().toString());"
    "return o.call(this,i,{...(n||{}),headers:h}).then(function(r2){"
    "return r2.clone().text().then(function(t2){"
    "return new Response(t2,{status:r2.status,statusText:r2.statusText,"
    "headers:r2.headers});});});}"
    "}catch(e){}"
    "return new Response(x,{status:r.status,statusText:r.statusText,"
    "headers:r.headers});"
    "});});};"
    "})();";
    return js;
}

static void (*orig_addScriptMessageHandler)(id self, SEL _cmd, id handler, id name);

static void fake_addScriptMessageHandler(id self, SEL _cmd, id handler, id name) {
    WKUserScript *script = [[WKUserScript alloc]
        initWithSource:getInjectionJS()
        injectionTime:WKUserScriptInjectionTimeAtDocumentStart
        forMainFrameOnly:NO];
    [(WKUserContentController *)self addUserScript:script];
    if (orig_addScriptMessageHandler) {
        orig_addScriptMessageHandler(self, _cmd, handler, name);
    }
}

// ============================================================================
// 5. 延迟 ObjC hook
// ============================================================================

static int _yx_attempts = 0;

static void do_hook_objc(void *ctx) {
    (void)ctx;

    // hook yx_headerEncryptString
    Method encMethod = class_getInstanceMethod(
        [NSString class], NSSelectorFromString(@"yx_headerEncryptString"));
    if (encMethod) {
        orig_yx_headerEncryptString = (void *)method_getImplementation(encMethod);
        method_setImplementation(encMethod, (IMP)fake_yx_headerEncryptString);
        NSLog(@"[MTPlugin] 注入检测绕过已启用");
    } else if (_yx_attempts < 10) {
        _yx_attempts++;
        dispatch_after_f(
            dispatch_time(DISPATCH_TIME_NOW, (long long)(0.5 * NSEC_PER_SEC)),
            dispatch_get_main_queue(), NULL, do_hook_objc);
        return;
    }

    // hook addScriptMessageHandler:name:
    Method addMethod = class_getInstanceMethod(
        NSClassFromString(@"WKUserContentController"),
        NSSelectorFromString(@"addScriptMessageHandler:name:"));
    if (addMethod) {
        orig_addScriptMessageHandler = (void *)method_getImplementation(addMethod);
        method_setImplementation(addMethod, (IMP)fake_addScriptMessageHandler);
        NSLog(@"[MTPlugin] WebView JS注入已启用");
    }

    NSLog(@"[MTPlugin] 所有 Hook 就绪");
}

// ============================================================================
// 6. 入口 — 同步 fishhook，延迟 ObjC hook
// ============================================================================

__attribute__((constructor))
static void mt_plugin_init(void) {
    @autoreleasepool {
        NSLog(@"[MTPlugin] 插件已加载");

        // ---- 第一步: 同步执行 (不能延迟!) ----
        // 找到自身在 dyld image 列表中的位置
        uint32_t count = _dyld_image_count();
        for (uint32_t i = 0; i < count; i++) {
            const char *name = _dyld_get_image_name(i);
            if (name && strstr(name, "MTPlugin.dylib")) {
                _self_dylib_path = name;
                _self_image_index = i;
                NSLog(@"[MTPlugin] 自身位于 image[%u]: %s", i, name);
                break;
            }
        }

        // 同步 fishhook — 必须在 app 的检测代码运行前完成!
        // (constructor 在 main() 之前执行，app 检测在 application:didFinishLaunching 之后)
        {
            struct rebinding rebindings[] = {
                {
                    "_dyld_get_image_name",
                    (void *)my_dyld_get_image_name,
                    (void **)&orig_dyld_get_image_name
                },
                {
                    "_dyld_image_count",
                    (void *)my_dyld_image_count,
                    (void **)&orig_dyld_image_count
                },
                {
                    "CFNetworkCopySystemProxySettings",
                    (void *)my_CFNetworkCopySystemProxySettings,
                    (void **)&orig_CFNetworkCopySystemProxySettings
                },
            };
            rebind_symbols(rebindings, 3);
            NSLog(@"[MTPlugin] dyld隐藏 + 代理绕过 已启用 (image[%u])", _self_image_index);
        }

        // ---- 第二步: 延迟 ObjC hook ----
        dispatch_after_f(
            dispatch_time(DISPATCH_TIME_NOW, (long long)(1.5 * NSEC_PER_SEC)),
            dispatch_get_main_queue(), NULL, do_hook_objc);
    }
}

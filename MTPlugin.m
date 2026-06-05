/*
 * MTPlugin.m - i茅台抢购插件
 *
 * 目标: i茅台 (com.moutai.mall) v1.9.7
 * 注入: TrollFools
 *
 * 功能:
 *   1. fishhook CFNetworkCopySystemProxySettings → 绕过代理/VPN 检测
 *   2. hook yx_headerEncryptString              → 绕过注入检测
 *   3. hook addScriptMessageHandler:name:       → WebView JS 注入
 *
 * 编译 (GitHub Actions macOS runner):
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
// 1. 绕过代理/VPN 检测
// ============================================================================

static CFDictionaryRef (*orig_CFNetworkCopySystemProxySettings)(void);

static CFDictionaryRef my_CFNetworkCopySystemProxySettings(void) {
    if (!orig_CFNetworkCopySystemProxySettings) return NULL;
    CFDictionaryRef orig = orig_CFNetworkCopySystemProxySettings();
    if (!orig) return orig;
    // 返回空字典 → app 认为没有代理配置
    return (__bridge_retained CFDictionaryRef)[NSMutableDictionary dictionary];
}

// ============================================================================
// 2. 绕过注入检测 - hook yx_headerEncryptString
// ============================================================================

static id (*orig_yx_headerEncryptString)(id self, SEL _cmd);

static id fake_yx_headerEncryptString(id self, SEL _cmd) {
    // root/0=完整性 debug/0=非调试 proxy/0=无代理 inject/0=无注入
    return @"root/0;debug/0;proxy/0;inject/0";
}

// ============================================================================
// 3. WebView JS 注入 - 拦截 fetch 请求
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

static IMP orig_addScriptMessageHandler = NULL;

static id fake_addScriptMessageHandler(id self, SEL _cmd, id handler, id name) {
    // 注入 JS 脚本到 WebView
    WKUserScript *script = [[WKUserScript alloc]
        initWithSource:getInjectionJS()
        injectionTime:WKUserScriptInjectionTimeAtDocumentStart
        forMainFrameOnly:NO];
    [(WKUserContentController *)self addUserScript:script];

    // 调用原始实现
    return ((id (*)(id, SEL, id, id))orig_addScriptMessageHandler)(self, _cmd, handler, name);
}

// ============================================================================
// 4. 入口 (constructor)
//
// constructor 中不能调用 dlopen/dlsym (会触发 dyld 重入崩溃)。
// ObjC runtime 函数 (objc_getClass 等) 可以安全调用。
// fishhook 通过 dispatch_after_f 延迟 1 秒执行。
// ============================================================================

static void delayed_fishhook_init(void *ctx) {
    (void)ctx;
    struct rebinding r = {
        "CFNetworkCopySystemProxySettings",
        (void *)my_CFNetworkCopySystemProxySettings,
        (void **)&orig_CFNetworkCopySystemProxySettings
    };
    rebind_symbols(&r, 1);
    NSLog(@"[MTPlugin] 代理检测绕过已启用");
}

__attribute__((constructor))
static void mt_plugin_init(void) {
    @autoreleasepool {
        NSLog(@"[MTPlugin] 茅台抢购插件已加载");

        // 1. fishhook: 延迟绕过代理检测
        dispatch_after_f(
            dispatch_time(DISPATCH_TIME_NOW, (long long)(1.0 * NSEC_PER_SEC)),
            dispatch_get_main_queue(), NULL, delayed_fishhook_init);

        // 2. hook yx_headerEncryptString: 绕过注入检测
        Method encMethod = class_getInstanceMethod(
            [NSString class], NSSelectorFromString(@"yx_headerEncryptString"));
        if (encMethod) {
            orig_yx_headerEncryptString = (void *)method_getImplementation(encMethod);
            method_setImplementation(encMethod, (IMP)fake_yx_headerEncryptString);
            NSLog(@"[MTPlugin] 注入检测绕过已启用");
        }

        // 3. hook addScriptMessageHandler:name:: WebView JS 注入
        Method addMethod = class_getInstanceMethod(
            NSClassFromString(@"WKUserContentController"),
            NSSelectorFromString(@"addScriptMessageHandler:name:"));
        if (addMethod) {
            orig_addScriptMessageHandler = method_getImplementation(addMethod);
            method_setImplementation(addMethod, (IMP)fake_addScriptMessageHandler);
            NSLog(@"[MTPlugin] WebView JS注入已启用");
        }

        NSLog(@"[MTPlugin] 所有Hook就绪");
    }
}

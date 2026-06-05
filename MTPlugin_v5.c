/*
 * MTPlugin_v5.c - 鑼呭彴鎶㈣喘鎻掍欢 v5 (淇 constructor 宕╂簝)
 *
 * v4 宕╂簝鏍瑰洜锛歝onstructor 涓皟鐢?dlopen() 鈫?dyld 閲嶅叆 鈫?EXC_BAD_ACCESS at 0x0
 *
 * v5 淇绛栫暐锛?
 * 1. constructor 涓畬鍏ㄤ笉璋冪敤 dlopen/dlsym锛堥伩鍏?dyld 閲嶅叆锛?
 * 2. ObjC runtime 鍑芥暟锛歟xtern 澹版槑锛坙ibSystem 淇濊瘉鍏堝姞杞斤級
 * 3. CFNetwork fishhook锛歞ispatch_after_f 寤惰繜鍒?app 鍚姩鍚庢墽琛?
 * 4. __DATA_CONST 娈典繚鎶わ細浣跨敤 vm_protect 纭繚鍙啓锛坕OS 15+ 鍏煎锛?
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <dlfcn.h>
#include <dispatch/dispatch.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <mach/mach.h>
#include <unistd.h>   // for getpagesize()
// ============================================================================
// libdispatch (extern 澹版槑锛岄伩鍏嶅ご鏂囦欢渚濊禆)
// ============================================================================
typedef void *dispatch_queue_t;
typedef void (*dispatch_function_t)(void *);
extern dispatch_queue_t dispatch_get_main_queue(void);
extern void dispatch_after_f(unsigned long long when, dispatch_queue_t queue,
                             void *context, dispatch_function_t work);
extern unsigned long long dispatch_time(unsigned long long when, long long delta);
#define DISPATCH_TIME_NOW 0ull
#define NSEC_PER_SEC 1000000000ull

// ============================================================================
// CF 绫诲瀷
// ============================================================================
typedef const void *CFDictionaryRef;
typedef const void *CFMutableDictionaryRef;
typedef const void *CFTypeRef;
typedef const void *CFAllocatorRef;
typedef unsigned long CFIndex;

// ============================================================================
// ObjC 绫诲瀷
// ============================================================================
typedef void *id;
typedef void *Class;
typedef void *SEL;
typedef void *Method;
typedef id (*IMP)(id, SEL, ...);

// ============================================================================
// ObjC runtime - extern 澹版槑
// 杩欎簺鍑芥暟鍦?/usr/lib/libobjc.dylib 涓紝鑰?libobjc 閫氳繃 app 鐨?LC_LOAD_DYLIB
// 淇濊瘉鍦?dylib constructor 鎵ц鍓嶅凡瀹屾垚鍔犺浇鍜岀鍙风粦瀹氥€?
// ============================================================================
extern Class objc_getClass(const char *name);
extern SEL sel_registerName(const char *name);
extern Method class_getInstanceMethod(Class cls, SEL name);
extern IMP method_getImplementation(Method m);
extern IMP method_setImplementation(Method m, IMP imp);
extern id objc_msgSend(id self, SEL op, ...);

// ============================================================================
// CFNetwork/CoreFoundation - 寤惰繜鍔犺浇鐨勫嚱鏁版寚閽?
// 杩欎簺妗嗘灦涔熷湪 app 鍚姩鏃惰嚜鍔ㄥ姞杞斤紝浣嗘垜浠笉鍦?constructor 涓幏鍙栧畠浠€?
// 鑰屾槸鍦?app 瀹屽叏鍚姩鍚庯紙dispatch_after_f 鍥炶皟涓級鎵嶉€氳繃 dlsym 鑾峰彇銆?
// ============================================================================
static CFDictionaryRef (*_CFNetworkCopySystemProxySettings)(void) = 0;
static CFMutableDictionaryRef (*_CFDictionaryCreateMutable)(CFAllocatorRef, CFIndex,
                                                            const void *, const void *) = 0;
static void (*_CFRelease)(CFTypeRef) = 0;

/*
 * load_cf_symbols() - 閫氳繃 dlsym 鑾峰彇 CFNetwork/CoreFoundation 鍑芥暟
 *
 * 瀹夊叏鎬э細姝ゅ嚱鏁板彧鍦?dispatch_after_f 鍥炶皟涓皟鐢紙app 鍚姩鍚?1 绉掞級锛?
 * 姝ゆ椂 dyld 宸插畬鍏ㄥ垵濮嬪寲锛宒lopen/dlsym 瀹夊叏鍙敤銆?
 *
 * 浣跨敤 RTLD_NOLOAD锛?x10锛夛細浠呮煡鎵惧凡鍔犺浇鐨勫簱锛屼笉瑙﹀彂鏂板姞杞姐€?
 * CFNetwork 宸查€氳繃 app 鐨?LC_LOAD_DYLIB 淇濊瘉宸插姞杞姐€?
 */
static void load_cf_symbols(void) {
    static int loaded = 0;
    if (loaded) return;
    loaded = 1;

    extern void *dlopen(const char *, int);
    extern void *dlsym(void *, const char *);

    void *cfn = dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", 0x10);
    if (cfn) {
        _CFNetworkCopySystemProxySettings =
            (CFDictionaryRef(*)(void))dlsym(cfn, "CFNetworkCopySystemProxySettings");
    }

    void *cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", 0x10);
    if (cf) {
        _CFDictionaryCreateMutable =
            (CFMutableDictionaryRef(*)(CFAllocatorRef, CFIndex, const void *, const void *))
            dlsym(cf, "CFDictionaryCreateMutable");
        _CFRelease = (void (*)(CFTypeRef))dlsym(cf, "CFRelease");
    }
}

// ============================================================================
// fishhook (绮剧畝鍐呰仈鐗?
// ============================================================================

#define LC_SEGMENT_64 0x19
#define LC_SYMTAB 0x2
#define LC_DYSYMTAB 0xB
#define S_LAZY_SYMBOL_POINTERS 0x7
#define S_NON_LAZY_SYMBOL_POINTERS 0x6
#define SECTION_TYPE 0xff
#define INDIRECT_SYMBOL_ABS 0x80000000
#define INDIRECT_SYMBOL_LOCAL 0x40000000

struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

struct rebindings_entry {
    struct rebinding *rebindings;
    int rebindings_nel;
    struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head = 0;

/*
 * make_segment_writable() - 纭繚鍐呭瓨鍖哄煙鍙啓
 *
 * iOS 15+ 灏?__DATA_CONST 璁句负鍙啓淇濇姢锛宖ishhook 闇€瑕佸啓鍏ヨ娈点€?
 * 浣跨敤 vm_protect 涓存椂鍏抽棴鍐欎繚鎶ゃ€?
 */
static void make_segment_writable(void *addr, size_t size) {
    mach_port_t task = mach_task_self();
    vm_address_t page = (vm_address_t)addr & ~(getpagesize() - 1);
    vm_protect(task, page, size + ((vm_address_t)addr - page), 0, VM_PROT_READ | VM_PROT_WRITE);
}

static void perform_rebinding_with_header(void *header, intptr_t slide) {
    uint32_t ncmds = *(uint32_t *)((uintptr_t)header + 16);
    uintptr_t cur = (uintptr_t)header + 32;
    void *linkedit = 0, *symtab_cmd = 0, *dysymtab_cmd = 0;

    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd = *(uint32_t *)cur;
        uint32_t cmdsize = *(uint32_t *)(cur + 4);
        if (cmd == LC_SEGMENT_64) {
            if (strcmp((char *)(cur + 8), "__LINKEDIT") == 0)
                linkedit = (void *)cur;
        } else if (cmd == LC_SYMTAB) {
            symtab_cmd = (void *)cur;
        } else if (cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (void *)cur;
        }
        cur += cmdsize;
    }
    if (!linkedit || !symtab_cmd || !dysymtab_cmd) return;

    uintptr_t linkedit_base = (uintptr_t)slide +
                              (uintptr_t)*(uint64_t *)((uintptr_t)linkedit + 24) -
                              (uintptr_t)*(uint64_t *)((uintptr_t)linkedit + 40);

    char *strtab = (char *)(linkedit_base + *(uint32_t *)((uintptr_t)symtab_cmd + 16));
    uint32_t *indirect_symtab =
        (uint32_t *)(linkedit_base + *(uint32_t *)((uintptr_t)dysymtab_cmd + 48));

    cur = (uintptr_t)header + 32;
    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd = *(uint32_t *)cur;
        uint32_t cmdsize = *(uint32_t *)(cur + 4);
        if (cmd == LC_SEGMENT_64) {
            char *segname = (char *)(cur + 8);
            if (strcmp(segname, "__DATA") == 0 || strcmp(segname, "__DATA_CONST") == 0) {
                uint32_t nsects = *(uint32_t *)(cur + 64);
                uintptr_t sect_start = cur + 72;
                for (uint32_t j = 0; j < nsects; j++) {
                    uintptr_t sect = sect_start + j * 80;
                    uint32_t type = *(uint32_t *)(sect + 64) & SECTION_TYPE;
                    if (type == S_LAZY_SYMBOL_POINTERS || type == S_NON_LAZY_SYMBOL_POINTERS) {
                        uint32_t *indices = indirect_symtab + *(uint32_t *)(sect + 72);
                        uint64_t addr = *(uint64_t *)(sect + 16);
                        uint64_t size = *(uint64_t *)(sect + 24);
                        void **bindings = (void **)((uintptr_t)slide + (uintptr_t)addr);

                        // 纭繚璇ユ鍙啓锛坕OS 15+ 鍏煎锛?
                        make_segment_writable(bindings, (size_t)size);

                        uint32_t count = (uint32_t)(size / sizeof(void *));
                        uint32_t symoff = *(uint32_t *)((uintptr_t)symtab_cmd + 8);
                        for (uint32_t k = 0; k < count; k++) {
                            uint32_t sym_idx = indices[k];
                            if (sym_idx == INDIRECT_SYMBOL_ABS ||
                                sym_idx == INDIRECT_SYMBOL_LOCAL ||
                                sym_idx == (INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL))
                                continue;
                            char *sym = strtab + *(uint32_t *)(linkedit_base + symoff +
                                                               sym_idx * 16);
                            if (sym[0] == '_') sym++;
                            struct rebindings_entry *e = _rebindings_head;
                            while (e) {
                                for (int r = 0; r < e->rebindings_nel; r++) {
                                    if (strcmp(sym, e->rebindings[r].name) == 0) {
                                        if (e->rebindings[r].replaced &&
                                            bindings[k] != e->rebindings[r].replacement) {
                                            *(e->rebindings[r].replaced) = bindings[k];
                                        }
                                        bindings[k] = e->rebindings[r].replacement;
                                        goto next_sym;
                                    }
                                }
                                e = e->next;
                            }
                        next_sym:;
                        }
                    }
                }
            }
        }
        cur += cmdsize;
    }
}

static int rebind_symbols(struct rebinding rebindings[], int nel) {
    struct rebindings_entry *e =
        (struct rebindings_entry *)malloc(sizeof(struct rebindings_entry));
    if (!e) return -1;
    e->rebindings = (struct rebinding *)malloc(sizeof(struct rebinding) * nel);
    if (!e->rebindings) {
        free(e);
        return -1;
    }
    memcpy(e->rebindings, rebindings, sizeof(struct rebinding) * nel);
    e->rebindings_nel = nel;
    e->next = _rebindings_head;
    _rebindings_head = e;

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++)
        perform_rebinding_with_header((void *)_dyld_get_image_header(i),
                                      _dyld_get_image_slide(i));
    return 0;
}

// ============================================================================
// 1. 缁曡繃浠ｇ悊/VPN 妫€娴?(fishhook CFNetworkCopySystemProxySettings)
// ============================================================================

static CFDictionaryRef (*orig_CFNetworkCopySystemProxySettings)(void) = 0;

static CFDictionaryRef my_CFNetworkCopySystemProxySettings(void) {
    if (!orig_CFNetworkCopySystemProxySettings) return 0;
    CFDictionaryRef orig = orig_CFNetworkCopySystemProxySettings();
    if (!orig || !_CFDictionaryCreateMutable) return orig;
    // 杩斿洖绌哄瓧鍏?鈫?app 璁や负娌℃湁浠ｇ悊閰嶇疆
    return _CFDictionaryCreateMutable(0, 0, 0, 0);
}

/*
 * delayed_fishhook_init() - 鍦?app 瀹屽叏鍚姩鍚庢墽琛?fishhook
 *
 * 閫氳繃 dispatch_after_f 寤惰繜 1 绉掕皟鐢紝姝ゆ椂锛?
 * - dyld 宸插畬鍏ㄥ垵濮嬪寲
 * - 鎵€鏈?framework 宸插姞杞?
 * - dlopen/dlsym 瀹夊叏鍙敤
 * - main run loop 宸插惎鍔?
 */
static void delayed_fishhook_init(void *ctx) {
    (void)ctx;

    // 鍔犺浇 CFNetwork/CoreFoundation 鍑芥暟鎸囬拡
    load_cf_symbols();

    // fishhook: 鏇挎崲 CFNetworkCopySystemProxySettings
    if (_CFNetworkCopySystemProxySettings) {
        struct rebinding r = {"CFNetworkCopySystemProxySettings",
                              (void *)my_CFNetworkCopySystemProxySettings,
                              (void **)&orig_CFNetworkCopySystemProxySettings};
        rebind_symbols(&r, 1);
    }
}

// ============================================================================
// 2. 缁曡繃娉ㄥ叆妫€娴?(hook yx_headerEncryptString)
//
// 杩欎釜 hook 鍦?constructor 涓洿鎺ユ墽琛岋紙涓嶄緷璧?dlopen/dlsym锛夈€?
// yx_headerEncryptString 鏄?NSString 鐨?category 鏂规硶锛岄€氳繃 ObjC runtime
// 鐨?class_getInstanceMethod/method_setImplementation 杩涜 hook銆?
// ============================================================================

static IMP orig_yx = 0;

static id fake_yx(id self, SEL _cmd) {
    (void)self;
    (void)_cmd;
    // 杩斿洖 "鍏ㄩ儴閫氳繃" 鐨勫畨鍏ㄧ姸鎬?
    return objc_msgSend((id)objc_getClass("NSString"),
                        sel_registerName("stringWithUTF8String:"),
                        "root/0;debug/0;proxy/0;inject/0");
}

// ============================================================================
// 3. WebView JS 娉ㄥ叆 (hook addScriptMessageHandler:name:)
//
// 鍚屾牱鍦?constructor 涓洿鎺ユ墽琛岋紝涓嶄緷璧?dlopen/dlsym銆?
// hook WKUserContentController 鐨?addScriptMessageHandler:name: 鏂规硶锛?
// 鍦?WebView 鍔犺浇鍓嶆敞鍏?fetch 鎷︽埅鑴氭湰銆?
// ============================================================================

static IMP orig_add = 0;

static const char *js_code =
    "(function(){"
    "const o=window.fetch;"
    "window.fetch=function(i,n){"
    "const a=[i,n];"
    "return o.apply(this,a).then(r=>r.clone().text().then(t=>{"
    "let x=t;try{"
    "const j=JSON.parse(t);"
    "if(j.data&&j.data.itemId==='IMTP1000313'&&"
    "((j.data.purchaseInfoMap&&Object.keys(j.data.purchaseInfoMap).length===0)||"
    "j.data.forbiddenBuyDesc)){"
    "x=JSON.stringify({code:2000,data:{itemId:'IMTP1000313',offline:false,"
    "purchaseInfoMap:{'1001017':{defaultSkuFlag:true,"
    "purchaseInfo:{skuId:'741',inventory:12,presellInventory:12,canAddCart:false,"
    "limitCount:6,inDeliveryArea:true,showSelfPickUpBtn:false,disable:false,"
    "defaultSkuFlag:false}}},showSaleUnit:true,nationWide:false}});}"
    "else if(j.data&&j.data.purchaseInfoMap){"
    "const m=j.data.purchaseInfoMap;Object.keys(m).forEach(k=>{"
    "const p=m[k]&&m[k].purchaseInfo;if(!p)return;"
    "if('forbiddenBuyDesc' in p)delete p.forbiddenBuyDesc;"
    "p.inventory=12;p.presellInventory=12;});x=JSON.stringify(j);}"
    "else if(j===2||(j.code&&(j.code===4293||j.code===4030||j.code===4031))){"
    "const h=new Headers(n&&n.headers||{});h.set('MT-K',Date.now().toString());"
    "return o.call(this,i,{...(n||{}),headers:h}).then(r2=>r2.clone().text()."
    "then(t2=>new Response(t2,{status:r2.status,statusText:r2.statusText,"
    "headers:r2.headers})));}"
    "}catch(e){}"
    "return new Response(x,{status:r.status,statusText:r.statusText,"
    "headers:r.headers});"
    "}));};"
    "})();";

static void fake_add(id self, SEL _cmd, id handler, id name) {
    Class wk = objc_getClass("WKUserScript");
    if (!wk) {
        if (orig_add) orig_add(self, _cmd, handler, name);
        return;
    }
    Class ns = objc_getClass("NSString");
    id j = objc_msgSend((id)ns, sel_registerName("stringWithUTF8String:"), js_code);
    id a = objc_msgSend((id)wk, sel_registerName("alloc"));
    id sc = objc_msgSend(a,
                         sel_registerName("initWithSource:injectionTime:forMainFrameOnly:"),
                         j, (id)0, (id)0);
    objc_msgSend(self, sel_registerName("addUserScript:"), sc);
    if (orig_add) orig_add(self, _cmd, handler, name);
}

// ============================================================================
// 鍏ュ彛 (__attribute__((constructor)))
//
// 瀹夊叏绾︽潫锛堥槻姝?dyld 閲嶅叆宕╂簝锛夛細
// 鉁?鍙互璋冪敤锛歰bjc_getClass, sel_registerName, class_getInstanceMethod 绛?
//    锛坙ibSystem/libobjc 淇濊瘉鍏堜簬 dylib 鍔犺浇锛?
// 鉁?鍙互璋冪敤锛歘dyld_image_count, _dyld_get_image_header 绛?
//    锛坙ibdyld 淇濊瘉鍏堜簬 dylib 鍔犺浇锛岀敤浜?fishhook锛?
// 鉁?鍙互璋冪敤锛歴trcmp, memcpy, malloc, free
//    锛坙ibSystem 淇濊瘉鍏堜簬 dylib 鍔犺浇锛?
// 鉁?鍙互璋冪敤锛歞ispatch_after_f
//    锛坙ibdispatch 鍦?libSystem 涓紝淇濊瘉鍙敤锛?
// 鉂?绂佹璋冪敤锛歞lopen, dlsym
//    锛堜細瑙﹀彂 dyld 閲嶅叆 鈫?dyld_image_containing_address 鈫?宕╂簝锛?
// ============================================================================

__attribute__((constructor)) static void init(void) {

    // ---- 1. Hook yx_headerEncryptString: 缁曡繃娉ㄥ叆妫€娴?----
    // 浼樺厛绾ф渶楂橈紝蹇呴』鍦?constructor 涓珛鍗冲畬鎴?
    // 浣跨敤 ObjC runtime 鍑芥暟锛坋xtern 澹版槑锛屼笉渚濊禆 dlopen锛?
    Class ns = objc_getClass("NSString");
    if (ns) {
        Method m = class_getInstanceMethod(ns, sel_registerName("yx_headerEncryptString"));
        if (m) {
            orig_yx = method_getImplementation(m);
            method_setImplementation(m, (IMP)fake_yx);
        }
    }

    // ---- 2. Hook WKUserContentController: WebView JS 娉ㄥ叆 ----
    // 鍚屾牱鍦?constructor 涓珛鍗冲畬鎴?
    Class wkucc = objc_getClass("WKUserContentController");
    if (wkucc) {
        Method m = class_getInstanceMethod(
            wkucc, sel_registerName("addScriptMessageHandler:name:"));
        if (m) {
            orig_add = method_getImplementation(m);
            method_setImplementation(m, (IMP)fake_add);
        }
    }

    // ---- 3. fishhook: 缁曡繃浠ｇ悊/VPN 妫€娴?----
    // 銆愬叧閿€戜笉鍦?constructor 涓皟鐢?dlopen/dlsym锛?
    // 浣跨敤 dispatch_after_f 寤惰繜 1 绉掓墽琛岋細
    //   - dispatch_after_f 鎺ュ彈 C 鍑芥暟鎸囬拡锛堜笉闇€瑕?block 璇硶锛?
    //   - 1 绉掑悗 main run loop 宸插惎鍔紝dlopen 瀹夊叏鍙敤
    //   - 姝ゆ椂 CFNetwork 宸插畬鍏ㄥ垵濮嬪寲锛宖ishhook 鍙畨鍏ㄦ浛鎹㈠嚱鏁?
    dispatch_after_f(dispatch_time(DISPATCH_TIME_NOW, (long long)(1.0 * NSEC_PER_SEC)),
                     dispatch_get_main_queue(), NULL, delayed_fishhook_init);
}
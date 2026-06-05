/*
 * MTPlugin.m - 诊断版 v3 (逐步排查闪退)
 *
 * 策略: 先只加日志，不加任何 hook。
 * 如果这个版本也闪退 → 说明是 dylib 本身的问题（签名/链接/架构）
 * 如果不闪退 → 逐步开启 hook 定位具体是哪个
 */

#import <Foundation/Foundation.h>

static void delayed_log(void *ctx) {
    (void)ctx;
    NSLog(@"[MTPlugin] ✅ dispatch_after_f 1秒回调正常");
}

__attribute__((constructor))
static void mt_plugin_init(void) {
    NSLog(@"[MTPlugin] ✅ dylib 加载成功，constructor 执行");

    // 测试 dispatch_after_f 是否正常
    dispatch_after_f(
        dispatch_time(DISPATCH_TIME_NOW, (long long)(1.0 * NSEC_PER_SEC)),
        dispatch_get_main_queue(), NULL, delayed_log);

    NSLog(@"[MTPlugin] ✅ 延迟任务已安排");
}

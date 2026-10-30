/* QuickJS host: no std/os modules, loader, host paths, network or subprocess APIs.
 * Protocol is stdin/stdout only. OS containment is mandatory, never a test bypass.
 */
#define _GNU_SOURCE
#include "quickjs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#if defined(__APPLE__)
#include <sandbox.h>
#elif defined(__linux__)
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#endif
#define FRAME (1024 * 1024)
static double deadline;
static double now(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec + ts.tv_nsec / 1e9; }
static int interrupt(JSRuntime *rt, void *opaque) { (void)rt; (void)opaque; return now() > deadline; }
static int contain(void) {
    struct rlimit cpu = {30,30}, files = {0,0}, core = {0,0};
    if (setrlimit(RLIMIT_CPU,&cpu) || setrlimit(RLIMIT_FSIZE,&files) || setrlimit(RLIMIT_CORE,&core)) return -1;
#if defined(__APPLE__)
    char *error = NULL;
    /* Anonymous pipes are inherited; every named file operation is denied. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    int rc = sandbox_init("(version 1)(deny default)(allow sysctl-read)", 0, &error);
    if (error) sandbox_free_error(error);
    #pragma clang diagnostic pop
    return rc;
#elif defined(__linux__)
#if defined(__x86_64__)
#define ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define ARCH AUDIT_ARCH_AARCH64
#else
    return -1;
#endif
#ifdef ARCH
#define ALLOW(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_##n, 0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ARCH, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
        ALLOW(read), ALLOW(write), ALLOW(close), ALLOW(clock_gettime),
        ALLOW(mmap), ALLOW(munmap), ALLOW(mprotect), ALLOW(brk),
        ALLOW(futex), ALLOW(rt_sigaction), ALLOW(rt_sigprocmask), ALLOW(rt_sigreturn),
        ALLOW(exit), ALLOW(exit_group), ALLOW(madvise), ALLOW(getrandom),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS)
    };
    struct sock_fprog p = { .len = sizeof(filter)/sizeof(filter[0]), .filter = filter };
    return prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) || prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p);
#endif
#else
    return -1;
#endif
}
static char *line(void) {
    char *s = malloc(FRAME+1); if (!s) return NULL;
    size_t n = 0; char c;
    while (n < FRAME) {
        if (read(0,&c,1) != 1) { free(s); return NULL; }
        if (c == '\n') { s[n] = 0; return s; }
        s[n++] = c;
    }
    free(s); return NULL;
}
static int send_frame(const char *s) {
    size_t n = strlen(s); if (n > FRAME) return -1;
    while (n) { ssize_t k = write(1,s,n); if (k <= 0) return -1; s += k; n -= k; }
    return write(1,"\n",1) == 1 ? 0 : -1;
}
static JSValue rpc(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)self;
    if (argc != 1) return JS_ThrowTypeError(ctx,"invalid request");
    JSValue text = JS_JSONStringify(ctx,argv[0],JS_UNDEFINED,JS_UNDEFINED);
    const char *raw = JS_ToCString(ctx,text);
    if (!raw || strlen(raw) > 65536) { if (raw) JS_FreeCString(ctx,raw); JS_FreeValue(ctx,text); return JS_ThrowTypeError(ctx,"request limit"); }
    char *frame = malloc(strlen(raw)+16);
    if (!frame) { JS_FreeCString(ctx,raw); JS_FreeValue(ctx,text); return JS_ThrowOutOfMemory(ctx); }
    sprintf(frame,"{\"call\":%s}",raw);
    int sent = send_frame(frame); free(frame); JS_FreeCString(ctx,raw); JS_FreeValue(ctx,text);
    if (sent) return JS_ThrowTypeError(ctx,"transport unavailable");
    char *response = line(); if (!response) return JS_ThrowTypeError(ctx,"transport unavailable");
    JSValue obj = JS_ParseJSON(ctx,response,strlen(response),"broker"); free(response);
    if (JS_IsException(obj)) return obj;
    JSValue value = JS_GetPropertyStr(ctx,obj,"value"); JS_FreeValue(ctx,obj); return value;
}
static JSValue output(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv) {
    (void)self;
    if (argc != 1) return JS_ThrowTypeError(ctx,"invalid output");
    JSValue text = JS_ToString(ctx,argv[0]);
    JSValue frame = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx,frame,"output",text);
    JSValue encoded = JS_JSONStringify(ctx,frame,JS_UNDEFINED,JS_UNDEFINED);
    const char *s = JS_ToCString(ctx,encoded);
    int rc = s ? send_frame(s) : -1;
    if (s) JS_FreeCString(ctx,s);
    JS_FreeValue(ctx,encoded); JS_FreeValue(ctx,frame);
    if (rc) return JS_ThrowTypeError(ctx,"output limit");
    return JS_UNDEFINED;
}
/* Exceptions are private protocol data; the parent masks and fingerprints them,
 * then exposes a fixed error category instead of the original message. */
static int failed_js(JSContext *ctx, JSValue error) {
    JSValue text = JS_ToString(ctx,error); JS_FreeValue(ctx,error);
    size_t length=0;
    const char *raw=JS_ToCStringLen(ctx,&length,text);
    if (!raw || length>4096) { if(raw)JS_FreeCString(ctx,raw); JS_FreeValue(ctx,text); return 1; }
    JSValue frame=JS_NewObject(ctx);
    JS_SetPropertyStr(ctx,frame,"error",JS_NewStringLen(ctx,raw,length));
    JS_FreeCString(ctx,raw); JS_FreeValue(ctx,text);
    JSValue encoded=JS_JSONStringify(ctx,frame,JS_UNDEFINED,JS_UNDEFINED);
    const char *bytes=JS_ToCString(ctx,encoded);
    if(bytes) { send_frame(bytes); JS_FreeCString(ctx,bytes); }
    JS_FreeValue(ctx,encoded); JS_FreeValue(ctx,frame); return 1;
}
int main(void) {
#if defined(__APPLE__)
    struct rlimit descriptors;
    if (getrlimit(RLIMIT_NOFILE,&descriptors) || descriptors.rlim_cur > 1048576) return 1;
    for (int fd=3; (rlim_t)fd<descriptors.rlim_cur; fd++) close(fd);
#elif defined(__linux__)
    if (syscall(__NR_close_range,3,~0U,0)) return 1;
#else
    return 1;
#endif
    JSRuntime *rt = JS_NewRuntime(); if (!rt) return 1;
    JS_SetMemoryLimit(rt,32 * 1024 * 1024); JS_SetMaxStackSize(rt,512 * 1024);
    JSContext *ctx = JS_NewContext(rt); if (!ctx) return 1;
    JSValue global = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx,global,"__rpc",JS_NewCFunction(ctx,rpc,"rpc",1));
    JS_SetPropertyStr(ctx,global,"__output",JS_NewCFunction(ctx,output,"output",1));
    JS_FreeValue(ctx,global);
    deadline = now()+30; JS_SetInterruptHandler(rt,interrupt,NULL);
    if (contain()) return 1;
    char *request = line(); if (!request) return 1;
    JSValue obj = JS_ParseJSON(ctx,request,strlen(request),"request"); free(request);
    if (JS_IsException(obj)) return 1;
    JSValue src = JS_GetPropertyStr(ctx,obj,"script"); JS_FreeValue(ctx,obj);
    const char *script = JS_ToCString(ctx,src); if (!script || strlen(script)>32768) return 1;
    const char *prefix =
        "((rpc,out)=>{delete globalThis.__rpc;delete globalThis.__output;"
        "globalThis.tools=Object.freeze({call:async(name,args)=>rpc({name,arguments:args}),"
        "readBatch:async(reads)=>rpc({reads}),fetchToolSchema:async(schema)=>rpc({schema})});"
        "globalThis.console=Object.freeze({log:(...xs)=>out(xs.map(x=>typeof x==='string'?x:JSON.stringify(x)).join(''))});"
        "return (async()=>{\n";
    const char *suffix = "\n})().then(v=>{out(JSON.stringify(v===undefined?null:v));return true;});})(__rpc,__output)";
    size_t len = strlen(prefix)+strlen(script)+strlen(suffix)+1;
    char *program = malloc(len); if (!program) return 1;
    snprintf(program,len,"%s%s%s",prefix,script,suffix);
    JS_FreeCString(ctx,script); JS_FreeValue(ctx,src);
    JSValue result = JS_Eval(ctx,program,strlen(program),"script",JS_EVAL_TYPE_GLOBAL); free(program);
    if (JS_IsException(result)) return failed_js(ctx,JS_GetException(ctx));
    while (JS_PromiseState(ctx,result) == JS_PROMISE_PENDING) {
        JSContext *job_ctx;
        int rc = JS_ExecutePendingJob(rt,&job_ctx);
        if (rc < 0) return failed_js(job_ctx,JS_GetException(job_ctx));
        if (rc == 0 || now()>deadline) return 1;
    }
    if (JS_PromiseState(ctx,result) == JS_PROMISE_REJECTED) return failed_js(ctx,JS_PromiseResult(ctx,result));
    if (JS_PromiseState(ctx,result) != JS_PROMISE_FULFILLED) return 1;
    JS_FreeValue(ctx,result);
    if (send_frame("{\"done\":true}")) return 1;
    JS_FreeContext(ctx); JS_FreeRuntime(rt); return 0;
}

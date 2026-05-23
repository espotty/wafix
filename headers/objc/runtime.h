#pragma once
#include <stdint.h>

typedef void*  id;
typedef void*  Class;
typedef void*  SEL;
typedef void (*IMP)(void);
typedef struct objc_method* Method;
typedef struct objc_ivar*   Ivar;

extern id    objc_getClass(const char *name);
extern SEL   sel_registerName(const char *str);
extern Method class_getInstanceMethod(Class cls, SEL name);
extern Method class_getClassMethod(Class cls, SEL name);
extern IMP    method_getImplementation(Method m);
extern IMP    method_setImplementation(Method m, IMP imp);
extern void   method_exchangeImplementations(Method m1, Method m2);
extern IMP    class_replaceMethod(Class cls, SEL name, IMP imp, const char *types);
extern id     objc_msgSend(id self, SEL op, ...);
extern id     objc_getMetaClass(const char *name);
extern Class* objc_copyClassList(unsigned int *outCount);
extern int    objc_getClassList(Class *buffer, int bufferCount);
extern const char* class_getName(Class cls);

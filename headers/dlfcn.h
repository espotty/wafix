#pragma once

#define RTLD_LAZY   0x1
#define RTLD_NOW    0x2
#define RTLD_GLOBAL 0x8
#define RTLD_LOCAL  0x4
#define RTLD_NOLOAD 0x10
#define RTLD_DEFAULT ((void*)-2)
#define RTLD_NEXT    ((void*)-1)

extern void* dlopen(const char* path, int mode);
extern void* dlsym(void* handle, const char* symbol);
extern int   dlclose(void* handle);
extern const char* dlerror(void);

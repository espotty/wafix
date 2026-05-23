#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void MSHookFunction(void *symbol, void *hook, void **old);
void MSHookMessageEx(void *cls, void *sel, void *hook, void **old);

#ifdef __cplusplus
}
#endif

#pragma once
#include "stdint.h"
extern void* malloc(size_t size);
extern void  free(void *ptr);
extern void* calloc(size_t nmemb, size_t size);
extern void  abort(void);

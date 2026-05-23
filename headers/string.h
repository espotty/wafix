#pragma once
#include "stdint.h"
extern int    strcmp(const char *s1, const char *s2);
extern char*  strstr(const char *haystack, const char *needle);
extern int    strncmp(const char *s1, const char *s2, size_t n);
extern char*  strcpy(char *dst, const char *src);
extern char*  strncpy(char *dst, const char *src, size_t n);
extern size_t strlen(const char *s);
extern void*  memcpy(void *dst, const void *src, size_t n);
extern void*  memset(void *s, int c, size_t n);
extern int    memcmp(const void *s1, const void *s2, size_t n);

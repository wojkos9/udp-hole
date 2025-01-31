#pragma once
#include <stdio.h>

extern int VERBOSE;

#define debug(...) if (VERBOSE) fprintf(stderr, __VA_ARGS__)
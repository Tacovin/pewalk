#ifndef PEWALK_REPORT_H
#define PEWALK_REPORT_H

#include "info.h"

#define SHOW_IMPORTS 1
#define SHOW_EXPORTS 2

void report_text(const char *path, const pe_t *pe, const rich_t *rich, const info_t *in, int flags);
void report_json(const char *path, const pe_t *pe, const rich_t *rich, const info_t *in, int flags);

#endif

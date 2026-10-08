#ifndef PEWALK_RICH_H
#define PEWALK_RICH_H

#include "pe.h"

#define RICH_MAX 128

typedef struct {
    uint16_t prodid;
    uint16_t build;
    uint32_t count;
} rich_entry_t;

typedef struct {
    int      found;
    uint32_t key;        /* the dword after "Rich", also the checksum */
    uint32_t calc;       /* checksum we computed ourselves */
    uint32_t start;      /* file offset of "DanS" */
    uint32_t end;        /* file offset of "Rich" */
    int      n;
    rich_entry_t e[RICH_MAX];
} rich_t;

int rich_parse(const pe_t *pe, rich_t *r);

const char *rich_prod_name(uint16_t prodid);
const char *rich_vs_version(uint16_t prodid, uint16_t build);

#endif

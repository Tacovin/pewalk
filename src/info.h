#ifndef PEWALK_INFO_H
#define PEWALK_INFO_H

#include "pe.h"
#include "rich.h"

#define MAX_TLS_CB 32
#define MAX_NOTES  32

typedef struct {
    const char *dll;
    const char *name;    /* NULL if imported by ordinal */
    uint16_t    ordinal;
} import_t;

typedef struct {
    import_t *imp;
    int       nimp;
    int       ndll;

    const char  *exp_dll;
    uint32_t     exp_count;
    uint32_t     exp_nnames;
    const char **exp_names;
    int          exp_names_got;

    uint64_t tls_cb[MAX_TLS_CB];
    int      ntls;

    const char *pdb;
    int         repro;   /* /Brepro build, timestamp is a hash */

    uint64_t overlay_off;
    uint64_t overlay_size;
    double   overlay_entropy;
    uint64_t cert_off;
    uint64_t cert_size;
    uint64_t symtab_off;
    uint64_t symtab_size;    /* symbols + string table */

    int  is_dotnet;

    int  nnotes;
    char notes[MAX_NOTES][200];
} info_t;

void info_collect(const pe_t *pe, const rich_t *rich, info_t *in);
void info_free(info_t *in);

#endif

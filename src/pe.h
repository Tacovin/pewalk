#ifndef PEWALK_PE_H
#define PEWALK_PE_H

#include <stddef.h>
#include <stdint.h>

#define MAX_SECTIONS 96

#define DIR_EXPORT    0
#define DIR_IMPORT    1
#define DIR_RESOURCE  2
#define DIR_SECURITY  4
#define DIR_RELOC     5
#define DIR_DEBUG     6
#define DIR_TLS       9
#define DIR_IAT       12
#define DIR_DELAY     13
#define DIR_CLR       14

#define SCN_CODE     0x00000020
#define SCN_EXEC     0x20000000
#define SCN_READ     0x40000000
#define SCN_WRITE    0x80000000

typedef struct {
    char     name[9];
    uint32_t vsize;
    uint32_t va;
    uint32_t raw_size;
    uint32_t raw_ptr;
    uint32_t chars;
    double   entropy;
} section_t;

typedef struct {
    uint32_t rva;
    uint32_t size;
} datadir_t;

typedef struct {
    const uint8_t *data;
    size_t   size;

    uint32_t e_lfanew;
    uint16_t machine;
    uint16_t nsections;      /* what the header claims */
    uint32_t timestamp;
    uint32_t symtab_off;     /* COFF symbol table, only gcc/mingw sets it */
    uint32_t nsyms;
    uint16_t characteristics;

    int      is64;
    uint32_t entry_rva;
    uint64_t image_base;
    uint32_t sect_align;
    uint32_t file_align;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_chars;

    uint32_t  ndirs;
    datadir_t dirs[16];

    int       nsect;         /* what we actually parsed */
    section_t sect[MAX_SECTIONS];
} pe_t;

static inline uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static inline uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

int pe_load(pe_t *pe, const uint8_t *data, size_t size, char *err, size_t errlen);

/* returns 1 if [off, off+len) is inside the file */
int pe_has(const pe_t *pe, uint64_t off, uint64_t len);

/* file offset for an rva, or -1 if it isn't backed by file data */
int64_t pe_rva2off(const pe_t *pe, uint32_t rva);

/* NUL terminated string at rva, NULL if it runs off the end */
const char *pe_str(const pe_t *pe, uint32_t rva, size_t maxlen);

/* index of the section containing rva, -1 if none */
int pe_section_of(const pe_t *pe, uint32_t rva);

uint32_t pe_raw_ptr(const pe_t *pe, const section_t *s);

double entropy(const uint8_t *buf, size_t len);

#endif

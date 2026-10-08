#include <math.h>
#include <stdio.h>
#include <string.h>

#include "pe.h"

#define PE_SIG 0x00004550 /* "PE\0\0" */

int pe_has(const pe_t *pe, uint64_t off, uint64_t len)
{
    return off <= pe->size && len <= pe->size - off;
}

uint32_t pe_raw_ptr(const pe_t *pe, const section_t *s)
{
    /* The loader rounds PointerToRawData down to 0x200 regardless of what
     * FileAlignment says. Some packers abuse this so we have to do it too. */
    if (pe->file_align < 0x200)
        return s->raw_ptr;
    return s->raw_ptr & ~0x1FFu;
}

static uint32_t sect_vsize(const section_t *s)
{
    /* VirtualSize = 0 happens in old linkers, fall back to raw size */
    return s->vsize ? s->vsize : s->raw_size;
}

int pe_section_of(const pe_t *pe, uint32_t rva)
{
    for (int i = 0; i < pe->nsect; i++) {
        const section_t *s = &pe->sect[i];
        if (rva >= s->va && rva - s->va < sect_vsize(s))
            return i;
    }
    return -1;
}

int64_t pe_rva2off(const pe_t *pe, uint32_t rva)
{
    if (rva < pe->size_of_headers && rva < pe->size)
        return rva;

    int i = pe_section_of(pe, rva);
    if (i < 0)
        return -1;

    const section_t *s = &pe->sect[i];
    uint32_t delta = rva - s->va;
    if (delta >= s->raw_size)
        return -1; /* in memory only (.bss style) */

    uint64_t off = (uint64_t)pe_raw_ptr(pe, s) + delta;
    if (off >= pe->size)
        return -1;
    return (int64_t)off;
}

const char *pe_str(const pe_t *pe, uint32_t rva, size_t maxlen)
{
    int64_t off = pe_rva2off(pe, rva);
    if (off < 0)
        return NULL;

    const char *p = (const char *)pe->data + off;
    size_t left = pe->size - (size_t)off;
    if (left > maxlen)
        left = maxlen;
    if (!memchr(p, 0, left))
        return NULL;
    return p;
}

double entropy(const uint8_t *buf, size_t len)
{
    size_t freq[256] = {0};
    double h = 0.0;

    if (!len)
        return 0.0;

    for (size_t i = 0; i < len; i++)
        freq[buf[i]]++;

    for (int i = 0; i < 256; i++) {
        if (!freq[i])
            continue;
        double p = (double)freq[i] / (double)len;
        h -= p * log2(p);
    }
    return h;
}

#define FAIL(...) do { snprintf(err, errlen, __VA_ARGS__); return -1; } while (0)

int pe_load(pe_t *pe, const uint8_t *data, size_t size, char *err, size_t errlen)
{
    memset(pe, 0, sizeof(*pe));
    pe->data = data;
    pe->size = size;

    if (size < 0x40 || data[0] != 'M' || data[1] != 'Z')
        FAIL("no MZ header");

    pe->e_lfanew = rd32(data + 0x3C);
    if (!pe_has(pe, pe->e_lfanew, 24))
        FAIL("e_lfanew points outside the file (0x%x)", pe->e_lfanew);
    if (rd32(data + pe->e_lfanew) != PE_SIG)
        FAIL("PE signature not found at 0x%x", pe->e_lfanew);

    const uint8_t *coff = data + pe->e_lfanew + 4;
    pe->machine         = rd16(coff);
    pe->nsections       = rd16(coff + 2);
    pe->timestamp       = rd32(coff + 4);
    pe->symtab_off      = rd32(coff + 8);
    pe->nsyms           = rd32(coff + 12);
    uint16_t opt_size   = rd16(coff + 16);
    pe->characteristics = rd16(coff + 18);

    uint32_t opt_off = pe->e_lfanew + 24;
    if (opt_size < 2 || !pe_has(pe, opt_off, opt_size))
        FAIL("optional header truncated");

    const uint8_t *opt = data + opt_off;
    uint16_t magic = rd16(opt);
    uint32_t dirs_off;

    if (magic == 0x10b) {
        if (opt_size < 96)
            FAIL("optional header too small for PE32");
        pe->image_base = rd32(opt + 28);
        pe->ndirs      = rd32(opt + 92);
        dirs_off       = 96;
    } else if (magic == 0x20b) {
        if (opt_size < 112)
            FAIL("optional header too small for PE32+");
        pe->is64       = 1;
        pe->image_base = rd64(opt + 24);
        pe->ndirs      = rd32(opt + 108);
        dirs_off       = 112;
    } else {
        FAIL("unknown optional header magic 0x%x", magic);
    }

    pe->entry_rva       = rd32(opt + 16);
    pe->sect_align      = rd32(opt + 32);
    pe->file_align      = rd32(opt + 36);
    pe->size_of_image   = rd32(opt + 56);
    pe->size_of_headers = rd32(opt + 60);
    pe->checksum        = rd32(opt + 64);
    pe->subsystem       = rd16(opt + 68);
    pe->dll_chars       = rd16(opt + 70);

    /* NumberOfRvaAndSizes can be anything, trust opt_size instead */
    uint32_t fit = (opt_size - dirs_off) / 8;
    uint32_t nd = pe->ndirs < 16 ? pe->ndirs : 16;
    if (nd > fit)
        nd = fit;
    for (uint32_t i = 0; i < nd; i++) {
        pe->dirs[i].rva  = rd32(opt + dirs_off + i * 8);
        pe->dirs[i].size = rd32(opt + dirs_off + i * 8 + 4);
    }

    uint32_t sh = opt_off + opt_size;
    int n = pe->nsections < MAX_SECTIONS ? pe->nsections : MAX_SECTIONS;
    for (int i = 0; i < n; i++, sh += 40) {
        if (!pe_has(pe, sh, 40))
            break;
        const uint8_t *p = data + sh;
        section_t *s = &pe->sect[pe->nsect++];

        memcpy(s->name, p, 8);
        s->name[8]  = 0;
        s->vsize    = rd32(p + 8);
        s->va       = rd32(p + 12);
        s->raw_size = rd32(p + 16);
        s->raw_ptr  = rd32(p + 20);
        s->chars    = rd32(p + 36);

        uint64_t rp = pe_raw_ptr(pe, s);
        uint64_t len = s->raw_size;
        if (rp >= size)
            len = 0;
        else if (len > size - rp)
            len = size - rp;
        s->entropy = entropy(data + rp, (size_t)len);
    }

    if (pe->nsect == 0 && pe->nsections != 0)
        FAIL("section table is outside the file");

    return 0;
}

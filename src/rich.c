/*
 * Rich header: undocumented block that MS link.exe drops between the DOS
 * stub and the PE header. Every entry is (product id, build, count) for one
 * tool that produced objects in the binary, xored with a key. The key is
 * also a checksum over the DOS header + entries, so if someone edits the
 * entries the checksum breaks. Copying the whole block from another file
 * with the same DOS stub still passes though.
 */
#include <string.h>

#include "rich.h"

#define RICH_MAGIC 0x68636952 /* "Rich" */
#define DANS_MAGIC 0x536E6144 /* "DanS" */

static uint32_t rol32(uint32_t v, unsigned n)
{
    n &= 31;
    if (!n)
        return v;
    return (v << n) | (v >> (32 - n));
}

int rich_parse(const pe_t *pe, rich_t *r)
{
    const uint8_t *d = pe->data;
    uint32_t limit = pe->e_lfanew;

    memset(r, 0, sizeof(*r));
    if (limit > pe->size)
        limit = (uint32_t)pe->size;

    /* "Rich" is dword aligned and sits somewhere after the DOS stub */
    uint32_t rich = 0;
    for (uint32_t off = 0x80; off + 8 <= limit; off += 4) {
        if (rd32(d + off) == RICH_MAGIC) {
            rich = off;
            break;
        }
    }
    if (!rich)
        return 0;

    uint32_t key = rd32(d + rich + 4);

    uint32_t dans = 0;
    for (uint32_t off = rich; off >= 0x80; off -= 4) {
        if ((rd32(d + off) ^ key) == DANS_MAGIC) {
            dans = off;
            break;
        }
    }
    if (!dans)
        return 0;

    r->found = 1;
    r->key   = key;
    r->start = dans;
    r->end   = rich;

    /* DanS is followed by 3 zero dwords (xored), entries start after that */
    for (uint32_t off = dans + 16; off + 8 <= rich; off += 8) {
        uint32_t id  = rd32(d + off) ^ key;
        uint32_t cnt = rd32(d + off + 4) ^ key;
        if (r->n < RICH_MAX) {
            r->e[r->n].prodid = (uint16_t)(id >> 16);
            r->e[r->n].build  = (uint16_t)(id & 0xFFFF);
            r->e[r->n].count  = cnt;
            r->n++;
        }
    }

    /* checksum = start offset + every byte before DanS rotated by its
     * position (e_lfanew is skipped) + every comp id rotated by its count */
    uint32_t sum = dans;
    for (uint32_t i = 0; i < dans; i++) {
        if (i >= 0x3C && i < 0x40)
            continue;
        sum += rol32(d[i], i);
    }
    for (uint32_t off = dans + 16; off + 8 <= rich; off += 8) {
        uint32_t id  = rd32(d + off) ^ key;
        uint32_t cnt = rd32(d + off + 4) ^ key;
        sum += rol32(id, cnt);
    }
    r->calc = sum;

    return 1;
}

/* Only the VS2015+ ids, checked against Windows system binaries (counts
 * like 1 linker / 1 cvtres line up). Older ones are all over the place in
 * the public lists so I left them as raw numbers instead of guessing. */
const char *rich_prod_name(uint16_t prodid)
{
    switch (prodid) {
    case 0x0001: return "Import0";
    case 0x00FF: return "Cvtres1400";
    case 0x0100: return "Export1400";
    case 0x0101: return "Implib1400";
    case 0x0102: return "Linker1400";
    case 0x0103: return "Masm1400";
    case 0x0104: return "Utc1900_C";
    case 0x0105: return "Utc1900_CPP";
    case 0x0108: return "Utc1900_LTCG_C";
    case 0x0109: return "Utc1900_LTCG_CPP";
    default:     return NULL;
    }
}

/* Visual Studio release from the toolchain build number. */
const char *rich_vs_version(uint16_t prodid, uint16_t build)
{
    if (prodid == 0x0001)
        return "-";

    /* MSVC 14.x (VS2015 and newer) all share the 0x00fd+ product ids and
     * the build number just keeps going up. Ranges are approximate, MS
     * internal builds (like the ones Windows is compiled with) fall in
     * between public releases. */
    if (prodid >= 0x00FD) {
        if (build >= 35700) return "VS2026";
        if (build >= 30400) return "VS2022";
        if (build >= 27508) return "VS2019";
        if (build >= 25017) return "VS2017";
        if (build >= 23026) return "VS2015";
        return "?";
    }

    switch (build) {
    case 21005: case 30501: case 30723: case 31101: case 40629:
        return "VS2013";
    case 51106: case 60315: case 60610: case 61030:
        return "VS2012";
    case 50727:
        return "VS2005/VS2012"; /* both shipped as 50727 */
    case 30319: case 40219:
        return "VS2010";
    case 21022: case 30729:
        return "VS2008";
    }
    return "?";
}

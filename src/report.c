#include <stdio.h>
#include <string.h>
#include <time.h>

#include "report.h"

#define EXPORTS_PREVIEW 10

static const char *machine_name(uint16_t m)
{
    switch (m) {
    case 0x014c: return "i386";
    case 0x8664: return "AMD64";
    case 0x01c0: return "ARM";
    case 0x01c4: return "ARMv7 Thumb-2";
    case 0xaa64: return "ARM64";
    case 0x0200: return "IA64";
    default:     return "unknown";
    }
}

static const char *subsystem_name(uint16_t s)
{
    switch (s) {
    case 1:  return "Native";
    case 2:  return "Windows GUI";
    case 3:  return "Windows console";
    case 9:  return "Windows CE";
    case 10: return "EFI application";
    case 11: return "EFI boot driver";
    case 12: return "EFI runtime driver";
    case 16: return "Boot application";
    default: return "unknown";
    }
}

static void fmt_time(uint32_t ts, char *buf, size_t len)
{
    time_t t = (time_t)ts;
    struct tm *tm = gmtime(&t);
    if (!tm || !strftime(buf, len, "%Y-%m-%d %H:%M:%S UTC", tm))
        snprintf(buf, len, "0x%08x", ts);
}

static void fmt_flags(uint32_t c, char *out)
{
    out[0] = (c & SCN_READ)  ? 'R' : '-';
    out[1] = (c & SCN_WRITE) ? 'W' : '-';
    out[2] = (c & SCN_EXEC)  ? 'X' : '-';
    out[3] = 0;
}

static const char *yn(int v) { return v ? "yes" : "no"; }

/* ---------------------------------------------------------------- text */

void report_text(const char *path, const pe_t *pe, const rich_t *rich, const info_t *in, int flags)
{
    char tbuf[64];
    uint16_t dc = pe->dll_chars;

    printf("%s  (%llu bytes)\n\n", path, (unsigned long long)pe->size);

    printf("  Machine       %s, %s\n", machine_name(pe->machine), pe->is64 ? "PE32+" : "PE32");
    printf("  Type          %s%s\n", (pe->characteristics & 0x2000) ? "DLL" : "EXE",
           in->is_dotnet ? " (.NET)" : "");
    printf("  Subsystem     %s\n", subsystem_name(pe->subsystem));

    fmt_time(pe->timestamp, tbuf, sizeof(tbuf));
    printf("  Timestamp     %s%s\n", tbuf, in->repro ? "  (reproducible build, not a real date)" : "");

    printf("  Image base    0x%llx\n", (unsigned long long)pe->image_base);
    int es = pe_section_of(pe, pe->entry_rva);
    printf("  Entry point   0x%x  (%s)\n", pe->entry_rva,
           !pe->entry_rva ? "none" : es >= 0 ? pe->sect[es].name : "outside sections");

    printf("  Mitigations   ASLR %s, DEP %s, CFG %s", yn(dc & 0x40), yn(dc & 0x100), yn(dc & 0x4000));
    if (pe->is64)
        printf(", HighEntropyVA %s", yn(dc & 0x20));
    if (dc & 0x400)
        printf(", NO_SEH");
    if ((dc & 0x40) && (pe->characteristics & 0x0001))
        printf("  (relocs stripped, ASLR can't actually move it)");
    printf("\n");

    if (in->pdb)
        printf("  PDB path      %s\n", in->pdb);

    printf("\nSections (%d", pe->nsect);
    if (pe->nsect != pe->nsections)
        printf(", header says %u", pe->nsections);
    printf(")\n");
    printf("  %-8s  %-10s  %-10s  %-10s  %-10s  %7s  %s\n",
           "Name", "VirtAddr", "VirtSize", "RawPtr", "RawSize", "Entropy", "Flags");
    for (int i = 0; i < pe->nsect; i++) {
        const section_t *s = &pe->sect[i];
        char fl[4];
        fmt_flags(s->chars, fl);
        printf("  %-8s  0x%08x  0x%08x  0x%08x  0x%08x  %7.2f  %s\n",
               s->name, s->va, s->vsize, s->raw_ptr, s->raw_size, s->entropy, fl);
    }

    if (rich->found) {
        printf("\nRich header  (key 0x%08x, checksum %s)\n", rich->key,
               rich->calc == rich->key ? "ok" : "MISMATCH");
        printf("  %-6s  %-18s  %6s  %-14s  %s\n", "ProdID", "Tool", "Build", "Toolchain", "Count");
        for (int i = 0; i < rich->n; i++) {
            const rich_entry_t *e = &rich->e[i];
            const char *nm = rich_prod_name(e->prodid);
            printf("  0x%04x  %-18s  %6u  %-14s  %u\n", e->prodid, nm ? nm : "",
                   e->build, rich_vs_version(e->prodid, e->build), e->count);
        }
    } else {
        printf("\nRich header   not present\n");
    }

    if (in->ndll) {
        printf("\nImports  (%d DLLs, %d functions)\n", in->ndll, in->nimp);
        for (int i = 0; i < in->nimp; ) {
            int j = i;
            while (j < in->nimp && in->imp[j].dll == in->imp[i].dll)
                j++;
            printf("  %-32s %d\n", in->imp[i].dll, j - i);
            if (flags & SHOW_IMPORTS) {
                for (int k = i; k < j; k++) {
                    if (in->imp[k].name)
                        printf("      %s\n", in->imp[k].name);
                    else
                        printf("      ordinal %u\n", in->imp[k].ordinal);
                }
            }
            i = j;
        }
    }

    if (in->exp_count || in->exp_nnames) {
        printf("\nExports  (%s, %u functions, %u by name)\n",
               in->exp_dll ? in->exp_dll : "?", in->exp_count, in->exp_nnames);
        int show = in->exp_names_got;
        if (!(flags & SHOW_EXPORTS) && show > EXPORTS_PREVIEW)
            show = EXPORTS_PREVIEW;
        for (int i = 0; i < show; i++)
            printf("  %s\n", in->exp_names[i]);
        if (show < in->exp_names_got)
            printf("  ... %d more, use -e to list all\n", in->exp_names_got - show);
    }

    if (in->ntls) {
        printf("\nTLS callbacks\n");
        for (int i = 0; i < in->ntls; i++)
            printf("  0x%llx\n", (unsigned long long)in->tls_cb[i]);
    }

    if (in->overlay_size) {
        printf("\nOverlay       offset 0x%llx, %llu bytes, entropy %.2f\n",
               (unsigned long long)in->overlay_off, (unsigned long long)in->overlay_size,
               in->overlay_entropy);
    }
    if (in->symtab_size)
        printf("Symbol table  offset 0x%llx, %llu bytes (COFF symbols, gcc/mingw build)\n",
               (unsigned long long)in->symtab_off, (unsigned long long)in->symtab_size);
    if (in->cert_size)
        printf("Signature     offset 0x%llx, %llu bytes (Authenticode)\n",
               (unsigned long long)in->cert_off, (unsigned long long)in->cert_size);

    if (in->nnotes) {
        printf("\nNotes\n");
        for (int i = 0; i < in->nnotes; i++)
            printf("  * %s\n", in->notes[i]);
    }
    printf("\n");
}

/* ---------------------------------------------------------------- json */

static void jstr(const char *s)
{
    putchar('"');
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\')
            printf("\\%c", c);
        else if (c < 0x20 || c >= 0x7f)
            printf("\\u%04x", c);   /* not real utf-8 handling, names are ascii anyway */
        else
            putchar(c);
    }
    putchar('"');
}

void report_json(const char *path, const pe_t *pe, const rich_t *rich, const info_t *in, int flags)
{
    (void)flags;

    printf("{\"file\":");
    jstr(path);
    printf(",\"size\":%llu", (unsigned long long)pe->size);
    printf(",\"machine\":\"0x%04x\",\"pe32plus\":%s", pe->machine, pe->is64 ? "true" : "false");
    printf(",\"dll\":%s,\"dotnet\":%s", (pe->characteristics & 0x2000) ? "true" : "false",
           in->is_dotnet ? "true" : "false");
    printf(",\"timestamp\":%u,\"repro\":%s", pe->timestamp, in->repro ? "true" : "false");
    printf(",\"image_base\":%llu,\"entry_rva\":%u", (unsigned long long)pe->image_base, pe->entry_rva);
    printf(",\"subsystem\":%u,\"dll_characteristics\":%u", pe->subsystem, pe->dll_chars);
    printf(",\"pdb\":");
    if (in->pdb) jstr(in->pdb); else printf("null");

    printf(",\"sections\":[");
    for (int i = 0; i < pe->nsect; i++) {
        const section_t *s = &pe->sect[i];
        printf("%s{\"name\":", i ? "," : "");
        jstr(s->name);
        printf(",\"va\":%u,\"vsize\":%u,\"raw_ptr\":%u,\"raw_size\":%u,\"chars\":%u,\"entropy\":%.4f}",
               s->va, s->vsize, s->raw_ptr, s->raw_size, s->chars, s->entropy);
    }
    printf("]");

    printf(",\"rich\":");
    if (rich->found) {
        printf("{\"key\":%u,\"checksum_ok\":%s,\"entries\":[", rich->key,
               rich->calc == rich->key ? "true" : "false");
        for (int i = 0; i < rich->n; i++)
            printf("%s{\"prodid\":%u,\"build\":%u,\"count\":%u}", i ? "," : "",
                   rich->e[i].prodid, rich->e[i].build, rich->e[i].count);
        printf("]}");
    } else {
        printf("null");
    }

    printf(",\"imports\":[");
    for (int i = 0; i < in->nimp; i++) {
        printf("%s{\"dll\":", i ? "," : "");
        jstr(in->imp[i].dll);
        if (in->imp[i].name) {
            printf(",\"name\":");
            jstr(in->imp[i].name);
        } else {
            printf(",\"ordinal\":%u", in->imp[i].ordinal);
        }
        printf("}");
    }
    printf("],\"import_dlls\":%d", in->ndll);

    printf(",\"exports\":{\"count\":%u,\"names\":[", in->exp_count);
    for (int i = 0; i < in->exp_names_got; i++) {
        if (i) putchar(',');
        jstr(in->exp_names[i]);
    }
    printf("]}");

    printf(",\"tls_callbacks\":[");
    for (int i = 0; i < in->ntls; i++)
        printf("%s%llu", i ? "," : "", (unsigned long long)in->tls_cb[i]);
    printf("]");

    printf(",\"overlay\":");
    if (in->overlay_size)
        printf("{\"offset\":%llu,\"size\":%llu,\"entropy\":%.4f}",
               (unsigned long long)in->overlay_off, (unsigned long long)in->overlay_size,
               in->overlay_entropy);
    else
        printf("null");

    printf(",\"notes\":[");
    for (int i = 0; i < in->nnotes; i++) {
        if (i) putchar(',');
        jstr(in->notes[i]);
    }
    printf("]}\n");
}

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "info.h"

#define MAX_IMPORTS     20000
#define MAX_EXP_NAMES   65536
#define MAX_NAME_LEN    4096    /* msvc mangled names can get really long */

static void note(info_t *in, const char *fmt, ...)
{
    if (in->nnotes >= MAX_NOTES)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(in->notes[in->nnotes++], sizeof(in->notes[0]), fmt, ap);
    va_end(ap);
}

static void parse_imports(const pe_t *pe, info_t *in)
{
    datadir_t d = pe->dirs[DIR_IMPORT];
    if (!d.rva)
        return;

    int64_t off = pe_rva2off(pe, d.rva);
    if (off < 0)
        return;

    int cap = 256;
    in->imp = malloc(cap * sizeof(import_t));
    if (!in->imp)
        return;

    unsigned tsz = pe->is64 ? 8 : 4;
    uint64_t ordflag = pe->is64 ? 0x8000000000000000ull : 0x80000000ull;

    for (int k = 0; k < 4096; k++, off += 20) {
        if (!pe_has(pe, off, 20))
            break;
        const uint8_t *p = pe->data + off;
        uint32_t oft  = rd32(p);
        uint32_t name = rd32(p + 12);
        uint32_t ft   = rd32(p + 16);
        if (!oft && !name && !ft)
            break;

        const char *dll = pe_str(pe, name, 256);
        if (!dll)
            dll = "?";
        in->ndll++;

        /* OriginalFirstThunk can be 0 (old borland stuff), then the IAT
         * itself still has the names on disk */
        int64_t t = pe_rva2off(pe, oft ? oft : ft);
        if (t < 0)
            continue;

        for (; pe_has(pe, t, tsz); t += tsz) {
            uint64_t v = pe->is64 ? rd64(pe->data + t) : rd32(pe->data + t);
            if (!v || in->nimp >= MAX_IMPORTS)
                break;

            if (in->nimp == cap) {
                cap *= 2;
                import_t *tmp = realloc(in->imp, cap * sizeof(import_t));
                if (!tmp)
                    return;
                in->imp = tmp;
            }

            import_t *im = &in->imp[in->nimp++];
            im->dll = dll;
            im->name = NULL;
            im->ordinal = 0;
            if (v & ordflag) {
                im->ordinal = (uint16_t)v;
            } else {
                /* IMAGE_IMPORT_BY_NAME: 2 byte hint then the name */
                im->name = pe_str(pe, (uint32_t)(v & 0x7FFFFFFF) + 2, MAX_NAME_LEN);
                if (!im->name)
                    im->name = "?";
            }
        }
    }
}

static void parse_exports(const pe_t *pe, info_t *in)
{
    datadir_t d = pe->dirs[DIR_EXPORT];
    if (!d.rva)
        return;

    int64_t off = pe_rva2off(pe, d.rva);
    if (off < 0 || !pe_has(pe, off, 40))
        return;

    const uint8_t *p = pe->data + off;
    in->exp_dll    = pe_str(pe, rd32(p + 12), 256);
    in->exp_count  = rd32(p + 20);
    in->exp_nnames = rd32(p + 24);
    uint32_t names = rd32(p + 32);

    uint32_t n = in->exp_nnames;
    if (n > MAX_EXP_NAMES)
        n = MAX_EXP_NAMES;
    if (!n)
        return;

    in->exp_names = calloc(n, sizeof(char *));
    if (!in->exp_names)
        return;

    for (uint32_t i = 0; i < n; i++) {
        int64_t o = pe_rva2off(pe, names + i * 4);
        if (o < 0 || !pe_has(pe, o, 4))
            break;
        const char *s = pe_str(pe, rd32(pe->data + o), MAX_NAME_LEN);
        in->exp_names[in->exp_names_got++] = s ? s : "?";
    }
}

static void parse_tls(const pe_t *pe, info_t *in)
{
    datadir_t d = pe->dirs[DIR_TLS];
    if (!d.rva)
        return;

    int64_t off = pe_rva2off(pe, d.rva);
    if (off < 0 || !pe_has(pe, off, pe->is64 ? 40 : 24))
        return;

    const uint8_t *p = pe->data + off;
    uint64_t cb = pe->is64 ? rd64(p + 24) : rd32(p + 12);
    if (!cb || cb < pe->image_base || cb - pe->image_base > 0xFFFFFFFFu)
        return;

    int64_t t = pe_rva2off(pe, (uint32_t)(cb - pe->image_base));
    if (t < 0)
        return;

    unsigned sz = pe->is64 ? 8 : 4;
    while (in->ntls < MAX_TLS_CB && pe_has(pe, t, sz)) {
        uint64_t va = pe->is64 ? rd64(pe->data + t) : rd32(pe->data + t);
        if (!va)
            break;
        in->tls_cb[in->ntls++] = va;
        t += sz;
    }
}

static void parse_debug(const pe_t *pe, info_t *in)
{
    datadir_t d = pe->dirs[DIR_DEBUG];
    if (!d.rva || d.size < 28)
        return;

    int64_t off = pe_rva2off(pe, d.rva);
    if (off < 0)
        return;

    uint32_t n = d.size / 28;
    if (n > 32)
        n = 32;

    for (uint32_t i = 0; i < n; i++, off += 28) {
        if (!pe_has(pe, off, 28))
            break;
        const uint8_t *e = pe->data + off;
        uint32_t type = rd32(e + 12);
        uint32_t len  = rd32(e + 16);
        uint32_t raw  = rd32(e + 24);

        if (type == 16) {
            in->repro = 1;
        } else if (type == 2 && len > 24 && pe_has(pe, raw, len)) {
            /* CodeView, "RSDS" + guid + age + path */
            const uint8_t *cv = pe->data + raw;
            if (rd32(cv) == 0x53445352 && memchr(cv + 24, 0, len - 24))
                in->pdb = (const char *)cv + 24;
        }
    }
}

static void find_overlay(const pe_t *pe, info_t *in)
{
    uint64_t end = pe->size_of_headers;

    for (int i = 0; i < pe->nsect; i++) {
        const section_t *s = &pe->sect[i];
        if (!s->raw_size)
            continue;
        uint64_t e = (uint64_t)pe_raw_ptr(pe, s) + s->raw_size;
        if (e > end)
            end = e;
    }

    /* the security dir is the only one that holds a file offset, not an rva */
    datadir_t c = pe->dirs[DIR_SECURITY];
    if (c.rva && c.size && pe_has(pe, c.rva, c.size)) {
        in->cert_off  = c.rva;
        in->cert_size = c.size;
    }

    /* mingw leaves the COFF symbol table + string table after the last
     * section, without this every gcc build looks like it has an overlay */
    if (pe->symtab_off && pe->nsyms) {
        uint64_t st = (uint64_t)pe->symtab_off + (uint64_t)pe->nsyms * 18;
        if (pe_has(pe, pe->symtab_off, st - pe->symtab_off)) {
            if (pe_has(pe, st, 4))
                st += rd32(pe->data + st);
            if (st <= pe->size) {
                in->symtab_off  = pe->symtab_off;
                in->symtab_size = st - pe->symtab_off;
            }
        }
    }

    if (end >= pe->size)
        return;

    in->overlay_off  = end;
    in->overlay_size = pe->size - end;
    in->overlay_entropy = entropy(pe->data + end, (size_t)in->overlay_size);
}

/* name == want, or want + 'A' / 'W' */
static int api_is(const char *name, const char *want)
{
    size_t n = strlen(want);
    if (strncmp(name, want, n) != 0)
        return 0;
    return name[n] == 0 || ((name[n] == 'A' || name[n] == 'W') && name[n + 1] == 0);
}

static const char *api_injection[] = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread",
    "QueueUserAPC", "SetThreadContext", "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection", NULL
};

/* no IsDebuggerPresent here, the MSVC CRT startup code imports it so it's
 * in almost every exe and the note would fire on notepad */
static const char *api_antidebug[] = {
    "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "NtSetInformationThread", NULL
};

static const char *api_input[] = {
    "SetWindowsHookEx", "GetAsyncKeyState", "RegisterRawInputDevices", NULL
};

static const char *api_dynamic[] = {
    "LoadLibrary", "LoadLibraryEx", "GetProcAddress", "LdrLoadDll",
    "LdrGetProcedureAddress", NULL
};

static int match_group(const info_t *in, const char **group, char *out, size_t outlen)
{
    int hits = 0;
    out[0] = 0;

    for (int i = 0; group[i]; i++) {
        for (int j = 0; j < in->nimp; j++) {
            if (!in->imp[j].name || !api_is(in->imp[j].name, group[i]))
                continue;
            size_t l = strlen(out);
            snprintf(out + l, outlen - l, "%s%s", hits ? ", " : "", in->imp[j].name);
            hits++;
            break;
        }
    }
    return hits;
}

static const char *packer_names[] = {
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".MPRESS1", ".MPRESS2",
    ".petite", ".themida", ".winlice", ".vmp0", ".vmp1", ".vmp2",
    ".enigma1", ".enigma2", ".nsp0", ".nsp1", "PEC2", "pebundle", NULL
};

static void make_notes(const pe_t *pe, const rich_t *rich, info_t *in)
{
    char buf[160];

    if (in->is_dotnet)
        note(in, ".NET assembly, the real code is IL. dnSpy / ILSpy will do a better job than a disassembler");

    if (rich->found && rich->calc != rich->key)
        note(in, "Rich header checksum mismatch (stored %08x, calculated %08x), the DOS stub or the entries were changed after linking",
             rich->key, rich->calc);

    if (pe->entry_rva) {
        int es = pe_section_of(pe, pe->entry_rva);
        if (es < 0)
            note(in, "entry point 0x%x is not inside any section", pe->entry_rva);
        else if (!(pe->sect[es].chars & SCN_EXEC))
            note(in, "entry point is in '%s' which is not marked executable", pe->sect[es].name);
        else if (es == pe->nsect - 1 && pe->nsect > 1)
            note(in, "entry point is in the last section ('%s'), typical for packed files", pe->sect[es].name);
    }

    for (int i = 0; i < pe->nsect; i++) {
        const section_t *s = &pe->sect[i];

        if ((s->chars & SCN_EXEC) && (s->chars & SCN_WRITE))
            note(in, "section '%s' is writable and executable", s->name);

        if (s->raw_size > 1024 && s->entropy >= 7.2)
            note(in, "section '%s' has entropy %.2f, likely compressed or encrypted", s->name, s->entropy);

        if ((s->chars & SCN_EXEC) && s->raw_size == 0 && s->vsize > 0)
            note(in, "section '%s' is executable but empty on disk, gets filled at runtime", s->name);

        for (int k = 0; packer_names[k]; k++) {
            if (strcmp(s->name, packer_names[k]) == 0) {
                note(in, "section name '%s' belongs to a known packer/protector", s->name);
                break;
            }
        }
    }

    if (in->ntls)
        note(in, "%d TLS callback(s), they run before the entry point. Set x64dbg to break on TLS callbacks", in->ntls);

    if (in->overlay_size) {
        /* signature and symbol table are expected to be there, only
         * complain about what's left */
        uint64_t extra = in->overlay_size;
        if (in->cert_size && in->cert_off >= in->overlay_off)
            extra -= in->cert_size;
        if (in->symtab_size && in->symtab_off >= in->overlay_off && in->symtab_size <= extra)
            extra -= in->symtab_size;
        if (extra)
            note(in, "%llu bytes of unexplained overlay data after 0x%llx (whole overlay entropy %.2f)",
                 (unsigned long long)extra, (unsigned long long)in->overlay_off,
                 in->overlay_entropy);
    }

    if (in->nimp && in->nimp < 15 && match_group(in, api_dynamic, buf, sizeof(buf)))
        note(in, "only %d imports and %s, rest of the APIs are probably resolved at runtime", in->nimp, buf);

    if (match_group(in, api_injection, buf, sizeof(buf)) >= 2)
        note(in, "imports used for process injection: %s", buf);
    if (match_group(in, api_antidebug, buf, sizeof(buf)))
        note(in, "anti-debug related imports: %s", buf);
    if (match_group(in, api_input, buf, sizeof(buf)))
        note(in, "keyboard/input capture imports: %s", buf);

    if (!in->repro) {
        time_t now = time(NULL);
        if (pe->timestamp == 0)
            note(in, "compile timestamp is zeroed");
        else if ((time_t)pe->timestamp > now + 86400)
            note(in, "compile timestamp is in the future, probably faked");
    }
}

void info_collect(const pe_t *pe, const rich_t *rich, info_t *in)
{
    memset(in, 0, sizeof(*in));

    in->is_dotnet = pe->dirs[DIR_CLR].rva != 0;

    parse_imports(pe, in);
    parse_exports(pe, in);
    parse_tls(pe, in);
    parse_debug(pe, in);
    find_overlay(pe, in);
    make_notes(pe, rich, in);
}

void info_free(info_t *in)
{
    free(in->imp);
    free(in->exp_names);
    in->imp = NULL;
    in->exp_names = NULL;
}

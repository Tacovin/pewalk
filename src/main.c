#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pe.h"
#include "rich.h"
#include "info.h"
#include "report.h"

#define MAX_FILE (512u * 1024 * 1024)

static void usage(void)
{
    fprintf(stderr,
        "usage: pewalk [-i] [-e] [-j] file...\n"
        "  -i   list every imported function\n"
        "  -e   list every exported name\n"
        "  -j   json output (one object per line)\n");
}

static uint8_t *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;

    uint8_t *buf = NULL;
    long sz;
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 || (unsigned long)sz > MAX_FILE)
        goto out;
    rewind(f);

    buf = malloc(sz ? (size_t)sz : 1);
    if (buf && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        buf = NULL;
    }
    *len = (size_t)sz;
out:
    fclose(f);
    return buf;
}

int main(int argc, char **argv)
{
    int flags = 0, json = 0, nfiles = 0, failed = 0;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-' || !argv[i][1]) {
            nfiles++;
            continue;
        }
        for (const char *p = argv[i] + 1; *p; p++) {
            switch (*p) {
            case 'i': flags |= SHOW_IMPORTS; break;
            case 'e': flags |= SHOW_EXPORTS; break;
            case 'j': json = 1; break;
            case 'h': usage(); return 0;
            default:
                fprintf(stderr, "unknown option -%c\n", *p);
                usage();
                return 2;
            }
        }
    }
    if (!nfiles) {
        usage();
        return 2;
    }

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1])
            continue;

        const char *path = argv[i];
        size_t len = 0;
        uint8_t *data = read_file(path, &len);
        if (!data) {
            fprintf(stderr, "%s: can't read file\n", path);
            failed++;
            continue;
        }

        pe_t pe;
        char err[128];
        if (pe_load(&pe, data, len, err, sizeof(err)) != 0) {
            fprintf(stderr, "%s: %s\n", path, err);
            free(data);
            failed++;
            continue;
        }

        rich_t rich;
        info_t in;
        rich_parse(&pe, &rich);
        info_collect(&pe, &rich, &in);

        if (json)
            report_json(path, &pe, &rich, &in, flags);
        else
            report_text(path, &pe, &rich, &in, flags);

        info_free(&in);
        free(data);
    }

    return failed ? 1 : 0;
}

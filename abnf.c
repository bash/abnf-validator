/* Parse ABNF to locate dangling references and undefined symbols
 *  does limited syntax checking
 *
 *  This is a quick&dirty hack donated to public domain by Chris Newman
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ERROR 0
#define COMMENT 1
#define RULEDEF 2
#define AMENDRULE 3
#define HEXMODE 4
#define BINMODE 5
#define DECMODE 6
#define ALTERNATE 7
#define REPEAT 8
#define BEGINGROUP 9
#define ENDGROUP 10
#define BEGINOPTION 11
#define ENDOPTION 12
#define RANGE 13
#define LITLIST 14
#define NUMBER 15
#define HEXNUMBER 16
#define QUOTED 17
#define PROSE 18
#define RULENAME 19
#define NEWLINE 20

static const char *token_name[] = {
    "error", "comment", "ruledef", "amendrule", "hexmode",
    "binmode", "decmode", "alternate", "repeat", "begingroup",
    "endgroup", "beginoption", "endoption", "range", "litlist",
    "number", "hexnumber", "quoted", "prose", "rulename",
    "newline"};

/* simple rulename datastructure
 */
struct rulename {
    struct rulename *next;
    int defined, referenced;
    int len;
    char data[1];
};

#define HTSIZE 1023
static struct rulename *htable[HTSIZE];
static unsigned char hex_table[256];
const static unsigned char hexchars[] = "0123456789ABCDEF";

static const char *baserules[] = {"ALPHA", "BIT", "CHAR", "CR", "CRLF",
                                  "CTL", "DIGIT", "DQUOTE", "HEXDIG", "HTAB",
                                  "LF", "LWSP", "OCTET", "SP", "VCHAR",
                                  "WSP", NULL};

const unsigned char cvt_to_lowercase[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0x3e, 0x3f, 0x40, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
    0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
    0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
    0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
    0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3,
    0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff};

#define TOLOWER(c) (cvt_to_lowercase[(unsigned char)(c)])

/* returns pointer to end of token, NULL if no tokens left in line
 */
char *gettoken(char *ptr, int *tokentype, int hexmode) {
    *tokentype = ERROR;

    switch (*ptr++) {
    case '\0':
        return (NULL);

    case '\r':
        if (*ptr == '\n') ++ptr;
    case '\n':
        *tokentype = NEWLINE;
        break;

    case ';':
        *tokentype = COMMENT;
        while (*ptr != '\0' && *ptr != '\n' && *ptr != '\r') ++ptr;
        break;

    case '/':
        *tokentype = ALTERNATE;
        break;

    case '*':
        *tokentype = REPEAT;
        break;

    case '(':
        *tokentype = BEGINGROUP;
        break;

    case ')':
        *tokentype = ENDGROUP;
        break;

    case '[':
        *tokentype = BEGINOPTION;
        break;

    case ']':
        *tokentype = ENDOPTION;
        break;

    case '-':
        *tokentype = RANGE;
        break;

    case '.':
        *tokentype = LITLIST;
        break;

    case '=':
        *tokentype = RULEDEF;
        if (*ptr == '/') {
            *tokentype = AMENDRULE;
            ++ptr;
        }
        break;

    case '%':
        switch (*ptr++) {
        case 'x':
        case 'X':
            *tokentype = HEXMODE;
            break;
        case 'b':
        case 'B':
            *tokentype = BINMODE;
            break;
        case 'd':
        case 'D':
            *tokentype = DECMODE;
            break;
        default:
            return ("Invalid literal");
        }
        break;

    case '"':
        while (*ptr && *ptr != '"') ++ptr;
        if (*ptr != '"') {
            return ("Unbalanced double quotes");
        }
        ++ptr;
        *tokentype = QUOTED;
        break;

    case '<':
        while (*ptr && *ptr != '>') ++ptr;
        if (*ptr != '>') {
            return ("Unbalanced angle brakets");
        }
        ++ptr;
        *tokentype = PROSE;
        break;

    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        if (hexmode) goto GETHEX;
        while (isdigit(*ptr)) ++ptr;
        *tokentype = NUMBER;
        break;

    default:
        /* deal with hex digits */
        if (hexmode && isxdigit(ptr[-1])) {
        GETHEX:
            while (isxdigit(*ptr)) ++ptr;
            *tokentype = HEXNUMBER;
            break;
        }

        if (!isalpha(ptr[-1])) {
            return ("Invalid character");
        }

        /* deal with rule names */
        while (isalnum(*ptr) || *ptr == '-') ++ptr;
        *tokentype = RULENAME;
        break;
    }

    return (ptr);
}

/* find a rule in a hash table
 */
struct rulename *hashfind(const char *ptr, int len) {
    int i, hash;
    struct rulename **pptr;

    /* lookup in hash table */
    hash = len;
    for (i = 0; i < len; ++i) {
        hash = (hash * 13 + TOLOWER(ptr[i])) % HTSIZE;
    }

    pptr = &htable[hash];
    while (*pptr && ((*pptr)->len != len || strncasecmp(ptr, (*pptr)->data, len) != 0)) {
        pptr = &(*pptr)->next;
    }

    /* create new entry, if needed */
    if (!*pptr) {
        *pptr = calloc(sizeof(struct rulename) + len, 1);

        if (!*pptr) {
            fprintf(stderr, "Out of memory\n");
            exit(1);
        }

        (*pptr)->len = len;
        memcpy((*pptr)->data, ptr, len);
    }

    return (*pptr);
}

int main(int argc, char **argv) {
    int verbose = 0;
    const unsigned char *uscan;
    char *buf, *name, *src, *dst, *linestart;
    char *ptr, *nptr;
    const char **ruleptr;
    int hexmode, tokentype, line;
    int plevel = 0, blevel = 0;
    int bused, bsize, amount;
    struct rulename *lastrule;
    int has_err = 0;
    struct rulename *first_rule = NULL;

    /* initialize hex table */
    memset(hex_table, 16, sizeof(hex_table));
    for (uscan = hexchars; *uscan; ++uscan) {
        hex_table[(unsigned)*uscan] = uscan - hexchars;
    }

    /* initialize default rules */
    for (ruleptr = baserules; *ruleptr != NULL; ++ruleptr) {
        lastrule = hashfind(*ruleptr, strlen(*ruleptr));
        lastrule->defined = lastrule->referenced = 1;
    }
    lastrule = NULL;

    /* get program name */
    name = strrchr(*argv, '/');
    name = name == NULL ? *argv : name + 1;

    /* parse args */
    while (*++argv != NULL && **argv == '-') switch ((*argv)[1]) {
        case 'v':
            verbose = 1;
            break;

        case 'h':
            printf("%s [-h] [-v]\n", name);
            printf("  -v  enable verbose output\n");
            printf("  -h  display this help\n");
            exit(0);

        default:
            fprintf(stderr, "Invalid arguments, type `%s -h' for usage\n", name);
            exit(1);
        }

    /* read the data into memory */
    bsize = 4096;
    buf = malloc(bsize);

    if (buf != NULL) {
        for (bused = 0;
             (amount = fread(buf + bused, 1, bsize - bused, stdin)) != 0;
             bused += amount) {

            if (bused + amount == bsize) {
                if (bsize > 10 * 1024 * 1024) {
                    fprintf(stderr, "Size limit exceeded\n");
                    exit(1);
                }

                buf = realloc(buf, bsize *= 2);
                if (buf == NULL) break;
            }
        }
    }

    if (buf == NULL) {
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }

    if (!feof(stdin)) {
        perror("input");
        exit(1);
    }

    buf[bused] = '\0';

    /* process lines */
    ptr = linestart = buf;
    hexmode = 0;
    line = 1;

    /* get tokens */
    for (;;) {
        /* skip whitespace */
        while (*ptr == ' ' || *ptr == '\t') {
            ++ptr;
            hexmode = 0;
        }

        /* get token, done if at end of line */
        if ((nptr = gettoken(ptr, &tokentype, hexmode)) == NULL) break;

        /* handle errors */
        if (!tokentype) {
            printf("Error (line %d, col %d): %s\n", line, (int)(ptr - linestart), nptr);
            exit(1);
        }

        /* reset hexmode */
        if (hexmode && tokentype != HEXNUMBER && tokentype != LITLIST && tokentype != RANGE) {
            hexmode = 0;
        }

        /* handle last rulename */
        if (lastrule != NULL) {
            if (tokentype == RULEDEF) {
                lastrule->defined = 1;
            } else if (tokentype == AMENDRULE) {
                lastrule->defined = lastrule->referenced = 1;
            } else {
                lastrule->referenced = 1;
            }
            lastrule = NULL;
        }

        if (verbose && tokentype != NEWLINE) {
            printf("line %d, col %d, %s", line, (int)(ptr - linestart), token_name[tokentype]);

            if (nptr != NULL) {
                printf(": %.*s", (int)(nptr - ptr), ptr);
            }

            putchar('\n');
        }

        switch (tokentype) {
        case NEWLINE:
            hexmode = 0;
            ++line;
            ptr = linestart = nptr;
            continue;

        case RULENAME:
            lastrule = hashfind(ptr, nptr - ptr);
            if (first_rule == NULL) first_rule = lastrule;
            break;

        case HEXMODE:
            hexmode = 1;
            break;

        case RULEDEF:
        case AMENDRULE:
            if (plevel || blevel) {
            UNBALANCED:
                printf("Error (line %d): Unbalanced %s\n", line, plevel ? "parenthesis" : "square brackets");
                exit(1);
            }
            break;

        case BEGINGROUP:
            ++plevel;
            break;

        case ENDGROUP:
            if (--plevel < 0) goto UNBALANCED;
            break;

        case BEGINOPTION:
            ++blevel;
            break;

        case ENDOPTION:
            if (--blevel < 0) goto UNBALANCED;
            break;
        }

        /* advance */
        ptr = nptr;
    }

    /* final warnings */
    if (plevel) {
        printf("Error at end of text: Unbalanced parenthesis\n");
        has_err = 1;
    }

    if (blevel) {
        printf("Error at end of text: Unbalanced square brackets\n");
        has_err = 1;
    }

    /* the first rule always counts as referenced */
    if (first_rule) first_rule->referenced = 1;

    /* list undefined and unreferenced rules */
    for (line = 0; line < HTSIZE; ++line) {
        lastrule = htable[line];
        while (lastrule) {
            if (!lastrule->defined) {
                printf("undefined rule: %s\n", lastrule->data);
                has_err = 1;
            }

            if (!lastrule->referenced) {
                printf("unreferenced rule: %s\n", lastrule->data);
                has_err = 1;
            }

            lastrule = lastrule->next;
        }
    }

    if (has_err == 1) {
        exit(1);
    }

    printf("ABNF validation (version 1.0) completed\n");

    exit(0);
}

/* Copyright © 2012 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of vscf.
 *
 * vscf is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * vscf is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with vscf.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>

#include "gdnsd/dmn.h"
#include "gdnsd/vscf.h"

/*
 * The initial size of the read()/fread() buffer.  Note that
 *  we can only parse a key or simple value by having
 *  it fit completely inside one buffer.  Therefore to
 *  avoid arbitrary restrictions, the buffer is
 *  resized by doubling if we run into a key or string
 *  value that exceeds the buffer size.
 */
#define INIT_BUF_SIZE 8192

#define set_err(_epp, _fmt, ...) do { \
    dmn_assert(_epp); \
    if(!*_epp) { \
        *_epp = malloc(256); \
        snprintf(*_epp, 256, _fmt, __VA_ARGS__); \
    } \
} while(0)

#define parse_error(_fmt, ...) \
    set_err(scnr->err, "Parse error at %s line %u: " _fmt, scnr->fn, scnr->lcount, __VA_ARGS__)

#define parse_error_noargs(_fmt) \
    set_err(scnr->err, "Parse error at %s line %u: " _fmt, scnr->fn, scnr->lcount)

/*************************************/
/*** Private data type definitions ***/
/*************************************/

typedef struct {
    vscf_data_t* parent;
    vscf_type_t  type;
    char*        rval;
    char*        val;
    unsigned     rlen;
    unsigned     len;
} vscf_simple_t;

typedef struct {
    vscf_data_t*  parent;
    vscf_type_t   type;
    unsigned      len;
    vscf_data_t** vals;
} vscf_array_t;

typedef struct _vscf_hentry_t vscf_hentry_t;
struct _vscf_hentry_t {
    unsigned       klen;
    char*          key;
    unsigned       index;
    bool           marked;
    vscf_data_t*   val;
    vscf_hentry_t* next;
};

typedef struct {
    vscf_data_t*    parent;
    vscf_type_t     type;
    unsigned        child_count;
    vscf_hentry_t** children;
    vscf_hentry_t** ordered;
} vscf_hash_t;

union _vscf_data_t {
    struct {
        vscf_data_t*    parent;
        vscf_type_t     type;
    };
    vscf_simple_t   simple;
    vscf_array_t    array;
    vscf_hash_t     hash;
};

typedef struct {
    int           cont_stack_top;
    int           cs;
    int           top;
    unsigned      cont_stack_alloc;
    unsigned      cs_stack_alloc;
    unsigned      lcount;
    unsigned      cur_klen;
    vscf_data_t*  cont;
    vscf_data_t** cont_stack;
    int*          cs_stack;
    const char*   p;
    const char*   pe;
    const char*   eof;
    char*         cur_key;
    const char*   fn;
    const char*   tstart;
    char**        err;
} vscf_scnr_t;

/*************************/
/*** Private functions ***/
/*************************/

static unsigned count2mask(unsigned x) {
    if(!x) return 1;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    return x;
}

F_NONNULL F_PURE
static unsigned djb_hash(const char* k, unsigned klen, const unsigned hash_mask) {
   dmn_assert(k);

   unsigned hash = 5381;

   while(klen--)
       hash = ((hash << 5) + hash) ^ *k++;

   return hash & hash_mask;
}

static vscf_hash_t* hash_new(void) {
    vscf_hash_t* h = calloc(1, sizeof(vscf_hash_t));
    h->type = VSCF_HASH_T;
    return h;
}

F_NONNULL
static void hash_grow(vscf_hash_t* h) {
    dmn_assert(h);

    const unsigned old_hash_mask = count2mask(h->child_count);
    const unsigned new_hash_mask = (old_hash_mask << 1) | 1;
    vscf_hentry_t** new_table = calloc(new_hash_mask + 1, sizeof(vscf_hentry_t*));
    for(unsigned i = 0; i <= old_hash_mask; i++) {
        vscf_hentry_t* entry = h->children[i];
        while(entry) {
            const unsigned child_hash = djb_hash(entry->key, entry->klen, new_hash_mask);
            vscf_hentry_t* slot = new_table[child_hash];
            vscf_hentry_t* next_entry = entry->next;
            entry->next = NULL;

            if(slot) {
                while(slot->next)
                    slot = slot->next;
                slot->next = entry;
            }
            else {
                new_table[child_hash] = entry;
            }

            entry = next_entry;
        }
    }

    free(h->children);

    h->children = new_table;
    h->ordered = realloc(h->ordered, (new_hash_mask + 1) * sizeof(vscf_hentry_t*));
}

F_NONNULL
static bool hash_add_val(const char* key, const unsigned klen, vscf_hash_t* h, vscf_data_t* v) {
    dmn_assert(key); dmn_assert(h); dmn_assert(v);
    v->parent = (vscf_data_t*)h;

    if(!h->children) {
        h->children = calloc(2, sizeof(vscf_hentry_t*));
        h->ordered = malloc(2 * sizeof(vscf_hentry_t*));
    }

    const unsigned child_mask = count2mask(h->child_count);
    const unsigned child_hash = djb_hash(key, klen, child_mask);

    vscf_hentry_t** store_at = &(h->children[child_hash]);
    while(*store_at) {
        if((klen == (*store_at)->klen)
            && !memcmp(key, (*store_at)->key, klen)) {
            return false;
        }
        store_at = &((*store_at)->next);
    }

    vscf_hentry_t* new_hentry = *store_at = calloc(1, sizeof(vscf_hentry_t));
    new_hentry->klen = klen;
    new_hentry->key = malloc(klen + 1);
    memcpy(new_hentry->key, key, klen + 1);
    new_hentry->index = h->child_count;
    new_hentry->val = v;

    if(h->child_count == child_mask)
        hash_grow(h);

    h->ordered[h->child_count++] = new_hentry;

    return true;
}

F_NONNULL
static bool scnr_hash_add_val(vscf_scnr_t* scnr, vscf_hash_t* h, vscf_data_t* v) {
    dmn_assert(scnr);
    dmn_assert(h);
    dmn_assert(v);
    dmn_assert(scnr->cur_key);

    bool rv = hash_add_val(scnr->cur_key, scnr->cur_klen, h, v);
    if(rv) {
        free(scnr->cur_key);
        scnr->cur_key = NULL;
        scnr->cur_klen = 0;
    }
    else {
        parse_error("Duplicate hash key '%s'\n", scnr->cur_key);
    }
    return rv;
}

static vscf_array_t* array_new(void) {
    vscf_array_t* a = calloc(1, sizeof(vscf_array_t));
    a->type   = VSCF_ARRAY_T;
    return a;
}

F_NONNULL
static void array_add_val(vscf_array_t* a, vscf_data_t* v) {
    dmn_assert(a); dmn_assert(v);
    v->parent = (vscf_data_t*)a;
    unsigned idx = a->len++;
    a->vals = realloc(a->vals, a->len * sizeof(vscf_data_t*));
    a->vals[idx] = v;
}

F_NONNULL
static vscf_simple_t* simple_new(const char* rval, const unsigned rlen) {
    dmn_assert(rval);
    vscf_simple_t* s = calloc(1, sizeof(vscf_simple_t));
    char* storage = malloc(rlen);
    memcpy(storage, rval, rlen);
    s->type   = VSCF_SIMPLE_T;
    s->rlen   = rlen;
    s->rval   = storage;
    return s;
}

F_NONNULL
static vscf_data_t* val_clone(const vscf_data_t* d, const bool ignore_marked);

F_NONNULL
static vscf_hash_t* hash_clone(const vscf_hash_t* h, const bool ignore_marked) {
    dmn_assert(h);
    vscf_hash_t* nh = hash_new();
    for(unsigned i = 0; i < h->child_count; i++) {
        const vscf_hentry_t* hentry = h->ordered[i];
        if(!ignore_marked || !hentry->marked) {
            vscf_data_t* new_child = val_clone(hentry->val, ignore_marked);
            hash_add_val(hentry->key, hentry->klen, nh, new_child);
        }
    }
    return nh;
}

F_NONNULL
static vscf_array_t* array_clone(const vscf_array_t* a, const bool ignore_marked) {
    dmn_assert(a);
    vscf_array_t* na = array_new();
    for(unsigned i = 0; i < a->len; i++) {
        array_add_val(na, val_clone(a->vals[i], ignore_marked));
    }
    return na;
}

F_NONNULL
static vscf_simple_t* simple_clone(const vscf_simple_t* s) {
    dmn_assert(s);
    return simple_new(s->rval, s->rlen);
}

static vscf_data_t* val_clone(const vscf_data_t* d, const bool ignore_marked) {
    dmn_assert(d);
    vscf_data_t* rv = NULL;
    switch(d->type) {
        case VSCF_HASH_T:   rv = (vscf_data_t*)hash_clone(&d->hash, ignore_marked); break;
        case VSCF_ARRAY_T:  rv = (vscf_data_t*)array_clone(&d->array, ignore_marked); break;
        case VSCF_SIMPLE_T: rv = (vscf_data_t*)simple_clone(&d->simple); break;
    }
    return rv;
}

/*
 * Takes a pointer to a constant simple key/value with len
 * Allocates necessary storage and stores the unescaped version
 *  in *out, returning the new length, which will be <= the original length
 * Note also that the returned storage is one byte longer than indicated and
 *  terminated with a NUL in that extra byte.  It serves two purposes:
 * (1) Ensuring that the data pointer of a zero-length string/key is not NULL
 *   (it points to one byte of NUL)
 * (2) Allowing the treatment of vscf strings as NUL-terminated in cases where
 *   embedded NULs are irrelevant (such as our own numeric conversions, and
 *   probably many user-code cases too).
 */
F_NONNULL
static unsigned unescape_string(char** outp, const char* in, unsigned len) {
    dmn_assert(outp);
    dmn_assert(in);
    char* out = malloc(len + 1);
    unsigned newlen = len;
    if(len)
        newlen = dns_unescape((uint8_t*)out, (const uint8_t*)in, len);
    out = realloc(out, newlen + 1); // downsize
    out[newlen] = 0;
    *outp = out;
    return newlen;
}

F_NONNULL
static void set_key(vscf_scnr_t* scnr, const char* end) {
    dmn_assert(scnr);
    dmn_assert(scnr->tstart);
    dmn_assert(end);
    scnr->cur_klen = unescape_string(&scnr->cur_key, scnr->tstart, end - scnr->tstart);
    scnr->tstart = NULL;
}

F_NONNULL
static bool add_to_cur_container(vscf_scnr_t* scnr, vscf_data_t* v) {
    dmn_assert(scnr);
    dmn_assert(scnr->cont);
    dmn_assert(v);

    if(scnr->cont->type == VSCF_HASH_T) {
        vscf_hash_t* h = &scnr->cont->hash;
        return scnr_hash_add_val(scnr, h, v);
    }
    else {
        dmn_assert(scnr->cont->type == VSCF_ARRAY_T);
        vscf_array_t* a = &scnr->cont->array;
        array_add_val(a, v);
        return true;
    }
}

F_NONNULL
static bool scnr_set_simple(vscf_scnr_t* scnr, const char* end) {
    dmn_assert(scnr);
    dmn_assert(scnr->tstart);
    dmn_assert(end);
    unsigned rlen = end - scnr->tstart;
    vscf_simple_t* s = simple_new(scnr->tstart, rlen);
    scnr->tstart = NULL;
    return add_to_cur_container(scnr, (vscf_data_t*)s);
}

F_NONNULL
static void vscf_simple_ensure_val(const vscf_simple_t* cs) {
    dmn_assert(cs);
    vscf_simple_t* s = (vscf_simple_t*)cs; // kill const...
    if(!s->val)
        s->len = unescape_string(&s->val, s->rval, s->rlen);
}

F_NONNULL
static bool cont_stack_push(vscf_scnr_t* scnr, vscf_data_t* c) {
    dmn_assert(scnr); dmn_assert(c);
    dmn_assert(scnr->cont);

    if(++scnr->cont_stack_top == (signed)scnr->cont_stack_alloc)
        scnr->cont_stack = realloc(scnr->cont_stack, ++scnr->cont_stack_alloc * sizeof(vscf_data_t*));

    if(!add_to_cur_container(scnr, c))
        return false;

    scnr->cont_stack[scnr->cont_stack_top] = scnr->cont;
    scnr->cont = c;

    return true;
}

F_NONNULL
static void cont_stack_pop(vscf_scnr_t* scnr) {
    dmn_assert(scnr);
    dmn_assert(scnr->cont_stack_top > -1);
    scnr->cont = scnr->cont_stack[scnr->cont_stack_top--];
}

/*** Destructors ***/

F_NONNULL
static void simple_destroy(vscf_simple_t* s) {
    dmn_assert(s);
    free(s->rval);
    if(s->val) free(s->val);
    free(s);
}

F_NONNULL
static void array_destroy(vscf_array_t* a);
F_NONNULL
static void hash_destroy(vscf_hash_t* h);

F_NONNULL
static void val_destroy(vscf_data_t* d) {
    dmn_assert(d);
    switch(d->type) {
        case VSCF_HASH_T:   hash_destroy(&d->hash); break;
        case VSCF_ARRAY_T:  array_destroy(&d->array); break;
        case VSCF_SIMPLE_T: simple_destroy(&d->simple); break;
    }
}

static void array_destroy(vscf_array_t* a) {
    dmn_assert(a);
    for(unsigned i = 0; i < a->len; i++)
        val_destroy(a->vals[i]);
    free(a->vals);
    free(a);
}

static void hash_destroy(vscf_hash_t* h) {
    dmn_assert(h);
    for(unsigned i = 0; i < h->child_count; i++) {
        vscf_hentry_t* hentry = h->ordered[i];
        val_destroy(hentry->val);
        free(hentry->key);
        free(hentry);
    }
    free(h->children);
    free(h->ordered);
    free(h);
}

/************************************/
/*** The Ragel machine definition ***/
/************************************/

%%{
    machine vscf;

    ##########
    ### Actions and rules related to simple text parsing/types
    ##########

    action token_start { scnr->tstart = fpc; }

    action set_key { set_key(scnr, fpc); }

    action set_key_q {
        scnr->tstart++;
        set_key(scnr, fpc - 1);
    }

    action set_simple {
        if(!scnr_set_simple(scnr, fpc))
            fbreak;
    }

    action set_simple_q {
        scnr->tstart++;
        if(!scnr_set_simple(scnr, fpc - 1))
            fbreak;
    }

    # newlines, count them
    nl      = '\r'? '\n' %{ scnr->lcount++; };

    # Single line comment, e.g. ; dns comment or # sh comment
    slc     = ([;#] [^\r\n]* nl);

    # Whitespace, which includes newlines and comments, and is
    #  always optional wherever it occurs.
    ws      = ([ \t] | nl | slc)*;

    # Escape sequences in general for any character-string
    escape_int = 25[0-5] | ( 2[0-4] | [01][0-9] ) [0-9] ;
    escapes = ('\\' [^0-9\r\n]) | ('\\' escape_int) | ('\\' nl);

    # The base set of literal characters allowed in unquoted
    #  charater-srings
    chr     = [^}{;# \t\r\n,"=\\] - (']'|'[');

    # quoted/unquoted character-strings.  The "$1 %0" construct
    #  here prevents some ambiguities on exiting an unquoted string,
    #  forcing the parser to prefer staying in the string over other
    #  alternatives.
    unquoted = (chr | escapes)+ $1 %0;
    quoted   = ('"' ([^"\r\n\\]|escapes|nl)* '"');

    # Keys and Values are both character-strings, and either can
    #  optionally be in quoted form.  However, they trigger different code.
    key      = (quoted %set_key_q    | unquoted %set_key   ) >token_start;
    simple   = (quoted %set_simple_q | unquoted %set_simple) >token_start;

    ##########
    ### Actions and rules related to the global data structure
    ##########

    action open_array {
        if(!cont_stack_push(scnr, (vscf_data_t*)array_new()))
            fbreak;
        fcall array;
    }

    action open_hash {
        if(!cont_stack_push(scnr, (vscf_data_t*)hash_new()))
            fbreak;
        fcall hash;
    }

    action close_array {
        cont_stack_pop(scnr);
        fret;
    }

    action close_hash {
        cont_stack_pop(scnr);
        fret;
    }

    # Any type of value
    value = (
          simple
        | '[' $open_array
        | '{' $open_hash
    );

    # A key => value assignment within a hash.  The "$1 %0"
    #  construct prevents the optional '>' from being considered
    #  a simple RHS string value.
    assign  = key ws ('=' '>'?) $1 %0 ws value;

    # Lists of values and assignments with optional trailing commas.
    # These defs include their surrounding whitespace.
    values  = ws (value  ws (',' ws)?)*;
    assigns = ws (assign ws (',' ws)?)*;

    # Array and Hash defs (after they are opened above in "value")
    array := values ']' $close_array;
    hash  := assigns '}' $close_hash;

    # The top level of the file is an implicit hash with no bracing
    main  := assigns;

    write data;
}%%

static const vscf_data_t* vscf_scan_fd_or_stream(const int fd, FILE* const stream, const char* desc, char** err) {
    dmn_assert(err); dmn_assert(*err == NULL);

    vscf_scnr_t* scnr = calloc(1, sizeof(vscf_scnr_t));
    unsigned buf_size = INIT_BUF_SIZE;
    char* buf = malloc(buf_size);
    dmn_assert(buf);

    scnr->lcount = 1;
    scnr->fn = desc ? desc : "";
    scnr->cont_stack_top = -1;
    scnr->cs = vscf_start;
    scnr->err = err;

    vscf_data_t* root = scnr->cont = (vscf_data_t*)hash_new();

    while(!scnr->eof) {
        unsigned have;
        if(scnr->tstart == NULL)
            have = 0;
        else {
            have = scnr->pe - scnr->tstart;
            if(scnr->tstart == buf) {
                buf_size *= 2;
                buf = realloc(buf, buf_size);
                dmn_assert(buf);
            }
            else {
                memmove(buf, scnr->tstart, have);
            }
            scnr->tstart = buf;
        }

        const int space = buf_size - have;
        char* read_at = buf + have;
        scnr->p = read_at;

        if(stream) {
            const int len = fread(read_at, 1, space, stream);
            scnr->pe = scnr->p + len;
            if(len < space) {
                if(ferror(stream) || !feof(stream)) {
                    set_err(err, "fread() of '%s' failed\n", scnr->fn);
                    break;
                }
                scnr->eof = scnr->pe;
            }
        }
        else {
            const int len = read(fd, read_at, space);
            scnr->pe = scnr->p + len;
            if(len < 0) {
                set_err(err, "read() of '%s' failed: errno %i\n", scnr->fn, errno);
                break;
            }
            if(len < space)
                scnr->eof = scnr->pe;

        }

        %%{
            prepush {
                if(scnr->top == (signed)scnr->cs_stack_alloc)
                    scnr->cs_stack
                        = realloc(scnr->cs_stack,
                            ++scnr->cs_stack_alloc * sizeof(int));
            }
            variable stack scnr->cs_stack;
            variable top   scnr->top;
            variable cs    scnr->cs;
            variable p     scnr->p;
            variable pe    scnr->pe;
            variable eof   scnr->eof;
            write exec;
        }%%

        if(scnr->cs == vscf_error)
            parse_error_noargs("Syntax error");
        if(*err)
            break;
    }

    if(!*err && scnr->cs < vscf_first_final) {
        if(scnr->cs == vscf_en_hash)
            parse_error_noargs("Unterminated hash");
        else if(scnr->cs == vscf_en_array)
            parse_error_noargs("Unterminated array");
        else
            parse_error_noargs("Syntax error");
    }

    if(scnr->cont_stack) free(scnr->cont_stack);
    if(scnr->cs_stack) free(scnr->cs_stack);
    free(buf);

    const vscf_data_t* retval;

    if(*err) {
        val_destroy(root);
        retval = NULL;
    }
    else {
        dmn_assert(scnr->cont_stack_top == -1);
        dmn_assert(scnr->cont == root);
        retval = (const vscf_data_t*)root;
    }

    free(scnr);
    return retval;
}

/****************************/
/*** Public API functions ***/
/****************************/

const vscf_data_t* vscf_scan_fd(int fd, const char* desc, char** err) {
    dmn_assert(desc); dmn_assert(err);
    *err = NULL;

    return vscf_scan_fd_or_stream(fd, NULL, desc, err);
}

const vscf_data_t* vscf_scan_stream(FILE* stream, const char* desc, char** err) {
    dmn_assert(stream); dmn_assert(desc); dmn_assert(err);
    *err = NULL;

    return vscf_scan_fd_or_stream(0, stream, desc, err);
}

const vscf_data_t* vscf_scan_filename(const char* fn, char** err) {
    dmn_assert(fn); dmn_assert(err);
    *err = NULL;

    int fd = open(fn, O_RDONLY);
    if(fd < 0) {
        set_err(err, "Cannot open config file '%s' for reading: errno %i\n", fn, errno);
        return NULL;
    }

    const vscf_data_t* retval = vscf_scan_fd_or_stream(fd, NULL, fn, err);
    close(fd);
    return retval;
}

void vscf_destroy(const vscf_data_t* d) { dmn_assert(d); val_destroy((vscf_data_t*)d); }

vscf_type_t vscf_get_type(const vscf_data_t* d) { dmn_assert(d); return d->type; }
bool vscf_is_simple(const vscf_data_t* d) { dmn_assert(d); return d->type == VSCF_SIMPLE_T; }
bool vscf_is_array(const vscf_data_t* d) { dmn_assert(d); return d->type == VSCF_ARRAY_T; }
bool vscf_is_hash(const vscf_data_t* d) { dmn_assert(d); return d->type == VSCF_HASH_T; }
bool vscf_is_root(const vscf_data_t* d) { dmn_assert(d); return d->parent == NULL; }
const vscf_data_t* vscf_get_parent(const vscf_data_t* d) { dmn_assert(d); return d->parent; }

unsigned vscf_simple_get_len(const vscf_data_t* d) {
    dmn_assert(d); dmn_assert(vscf_is_simple(d));
    vscf_simple_ensure_val(&d->simple);
    return d->simple.len;
}

const char* vscf_simple_get_data(const vscf_data_t* d) {
    dmn_assert(d); dmn_assert(vscf_is_simple(d));
    vscf_simple_ensure_val(&d->simple);
    return d->simple.val;
}

unsigned vscf_array_get_len(const vscf_data_t* d) {
    dmn_assert(d);
    if(d->type != VSCF_ARRAY_T)
        return 1;
    return d->array.len;
}

const vscf_data_t* vscf_array_get_data(const vscf_data_t* d, unsigned idx) {
    dmn_assert(d);
    if(d->type != VSCF_ARRAY_T) {
        if(idx) return NULL;
        return d;
    }
    if(idx >= d->array.len) return NULL;
    return d->array.vals[idx];
}

unsigned vscf_hash_get_len(const vscf_data_t* d) {
    dmn_assert(d); dmn_assert(vscf_is_hash(d));
    return d->hash.child_count;
}

const vscf_data_t* vscf_hash_get_data_bykey(const vscf_data_t* d, const char* key, unsigned klen, bool set_mark) {
    dmn_assert(d); dmn_assert(vscf_is_hash(d));
    dmn_assert(key);
    if(d->hash.child_count) {
        unsigned child_mask = count2mask(d->hash.child_count);
        unsigned child_hash = djb_hash(key, klen, child_mask);
        vscf_hentry_t* he = d->hash.children[child_hash];
        while(he) {
            if((klen == he->klen) && !memcmp(key, he->key, klen)) {
                if(set_mark) he->marked = true;
                return he->val;
            }
            he = he->next;
        }
    }

    return NULL;
}

const char* vscf_hash_get_key_byindex(const vscf_data_t* d, unsigned idx, unsigned* klen_ptr) {
    dmn_assert(d); dmn_assert(vscf_is_hash(d));
    if(idx >= d->hash.child_count) return NULL;
    if(klen_ptr) *klen_ptr = d->hash.ordered[idx]->klen;
    const char *rv = d->hash.ordered[idx]->key;
    dmn_assert(rv);
    return rv;
}

const vscf_data_t* vscf_hash_get_data_byindex(const vscf_data_t* d, unsigned idx) {
    dmn_assert(d); dmn_assert(vscf_is_hash(d));
    if(idx >= d->hash.child_count) return NULL;
    const vscf_data_t* rv = d->hash.ordered[idx]->val;
    dmn_assert(rv);
    return rv;
}

int vscf_hash_get_index_bykey(const vscf_data_t* d, const char* key, unsigned klen) {
    dmn_assert(d); dmn_assert(vscf_is_hash(d));
    dmn_assert(key);
    if(d->hash.child_count) {
        unsigned child_mask = count2mask(d->hash.child_count);
        unsigned child_hash = djb_hash(key, klen, child_mask);
        vscf_hentry_t* he = d->hash.children[child_hash];
        while(he) {
            if((klen == he->klen) && !memcmp(key, he->key, klen))
                return he->index;
            he = he->next;
        }
    }

    return -1;
}

void vscf_hash_iterate(const vscf_data_t* d, bool ignore_mark, vscf_hash_iter_cb_t f, void* data) {
    dmn_assert(d); dmn_assert(vscf_is_hash(d));
    dmn_assert(f);
    for(unsigned i = 0; i < d->hash.child_count; i++) {
        const vscf_hentry_t* hentry = d->hash.ordered[i];
        if(!ignore_mark || !hentry->marked)
            if(!f(hentry->key, hentry->klen, hentry->val, data))
                return;
    }
}

void vscf_hash_sort(const vscf_data_t* d, vscf_key_cmp_cb_t f) {
    dmn_assert(d); dmn_assert(vscf_is_hash(d));
    dmn_assert(f);
    qsort(d->hash.ordered, d->hash.child_count, sizeof(vscf_hentry_t*),
        (int(*)(const void*, const void*))f
    );
    for(unsigned i = 0; i < d->hash.child_count; i++)
        d->hash.ordered[i]->index = i;
}

bool vscf_simple_get_as_ulong(const vscf_data_t* d, unsigned long* out) {
    dmn_assert(d); dmn_assert(vscf_is_simple(d));
    dmn_assert(out);
    vscf_simple_ensure_val(&d->simple);
    if(!d->simple.len) return false;
    char* eptr;
    char* real_eptr = d->simple.val + d->simple.len;
    errno = 0;
    unsigned long retval = strtoul(d->simple.val, &eptr, 0);
    if(errno || eptr != real_eptr) {
        errno = 0;
        return false;
    }

    *out = retval;
    return true;
}

bool vscf_simple_get_as_long(const vscf_data_t* d, long* out) {
    dmn_assert(d); dmn_assert(vscf_is_simple(d));
    dmn_assert(out);
    vscf_simple_ensure_val(&d->simple);
    if(!d->simple.len) return false;
    char* eptr;
    char* real_eptr = d->simple.val + d->simple.len;
    errno = 0;
    long retval = strtol(d->simple.val, &eptr, 0);
    if(errno || eptr != real_eptr) {
        errno = 0;
        return false;
    }

    *out = retval;
    return true;
}

bool vscf_simple_get_as_double(const vscf_data_t* d, double* out) {
    dmn_assert(d); dmn_assert(vscf_is_simple(d));
    dmn_assert(out);
    vscf_simple_ensure_val(&d->simple);
    if(!d->simple.len) return false;
    char* eptr;
    char* real_eptr = d->simple.val + d->simple.len;
    errno = 0;
    double retval = strtod(d->simple.val, &eptr);
    if(errno || eptr != real_eptr) {
        errno = 0;
        return false;
    }

    *out = retval;
    return true;
}

bool vscf_simple_get_as_bool(const vscf_data_t* d, bool* out) {
    dmn_assert(d); dmn_assert(vscf_is_simple(d));
    dmn_assert(out);
    vscf_simple_ensure_val(&d->simple);
    if(d->simple.len == 4
        && (d->simple.val[0] == 'T' || d->simple.val[0] == 't')
        && (d->simple.val[1] == 'R' || d->simple.val[1] == 'r')
        && (d->simple.val[2] == 'U' || d->simple.val[2] == 'u')
        && (d->simple.val[3] == 'E' || d->simple.val[3] == 'e')) {
        *out = true;
        return true;
    }

    if(d->simple.len == 5
        && (d->simple.val[0] == 'F' || d->simple.val[0] == 'f')
        && (d->simple.val[1] == 'A' || d->simple.val[1] == 'a')
        && (d->simple.val[2] == 'L' || d->simple.val[2] == 'l')
        && (d->simple.val[3] == 'S' || d->simple.val[3] == 's')
        && (d->simple.val[4] == 'E' || d->simple.val[4] == 'e')) {
        *out = false;
        return true;
    }

    return false;
}

dname_status_t vscf_simple_get_as_dname(const vscf_data_t* d, uint8_t* dname) {
    dmn_assert(d); dmn_assert(vscf_is_simple(d));
    dmn_assert(dname);
    return dname_from_string(dname, (const uint8_t*)d->simple.rval, d->simple.rlen);
}

vscf_data_t* vscf_hash_new(void) { return (vscf_data_t*)hash_new(); }

vscf_data_t* vscf_array_new(void) { return (vscf_data_t*)array_new(); }

vscf_data_t* vscf_simple_new(const char* rval, const unsigned rlen) {
    dmn_assert(rval);
    return (vscf_data_t*)simple_new(rval, rlen);
}

void vscf_array_add_val(vscf_data_t* a, vscf_data_t* v) {
    dmn_assert(a); dmn_assert(vscf_is_array(a));
    dmn_assert(v);
    array_add_val(&a->array, v);
}

bool vscf_hash_add_val(const char* key, const unsigned klen, vscf_data_t* h, vscf_data_t* v) {
    dmn_assert(h); dmn_assert(vscf_is_hash(h));
    dmn_assert(key); dmn_assert(v);
    return hash_add_val(key, klen, &h->hash, v);
}

vscf_data_t* vscf_clone(const vscf_data_t* d, const bool ignore_marked) { dmn_assert(d); return val_clone(d, ignore_marked); }

void vscf_hash_inherit(const vscf_data_t* src, vscf_data_t* dest, const char* k, const bool mark_src) {
    dmn_assert(src); dmn_assert(dest); dmn_assert(k);
    dmn_assert(vscf_is_hash(src)); dmn_assert(vscf_is_hash(dest));

    const vscf_data_t* src_val = vscf_hash_get_data_bystringkey(src, k, mark_src);
    if(src_val && !vscf_hash_get_data_bystringkey(dest, k, false))
        vscf_hash_add_val(k, strlen(k), dest, vscf_clone(src_val, false));
}

void vscf_hash_inherit_all(const vscf_data_t* src, vscf_data_t* dest, const bool skip_marked) {
    dmn_assert(src); dmn_assert(dest);
    dmn_assert(vscf_is_hash(src)); dmn_assert(vscf_is_hash(dest));

    const unsigned src_len = vscf_hash_get_len(src);
    for(unsigned i = 0; i < src_len; i++)
        if(!skip_marked || !src->hash.ordered[i]->marked)
            vscf_hash_inherit(src, dest, vscf_hash_get_key_byindex(src, i, NULL), false);
}

bool vscf_hash_bequeath_all(const vscf_data_t* src, const char* k, const bool mark_src, const bool skip_marked) {
    dmn_assert(src); dmn_assert(k);
    dmn_assert(vscf_is_hash(src));

    bool rv = false;

    const vscf_data_t* src_val = vscf_hash_get_data_bystringkey(src, k, mark_src);
    if(src_val) {
        const unsigned src_len = vscf_hash_get_len(src);
        for(unsigned i = 0; i < src_len; i++) {
            vscf_data_t* child_val = (vscf_data_t*)vscf_hash_get_data_byindex(src, i);
            if(vscf_is_hash(child_val) && (!skip_marked || !src->hash.ordered[i]->marked))
                if(!vscf_hash_get_data_bystringkey(child_val, k, false))
                    vscf_hash_add_val(k, strlen(k), child_val, vscf_clone(src_val, false));
        }
        rv = true;
    }

    return rv;
}

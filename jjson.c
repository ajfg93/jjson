#include "jjson.h"
#include <assert.h>  /* assert() */
#include <errno.h>   /* errno, ERANGE */
#include <math.h>    /* HUGE_VAL */
#include <stdlib.h>  /* NULL, malloc(), realloc(), free(), strtod() */
#include <string.h>  /* memcpy() */
#include <stdio.h>

#ifndef JJSON_PARSE_STACK_INIT_SIZE
#define JJSON_PARSE_STACK_INIT_SIZE 256
#endif

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)
#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ((ch) >= '1' && (ch) <= '9')
#define PUTC(c, ch)         do { *(char*)jjson_context_push(c, sizeof(char)) = (ch); } while(0)

typedef struct {
    const char* json;
    char* stack;
    size_t size, top;
}jjson_context;

static void* jjson_context_push(jjson_context* c, size_t size) {
    void* ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0)
            c->size = JJSON_PARSE_STACK_INIT_SIZE;
        while (c->top + size >= c->size)
            c->size += c->size >> 1;  /* c->size * 1.5 */
        c->stack = (char*)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void* jjson_context_pop(jjson_context* c, size_t size) {
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

static void jjson_parse_whitespace(jjson_context* c) {
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}

static int jjson_parse_literal(jjson_context* c, jjson_value* v, const char* literal, jjson_type type) {
    size_t i;
    EXPECT(c, literal[0]);
    for (i = 0; literal[i + 1]; i++)
        if (c->json[i] != literal[i + 1])
            return JJSON_PARSE_INVALID_VALUE;
    c->json += i;
    v->type = type;
    return JJSON_PARSE_OK;
}

static int jjson_parse_number(jjson_context* c, jjson_value* v) {
    const char* p = c->json;
    if (*p == '-') p++;
    if (*p == '0') p++;
    else {
        if (!ISDIGIT1TO9(*p)) return JJSON_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    if (*p == '.') {
        p++;
        if (!ISDIGIT(*p)) return JJSON_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!ISDIGIT(*p)) return JJSON_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    errno = 0;
    v->u.n = strtod(c->json, NULL);
    if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL))
        return JJSON_PARSE_NUMBER_TOO_BIG;
    v->type = JJSON_NUMBER;
    c->json = p;
    return JJSON_PARSE_OK;
}

static const char* jjson_parse_hex4(const char* p, unsigned* u) {
    int i;
    *u = 0;
    for (i = 0; i < 4; i++) {
        char ch = *p++;
        *u <<= 4;
        if      (ch >= '0' && ch <= '9')  *u |= ch - '0';
        else if (ch >= 'A' && ch <= 'F')  *u |= ch - ('A' - 10);
        else if (ch >= 'a' && ch <= 'f')  *u |= ch - ('a' - 10);
        else return NULL;
    }
    return p;
}

static void jjson_encode_utf8(jjson_context* c, unsigned u) {
    if (u <= 0x7F) 
        PUTC(c, u & 0xFF);
    else if (u <= 0x7FF) {
        PUTC(c, 0xC0 | ((u >> 6) & 0xFF));
        PUTC(c, 0x80 | ( u       & 0x3F));
    }
    else if (u <= 0xFFFF) {
        PUTC(c, 0xE0 | ((u >> 12) & 0xFF));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    }
    else {
        assert(u <= 0x10FFFF);
        PUTC(c, 0xF0 | ((u >> 18) & 0xFF));
        PUTC(c, 0x80 | ((u >> 12) & 0x3F));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    }
}

#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)

static int jjson_parse_string_raw(jjson_context* c, char** str, size_t* len) {
    size_t head = c->top;
    unsigned u, u2;
    const char* p;
    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                *len = c->top - head;
                *str = jjson_context_pop(c, *len);
                c->json = p;
                return JJSON_PARSE_OK;
            case '\\':
                switch (*p++) {
                    case '\"': PUTC(c, '\"'); break;
                    case '\\': PUTC(c, '\\'); break;
                    case '/':  PUTC(c, '/' ); break;
                    case 'b':  PUTC(c, '\b'); break;
                    case 'f':  PUTC(c, '\f'); break;
                    case 'n':  PUTC(c, '\n'); break;
                    case 'r':  PUTC(c, '\r'); break;
                    case 't':  PUTC(c, '\t'); break;
                    case 'u':
                        if (!(p = jjson_parse_hex4(p, &u)))
                            STRING_ERROR(JJSON_PARSE_INVALID_UNICODE_HEX);
                        if (u >= 0xD800 && u <= 0xDBFF) { /* surrogate pair */
                            if (*p++ != '\\')
                                STRING_ERROR(JJSON_PARSE_INVALID_UNICODE_SURROGATE);
                            if (*p++ != 'u')
                                STRING_ERROR(JJSON_PARSE_INVALID_UNICODE_SURROGATE);
                            if (!(p = jjson_parse_hex4(p, &u2)))
                                STRING_ERROR(JJSON_PARSE_INVALID_UNICODE_HEX);
                            if (u2 < 0xDC00 || u2 > 0xDFFF)
                                STRING_ERROR(JJSON_PARSE_INVALID_UNICODE_SURROGATE);
                            u = (((u - 0xD800) << 10) | (u2 - 0xDC00)) + 0x10000;
                        }
                        jjson_encode_utf8(c, u);
                        break;
                    default:
                        STRING_ERROR(JJSON_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            case '\0':
                STRING_ERROR(JJSON_PARSE_MISS_QUOTATION_MARK);
            default:
                if ((unsigned char)ch < 0x20)
                    STRING_ERROR(JJSON_PARSE_INVALID_STRING_CHAR);
                PUTC(c, ch);
        }
    }
}

static int jjson_parse_string(jjson_context* c, jjson_value* v) {
    int ret;
    char* s;
    size_t len;
    if ((ret = jjson_parse_string_raw(c, &s, &len)) == JJSON_PARSE_OK)
        jjson_set_string(v, s, len);
    return ret;
}

static int jjson_parse_value(jjson_context* c, jjson_value* v);

static int jjson_parse_array(jjson_context* c, jjson_value* v) {
    size_t i, size = 0;
    int ret;
    EXPECT(c, '[');
    jjson_parse_whitespace(c);
    if (*c->json == ']') {
        c->json++;
        jjson_set_array(v, 0);
        return JJSON_PARSE_OK;
    }
    for (;;) {
        jjson_value e;
        jjson_init(&e);
        if ((ret = jjson_parse_value(c, &e)) != JJSON_PARSE_OK)
            break;
        memcpy(jjson_context_push(c, sizeof(jjson_value)), &e, sizeof(jjson_value));
        size++;
        jjson_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
            jjson_parse_whitespace(c);
        }
        else if (*c->json == ']') {
            c->json++;
            jjson_set_array(v, size);
            memcpy(v->u.a.e, jjson_context_pop(c, size * sizeof(jjson_value)), size * sizeof(jjson_value));
            v->u.a.size = size;
            return JJSON_PARSE_OK;
        }
        else {
            ret = JJSON_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }
    /* Pop and free values on the stack */
    for (i = 0; i < size; i++)
        jjson_free((jjson_value*)jjson_context_pop(c, sizeof(jjson_value)));
    return ret;
}

static int jjson_parse_object(jjson_context* c, jjson_value* v) {
    size_t i, size;
    jjson_member m;
    int ret;
    EXPECT(c, '{');
    jjson_parse_whitespace(c);
    if (*c->json == '}') {
        c->json++;
        v->type = JJSON_OBJECT;
        v->u.o.m = 0;
        v->u.o.size = 0;
        return JJSON_PARSE_OK;
    }
    m.k = NULL;
    size = 0;
    for (;;) {
        char* str;
        jjson_init(&m.v);
        /* parse key */
        if (*c->json != '"') {
            ret = JJSON_PARSE_MISS_KEY;
            break;
        }
        if ((ret = jjson_parse_string_raw(c, &str, &m.klen)) != JJSON_PARSE_OK)
            break;
        memcpy(m.k = (char*)malloc(m.klen + 1), str, m.klen);
        m.k[m.klen] = '\0';
        /* parse ws colon ws */
        jjson_parse_whitespace(c);
        if (*c->json != ':') {
            ret = JJSON_PARSE_MISS_COLON;
            break;
        }
        c->json++;
        jjson_parse_whitespace(c);
        /* parse value */
        if ((ret = jjson_parse_value(c, &m.v)) != JJSON_PARSE_OK)
            break;
        memcpy(jjson_context_push(c, sizeof(jjson_member)), &m, sizeof(jjson_member));
        size++;
        m.k = NULL; /* ownership is transferred to member on stack */
        /* parse ws [comma | right-curly-brace] ws */
        jjson_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
            jjson_parse_whitespace(c);
        }
        else if (*c->json == '}') {
            size_t s = sizeof(jjson_member) * size;
            c->json++;
            v->type = JJSON_OBJECT;
            v->u.o.size = size;
            memcpy(v->u.o.m = (jjson_member*)malloc(s), jjson_context_pop(c, s), s);
            return JJSON_PARSE_OK;
        }
        else {
            ret = JJSON_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }
    /* Pop and free members on the stack */
    free(m.k);
    for (i = 0; i < size; i++) {
        jjson_member* m = (jjson_member*)jjson_context_pop(c, sizeof(jjson_member));
        free(m->k);
        jjson_free(&m->v);
    }
    v->type = JJSON_NULL;
    return ret;
}

static int jjson_parse_value(jjson_context* c, jjson_value* v) {
    switch (*c->json) {
        case 't':  return jjson_parse_literal(c, v, "true", JJSON_TRUE);
        case 'f':  return jjson_parse_literal(c, v, "false", JJSON_FALSE);
        case 'n':  return jjson_parse_literal(c, v, "null", JJSON_NULL);
        default:   return jjson_parse_number(c, v);
        case '"':  return jjson_parse_string(c, v);
        case '[':  return jjson_parse_array(c, v);
        case '{':  return jjson_parse_object(c, v);
        case '\0': return JJSON_PARSE_EXPECT_VALUE;
    }
}

#ifndef JJSON_PARSE_STRINGIFY_INIT_SIZE
#define JJSON_PARSE_STRINGIFY_INIT_SIZE 256
#endif

#define PUTS(c, s, len) memcpy(jjson_context_push(c, len), s, len)

static void jjson_stringify_string(jjson_context* c, const char* s, size_t len){
    size_t i;
    PUTC(c, '"');
    assert (s != NULL);
    for (i = 0; i < len; i++){
        switch(s[i]){
            case '\"': PUTS(c, "\\\"", 2);break;
            case '\\': PUTS(c, "\\\\", 2);break;
            case '\b': PUTS(c, "\\b", 2); break;
            case '\f': PUTS(c, "\\f", 2);break;
            case '\n': PUTS(c, "\\n",  2); break;
            case '\r': PUTS(c, "\\r",  2); break;
            case '\t': PUTS(c, "\\t",  2); break;
            default:
                PUTC(c, s[i]);
        }
    }
    PUTC(c, '"');
}

static int jjson_stringify_value(jjson_context* c, const jjson_value* v){
    size_t i;
    switch(v->type){
        case JJSON_NULL: PUTS(c, "null", 4); break;
        case JJSON_FALSE: PUTS(c, "false", 5); break;
        case JJSON_TRUE: PUTS(c, "true", 4); break;
        case JJSON_NUMBER:
            {
                char *buffer = jjson_context_push(c, 32);
                int length = sprintf(buffer, "%.17g", v->u.n);
                c->top -= 32 - length;
                break;
            }
        case JJSON_STRING:
            jjson_stringify_string(c, v->u.s.s, v->u.s.len);
            break;
        case JJSON_ARRAY:
            PUTC(c, '[');
            for(i = 0; i < v->u.a.size; i++){
                if (i > 0)
                    PUTC(c, ',');
                jjson_stringify_value(c, &v->u.a.e[i]);
            }
            PUTC(c, ']');
            break;
        case JJSON_OBJECT:
            PUTC(c, '{');
            for(i = 0; i < v->u.o.size; i++){
                if(i > 0)
                    PUTC(c, ',');
                jjson_stringify_string(c, v->u.o.m[i].k, v->u.o.m[i].klen);
                PUTC(c, ':');
                jjson_stringify_value(c, &v->u.o.m[i].v);
            }
            PUTC(c, '}');
            break;
        default:
            break;
    }
    return JJSON_STRINGIFY_OK;
}

int jjson_stringify(const jjson_value* v, char** json, size_t* length){
    /*
      caller need to free *json
    */
    jjson_context c;
    int ret;
    assert( v != NULL);
    assert(json != NULL);
    c.stack = (char*)malloc(c.size = JJSON_PARSE_STRINGIFY_INIT_SIZE);
    c.top = 0;
    if ((ret = jjson_stringify_value(&c, v)) != JJSON_STRINGIFY_OK){
        free(c.stack);
        *json = NULL;
        return ret;
    }
    if (length)
        *length = c.top;
    PUTC(&c, '\0');
    *json = c.stack;
    return JJSON_STRINGIFY_OK;
}

int jjson_parse(jjson_value* v, const char* json) {
    jjson_context c;
    int ret;
    assert(v != NULL);
    c.json = json;
    c.stack = NULL;
    c.size = c.top = 0;
    jjson_init(v);
    jjson_parse_whitespace(&c);
    if ((ret = jjson_parse_value(&c, v)) == JJSON_PARSE_OK) {
        jjson_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = JJSON_NULL;
            ret = JJSON_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return ret;
}

void jjson_free(jjson_value* v) {
    size_t i;
    assert(v != NULL);
    switch (v->type) {
        case JJSON_STRING:
            free(v->u.s.s);
            break;
        case JJSON_ARRAY:
            for (i = 0; i < v->u.a.size; i++)
                jjson_free(&v->u.a.e[i]);
            free(v->u.a.e);
            break;
        case JJSON_OBJECT:
            for (i = 0; i < v->u.o.size; i++) {
                free(v->u.o.m[i].k);
                jjson_free(&v->u.o.m[i].v);
            }
            free(v->u.o.m);
            break;
        default: break;
    }
    v->type = JJSON_NULL;
}

jjson_type jjson_get_type(const jjson_value* v) {
    assert(v != NULL);
    return v->type;
}

int jjson_get_boolean(const jjson_value* v) {
    assert(v != NULL && (v->type == JJSON_TRUE || v->type == JJSON_FALSE));
    return v->type == JJSON_TRUE;
}

void jjson_set_boolean(jjson_value* v, int b) {
    jjson_free(v);
    v->type = b ? JJSON_TRUE : JJSON_FALSE;
}

double jjson_get_number(const jjson_value* v) {
    assert(v != NULL && v->type == JJSON_NUMBER);
    return v->u.n;
}

void jjson_set_number(jjson_value* v, double n) {
    jjson_free(v);
    v->u.n = n;
    v->type = JJSON_NUMBER;
}

const char* jjson_get_string(const jjson_value* v) {
    assert(v != NULL && v->type == JJSON_STRING);
    return v->u.s.s;
}

size_t jjson_get_string_length(const jjson_value* v) {
    assert(v != NULL && v->type == JJSON_STRING);
    return v->u.s.len;
}

void jjson_set_string(jjson_value* v, const char* s, size_t len) {
    assert(v != NULL && (s != NULL || len == 0));
    jjson_free(v);
    v->u.s.s = (char*)malloc(len + 1);
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
    v->type = JJSON_STRING;
}

size_t jjson_get_array_size(const jjson_value* v) {
    assert(v != NULL && v->type == JJSON_ARRAY);
    return v->u.a.size;
}

jjson_value* jjson_get_array_element(const jjson_value* v, size_t index) {
    assert(v != NULL && v->type == JJSON_ARRAY);
    assert(index < v->u.a.size);
    return &v->u.a.e[index];
}

size_t jjson_get_object_size(const jjson_value* v) {
    assert(v != NULL && v->type == JJSON_OBJECT);
    return v->u.o.size;
}

const char* jjson_get_object_key(const jjson_value* v, size_t index) {
    assert(v != NULL && v->type == JJSON_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].k;
}

size_t jjson_get_object_key_length(const jjson_value* v, size_t index) {
    assert(v != NULL && v->type == JJSON_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].klen;
}

jjson_value* jjson_get_object_value(const jjson_value* v, size_t index) {
    assert(v != NULL && v->type == JJSON_OBJECT);
    assert(index < v->u.o.size);
    return &v->u.o.m[index].v;
}


size_t jjson_find_object_index(const jjson_value* v, const char* key, size_t klen){
    size_t i;
    assert( v != NULL && v->type == JJSON_OBJECT && key != NULL);
    for(i = 0; i< v->u.o.size; i++)
        if(v->u.o.m[i].klen == klen && memcmp(v->u.o.m[i].k, key, klen) == 0)
            return i;
    return JJSON_KEY_NOT_EXIST;
}

jjson_value* jjson_find_object_value(const jjson_value* v, const char* key, size_t klen){
    size_t index = jjson_find_object_index(v, key, klen);
    return index != JJSON_KEY_NOT_EXIST ? &v->u.o.m[index].v : NULL;
}

int jjson_is_equal(const jjson_value* lhs, const jjson_value* rhs){
    size_t i;
    assert(lhs != NULL && rhs != NULL);
    if(lhs->type != rhs->type)
        return 0;
    switch(lhs->type){
        case JJSON_STRING:
            return lhs->u.s.len == rhs->u.s.len && memcmp(lhs->u.s.s, rhs->u.s.s, lhs->u.s.len) == 0;
        case JJSON_NUMBER:
            return lhs->u.n == rhs->u.n;
        case JJSON_ARRAY:
            if(lhs->u.a.size != rhs->u.a.size)
                return 0;
            for(i = 0; i < lhs->u.a.size; i++){
                if(!jjson_is_equal(&lhs->u.a.e[i], &rhs->u.a.e[i]))
                    return 0;
            }
            return 1;
        case JJSON_OBJECT:
            if(lhs->u.o.size != rhs->u.o.size)
                return 0;
            for(i = 0; i < lhs->u.o.size; i++){
                jjson_value* rhs_v;
                rhs_v = jjson_find_object_value(rhs, lhs->u.o.m[i].k, lhs->u.o.m[i].klen);
                if(rhs_v == NULL || !jjson_is_equal(&lhs->u.o.m[i].v, rhs_v))
                    return 0;
            }
            return 1;
        default:
            return 1;
    }
}

void jjson_copy(jjson_value* dst, const jjson_value* src){
    size_t i;
    assert(src != NULL && dst != NULL && src != dst);
    switch(src->type){
        case JJSON_STRING:
            jjson_set_string(dst, src->u.s.s, src->u.s.len);
            break;
        case JJSON_ARRAY:
            jjson_free(dst);
            dst->type = JJSON_ARRAY;
            dst->u.a.size = src->u.a.size;
            dst->u.a.e = (jjson_value*) malloc(dst->u.a.size * sizeof(jjson_value));
            for(i = 0; i < src->u.a.size; i++){
                jjson_init(&dst->u.a.e[i]);
                jjson_copy(&dst->u.a.e[i], &src->u.a.e[i]);
            }
            break;
        case JJSON_OBJECT:
            jjson_free(dst);
            dst->type = JJSON_OBJECT;
            dst->u.o.size = src->u.o.size;
            dst->u.o.m = (jjson_member*) malloc(dst->u.o.size * sizeof(jjson_member));
            for(i = 0; i < src->u.o.size; i++){
                dst->u.o.m[i].klen = src->u.o.m[i].klen;
                dst->u.o.m[i].k = (char*) malloc(dst->u.o.m[i].klen);
                memcpy(dst->u.o.m[i].k, src->u.o.m[i].k, dst->u.o.m[i].klen);
                jjson_init(&dst->u.o.m[i].v);
                jjson_copy(&dst->u.o.m[i].v, &src->u.o.m[i].v);
            }
            break;
        default:
            jjson_free(dst);
            memcpy(dst, src, sizeof(jjson_value));
            break;
    }
}

void jjson_move(jjson_value* dst, jjson_value* src){
    assert(dst != NULL && src != NULL && src != dst);
    jjson_free(dst);
    memcpy(dst, src, sizeof(jjson_value));
    jjson_init(src);
}

void jjson_swap(jjson_value* lhs, jjson_value* rhs){
    assert(lhs != NULL && rhs != NULL);
    if (lhs != rhs){
        jjson_value temp;
        memcpy(&temp, lhs, sizeof(jjson_value));
        memcpy(rhs, lhs, sizeof(jjson_value));
        memcpy(rhs, &temp, sizeof(jjson_value));
    }
}

void jjson_set_array(jjson_value* v, size_t capacity){
    assert(v != NULL);
    jjson_free(v);
    v->type = JJSON_ARRAY;
    v->u.a.size = 0;
    v->u.a.capacity = capacity;
    v->u.a.e = capacity > 0 ? (jjson_value*) malloc(capacity * sizeof(jjson_value)) : NULL;
}

size_t jjson_get_array_capacity(const jjson_value* v){
    assert(v != NULL && v->type == JJSON_ARRAY);
    return v->u.a.capacity;
}

void jjson_reserve_array(jjson_value* v, size_t capacity){
    assert(v != NULL && v->type == JJSON_ARRAY);
    if(v->u.a.capacity < capacity){
        v->u.a.capacity = capacity;
        v->u.a.e = (jjson_value*) realloc(v->u.a.e, capacity * sizeof(jjson_value));
    }
}

void jjson_shrink_array(jjson_value* v) {
    assert(v != NULL && v->type == JJSON_ARRAY);
    if (v->u.a.capacity > v->u.a.size) {
        v->u.a.capacity = v->u.a.size;
        v->u.a.e = (jjson_value*)realloc(v->u.a.e, v->u.a.capacity * sizeof(jjson_value));
    }
}

jjson_value* jjson_pushback_array_element(jjson_value* v){
    assert(v != NULL && v->type == JJSON_ARRAY);
    if (v->u.a.size == v->u.a.capacity)
        /* set_array initialization won't be 0 but pop operation may reduce array to 0. */
        /* No, I was wrong. capacity could be set to 0 in set_array */
        jjson_reserve_array(v, v->u.a.capacity == 0 ? 1 : v->u.a.capacity * 2);
    jjson_init(&v->u.a.e[v->u.a.size]);
    return &v->u.a.e[v->u.a.size++];
}

void jjson_popback_array_element(jjson_value* v){
    assert(v != NULL && v->type == JJSON_ARRAY && v->u.a.size > 0);
    jjson_free(&v->u.a.e[--v->u.a.size]);
}

jjson_value* jjson_insert_array_element(jjson_value* v, size_t index){
    size_t i;
    assert(v != NULL && v->type == JJSON_ARRAY && index >= 0 && index <= v->u.a.size);
    if(index == v->u.a.size)
        return jjson_pushback_array_element(v);
    else{
        if(v->u.a.size == v->u.a.capacity)
            jjson_reserve_array(v, v->u.a.capacity == 0 ? 1 : v->u.a.capacity * 2);
        for(i = v->u.a.size; i > index; i--){
            v->u.a.e[i] = v->u.a.e[i-1];
        }
        /* jjson_init it, in case caller e.g. free it */
        jjson_init(&v->u.a.e[index]);
        v->u.a.size++;
        return &v->u.a.e[index];
    }
}

void jjson_erase_array_element(jjson_value* v, size_t index, size_t count){
    size_t i, start;

    assert(v != NULL && v->type == JJSON_ARRAY && index >= 0 && index < v->u.a.size && count >= 0 && (index + count) <= v->u.a.size);
    if(count) {
        for(i = index, start = 0; start != count ; i++, start++ )
            jjson_free(&v->u.a.e[i]);
        for(i = index ; i < v->u.a.size - count; i++)
            v->u.a.e[i] = v->u.a.e[i+count];
        v->u.a.size -= count;
    }
}

void jjson_clear_array(jjson_value* v){
    assert(v != NULL && v->type == JJSON_ARRAY);
    if(v->u.a.size){
        jjson_erase_array_element(v, 0, v->u.a.size);
    }
}

void jjson_set_object(jjson_value* v, size_t capacity){
    assert(v != NULL);
    jjson_free(v);
    v->type = JJSON_OBJECT;
    v->u.o.size = 0;
    v->u.o.capacity = capacity;
    v->u.o.m = capacity > 0 ? (jjson_member*) malloc(capacity * sizeof(jjson_member)) : NULL;
}

size_t jjson_get_object_capacity(const jjson_value* v){
    assert(v != NULL && v->type == JJSON_OBJECT);
    return v->u.o.capacity;
}

void jjson_reserve_object(jjson_value* v, size_t capacity){
    assert(v != NULL && v->type == JJSON_OBJECT);
    if(v->u.o.capacity < capacity){
        v->u.o.capacity = capacity;
        v->u.o.m = (jjson_member*) realloc(v->u.o.m, capacity * sizeof(jjson_member));
    }
}

void jjson_shrink_object(jjson_value* v){
    assert(v != NULL && v->type == JJSON_OBJECT);
    if(v->u.o.capacity > v->u.o.size){
        v->u.o.capacity = v->u.o.size;
        v->u.o.m = (jjson_member*) realloc(v->u.o.m, v->u.o.capacity * sizeof(jjson_member));
    }
}

jjson_value* jjson_set_object_value(jjson_value* v, const char* key, size_t klen){
    assert(v != NULL && v->type == JJSON_OBJECT && key != NULL);
    size_t index;
    jjson_value* ret_v;
    if((ret_v = jjson_find_object_value(v, key, klen)) != NULL)
        return ret_v;
    else{
        if(v->u.o.size == v->u.o.capacity)
            jjson_reserve_object(v, v->u.o.capacity == 0 ? 1 : v->u.o.capacity * 2);
        v->u.o.m[v->u.o.size].klen = klen;
        memcpy(v->u.o.m[v->u.o.size].k = (char*) malloc(klen), key, klen);
        ret_v = &v->u.o.m[v->u.o.size].v;
        jjson_init(ret_v);
        v->u.o.size++;
        return ret_v;
    }
}

void jjson_remove_object_value(jjson_value* v, size_t index){
    assert(v != NULL && v->type == JJSON_OBJECT && index >= 0 && index < v->u.o.size);
    size_t i;
    free(v->u.o.m[index].k);
    jjson_free(&v->u.o.m[index].v);
    for(i = index; i < v->u.o.size - 1; i++)
        v->u.o.m[i] = v->u.o.m[i + 1];
    v->u.o.size--;
}

void jjson_clear_object(jjson_value* v){
    assert(v != NULL && v->type == JJSON_OBJECT);
    size_t i;
    
    for(i = 0; i < v->u.o.size; i++){
        free(v->u.o.m[i].k);
        jjson_free(&v->u.o.m[i].v);
    }
    v->u.o.size = 0;
}


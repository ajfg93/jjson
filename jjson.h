#ifndef JJSON_H__
#define JJSON_H__

#include <stddef.h> /* size_t */

typedef enum { JJSON_NULL, JJSON_FALSE, JJSON_TRUE, JJSON_NUMBER, JJSON_STRING, JJSON_ARRAY, JJSON_OBJECT } jjson_type;

typedef struct jjson_value jjson_value;
typedef struct jjson_member jjson_member;

struct jjson_value {
    union {
        struct { jjson_member* m; size_t size, capacity; }o;   /* object: members, member count */
        struct { jjson_value* e; size_t size, capacity; }a;    /* array:  elements, element count */
        struct { char* s; size_t len; }s;           /* string: null-terminated string, string length */
        double n;                                   /* number */
    }u;
    jjson_type type;
};

struct jjson_member {
    char* k; size_t klen;   /* member key string, key string length */
    jjson_value v;           /* member value */
};

enum {
    JJSON_PARSE_OK = 0,
    JJSON_PARSE_EXPECT_VALUE,
    JJSON_PARSE_INVALID_VALUE,
    JJSON_PARSE_ROOT_NOT_SINGULAR,
    JJSON_PARSE_NUMBER_TOO_BIG,
    JJSON_PARSE_MISS_QUOTATION_MARK,
    JJSON_PARSE_INVALID_STRING_ESCAPE,
    JJSON_PARSE_INVALID_STRING_CHAR,
    JJSON_PARSE_INVALID_UNICODE_HEX,
    JJSON_PARSE_INVALID_UNICODE_SURROGATE,
    JJSON_PARSE_MISS_COMMA_OR_SQUARE_BRACKET,
    JJSON_PARSE_MISS_KEY,
    JJSON_PARSE_MISS_COLON,
    JJSON_PARSE_MISS_COMMA_OR_CURLY_BRACKET,
    JJSON_STRINGIFY_OK
};

#define jjson_init(v) do { (v)->type = JJSON_NULL; } while(0)
#define JJSON_KEY_NOT_EXIST ((size_t) -1)



int jjson_parse(jjson_value* v, const char* json);

void jjson_free(jjson_value* v);

jjson_type jjson_get_type(const jjson_value* v);

#define jjson_set_null(v) jjson_free(v)

int jjson_get_boolean(const jjson_value* v);
void jjson_set_boolean(jjson_value* v, int b);

double jjson_get_number(const jjson_value* v);
void jjson_set_number(jjson_value* v, double n);

const char* jjson_get_string(const jjson_value* v);
size_t jjson_get_string_length(const jjson_value* v);
void jjson_set_string(jjson_value* v, const char* s, size_t len);

size_t jjson_get_array_size(const jjson_value* v);
jjson_value* jjson_get_array_element(const jjson_value* v, size_t index);
void jjson_set_array(jjson_value* v, size_t capacity);
size_t jjson_get_array_capacity(const jjson_value* v);
void jjson_reserve_array(jjson_value* v, size_t capacity);
void jjson_shrink_array(jjson_value* v);
jjson_value* jjson_pushback_array_element(jjson_value* v);
void jjson_popback_array_element(jjson_value* v);
jjson_value* jjson_insert_array_element(jjson_value* v, size_t index);
void jjson_erase_array_element(jjson_value* v, size_t index, size_t count);
void jjson_clear_array(jjson_value* v);



size_t jjson_get_object_size(const jjson_value* v);
const char* jjson_get_object_key(const jjson_value* v, size_t index);
size_t jjson_get_object_key_length(const jjson_value* v, size_t index);
jjson_value* jjson_get_object_value(const jjson_value* v, size_t index);
size_t jjson_find_object_index(const jjson_value* v, const char* key, size_t klen);
jjson_value* jjson_find_object_value(const jjson_value* v, const char* key, size_t klen); 
int jjson_is_equal(const jjson_value* lhs, const jjson_value* rhs);
void jjson_set_object(jjson_value* v, size_t capacity);
size_t jjson_get_object_capacity(const jjson_value* v);
void jjson_reserve_object(jjson_value* v, size_t capacity);
void jjson_shrink_object(jjson_value* v);
jjson_value* jjson_set_object_value(jjson_value* v, const char* key, size_t klen);
void jjson_remove_object_value(jjson_value* v, size_t index);
void jjson_clear_object(jjson_value* v);


int jjson_stringify(const jjson_value* v, char** json, size_t* length);

void jjson_copy(jjson_value* dst, const jjson_value* src);
void jjson_move(jjson_value* dst, jjson_value* src);
void jjson_swap(jjson_value* dst, jjson_value* src);
#endif /* JJSONJSON_H__ */

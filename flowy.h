#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdint.h>

#ifndef __FLOWY_H
#define __FLOWY_H

/*
 * struct grouper_rule.op is a uint16_t with the options ORed together so that
 * one can have a switch over them.
 *
 * the comparison constants come first as they are not of the size of a power
 * of two and hence, would create wholes in the range of possible values for
 * grouper_rule.op which in turn would make it harder for the compiler to
 * optimize the switch. It is generally better if the possible values for the
 * switch statement are continuous because then, a branchtable can be built.
 *
 * +---+---+---+---+---+---+---+---+---+
 * |    comp   | delta | size1 | size2 |
 * +---+---+---+---+---+---+---+---+---+
 *
 * comp:  eq/ne/gt/lt/le/ge comparison operation
 * delta:     relative/absolute/no delta
 * size1: 8/16/32/64 bits for first argument
 * size2: 8/16/32/64 bits for second argument
 */

enum {
    /* size2 */
    RULE_S2_8 = 0,
    RULE_S2_16 = 1,
    RULE_S2_32 = 2,
    RULE_S2_64 = 3,
    /* size1 */
    RULE_S1_8 = 0,
    RULE_S1_16 = 4,
    RULE_S1_32 = 8,
    RULE_S1_64 = 12,
    /* D */
    RULE_ABS = 0,
    RULE_REL = 16,
    RULE_NO = 32,
    /* comp */
    RULE_EQ = 0,
    RULE_NE = 64,
    RULE_GT = 128,
    RULE_LT = 192,
    RULE_LE = 256,
    RULE_GE = 320,
};

enum field_length {
    LEN_UNIX_SECS       = 32,
    LEN_UNIX_NSECS      = 32,
    LEN_SYSUPTIME       = 32,
    LEN_EXADDR          = 32,

    LEN_DFLOWS          = 32,
    LEN_DPKTS           = 32,
    LEN_DOCTETS         = 32,
    LEN_FIRST           = 32,

    LEN_LAST            = 32,
    LEN_ENGINE_TYPE     = 8,
    LEN_ENGINE_ID       = 8,

    LEN_SRCADDR         = 32,
    LEN_DSTADDR         = 32,

    LEN_NEXTHOP         = 32,
    LEN_INPUT           = 16,
    LEN_OUTPUT          = 16,
    LEN_SRCPORT         = 16,

    LEN_DSTPORT         = 16,
    LEN_PROT            = 8,
    LEN_TOS             = 8,
    LEN_TCP_FLAGS       = 8,

    LEN_SRC_MASK        = 8,
    LEN_DST_MASK        = 8,
    LEN_SRC_AS          = 16,
    LEN_DST_AS          = 16,

    LEN_IN_ENCAPS       = 8,
    LEN_OUT_ENCAPS      = 8,
    LEN_PEER_NEXTHOP    = 32,
    LEN_ROUTER_SC       = 32,

    LEN_EXTRA_PKTS      = 32,
    LEN_MARKED_TOS      = 8,
    LEN_SRC_TAG         = 32,
    LEN_DST_TAG         = 32,
};

/*
 * query definition
 */

struct flowquery {
    size_t num_branches;
    struct branch_info *branches;
    struct merger_rule **mrules;
};

/*
 * branch info
 */

struct branch_info {
    struct ft_data *data;
    struct filter_rule *filter_rules;
    size_t num_filter_rules;
    struct grouper_rule *group_modules;
    size_t num_group_modules;
    struct grouper_aggr *aggr;
    size_t num_aggr;
    struct gfilter_rule *gfilter_rules;
    size_t num_gfilter_rules;
};

/*
 * filter rules
 */

struct filter_rule {
    size_t field_offset;
    uint64_t value;
    uint64_t delta;
    bool (*func)(
            char *record,
            size_t field_offset,
            uint64_t value,
            uint64_t delta);
};

/*
 * group - store module members and aggregation results
 * aggr  - store single aggr results or unions
 * start, end - times have to be stored as first and last members of the group
 *              do not necessarily supply these values
 */

struct group {
    char       **members;
    size_t       num_members;
    struct aggr *aggr;
    uint32_t start;
    uint32_t end;
};

struct aggr {
    size_t    num_values;
    uint64_t *values;
};

/*
 * grouper rules
 *
 * each module is a double pointer
 */

struct grouper_rule {
    size_t field_offset1;
    size_t field_offset2;
    uint64_t delta;
    uint16_t op;
    bool (*func)(
            struct group *group,
            size_t field_offset1,
            char *record2,
            size_t field_offset2,
            uint64_t delta);
};

struct grouper_aggr {
    int module; // NEW: indicate module, -1 for all
    size_t field_offset;
    struct aggr (*func)(
            char **group_records,
            size_t num_records,
            size_t field_offset);
};

/*
 * group filter rules
 */

struct gfilter_rule {
    size_t field;
    uint64_t value;
    uint64_t delta;
    bool (*func)(struct group *group,
            size_t field,
            uint64_t value,
            uint64_t delta);
};

/*
 * merger rules
 */

struct merger_rule {
    size_t branch1;
    size_t field1;
    size_t branch2;
    size_t field2;
    uint64_t delta;
    bool (*func)(struct group *group1,
            size_t field1,
            struct group *group2,
            size_t field2,
            uint64_t delta);
};

/*
 * tree search
 */

struct bsearch_handle {
    char **ordered_records;
    char ***uniq_records;
    size_t num_uniq_records;
};

void *bsearch_r(const void *key, const void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *thunk), void *thunk);

int comp_uint8_t(const void *e1, const void *e2, void *thunk);
int comp_uint16_t(const void *e1, const void *e2, void *thunk);
int comp_uint32_t(const void *e1, const void *e2, void *thunk);
int comp_uint64_t(const void *e1, const void *e2, void *thunk);
int comp_uint8_t_p(const void *e1, const void *e2, void *thunk);
int comp_uint16_t_p(const void *e1, const void *e2, void *thunk);
int comp_uint32_t_p(const void *e1, const void *e2, void *thunk);
int comp_uint64_t_p(const void *e1, const void *e2, void *thunk);
struct bsearch_handle *tree_create_uint8_t(char **records, size_t num_records, unsigned short field_offset);
struct bsearch_handle *tree_create_uint16_t(char **records, size_t num_records, unsigned short field_offset);
struct bsearch_handle *tree_create_uint32_t(char **records, size_t num_records, unsigned short field_offset);
struct bsearch_handle *tree_create_uint64_t(char **records, size_t num_records, unsigned short field_offset);
char **tree_find_uint8_t(struct bsearch_handle *handle, char *record, unsigned short field_offset);
char **tree_find_uint16_t(struct bsearch_handle *handle, char *record, unsigned short field_offset);
char **tree_find_uint32_t(struct bsearch_handle *handle, char *record, unsigned short field_offset);
char **tree_find_uint64_t(struct bsearch_handle *handle, char *record, unsigned short field_offset);
void tree_destroy(struct bsearch_handle *handle);

#endif
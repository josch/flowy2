#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "ftreader.h"

// TODO: allow OR in filters
// TODO: allow grouping and merging with more than one module

/*
   enum field {
   UNIX_SECS       = 0x00,
   UNIX_NSECS      = 0x01,
   SYSUPTIME       = 0x02,
   EXADDR          = 0x03,

   DFLOWS          = 0x04,
   DPKTS           = 0x05,
   DOCTETS         = 0x06,
   FIRST           = 0x07,

   LAST            = 0x08,
   ENGINE_TYPE     = 0x09,
   ENGINE_ID       = 0x0a,

   SRCADDR         = 0x0c,
   DSTADDR         = 0x0d,

   NEXTHOP         = 0x10,
   INPUT           = 0x11,
   OUTPUT          = 0x12,
   SRCPORT         = 0x13,

   DSTPORT         = 0x14,
   PROT            = 0x15,
   TOS             = 0x16,
   TCP_FLAGS       = 0x17,

   SRC_MASK        = 0x18,
   DST_MASK        = 0x19,
   SRC_AS          = 0x1a,
   DST_AS          = 0x1b,

   IN_ENCAPS       = 0x1c,
   OUT_ENCAPS      = 0x1d,
   PEER_NEXTHOP    = 0x1e,
   ROUTER_SC       = 0x1f,

   EXTRA_PKTS      = 0x20,
   MARKED_TOS      = 0x21,
   SRC_TAG         = 0x22,
   DST_TAG         = 0x23,
   };
 */

/*
   enum field_type {
   U_INT8  = 0;
   U_INT16 = 1;
   U_INT32 = 2;
   U_INT64 = 3;
   };*/

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
 * idea: have functions for all possible combinations of field type and
 *       comparison type. this gets huge for relative comparison (33 fields x
 *       33 fields x 19 comparisons = 20691) but one could auto generate those
 *       functions. it would avoid having to check the field_length parameter.
 */

bool filter_equal(char **records, int record, unsigned short field_offset, enum field_length length, int value, int delta)
{
    if (length == 8) {
        return value == *(unsigned char *)(records[record] + field_offset);
    } else if (length == 16) {
        return value == *(unsigned short *)(records[record] + field_offset);
    } else if (length == 32) {
        return value == *(unsigned int *)(records[record] + field_offset);
    }

    return false;
}

bool gfilter_rel_equal(char **records, int record1, unsigned short field_offset1, enum field_length length1,
                                      int record2, unsigned short field_offset2, enum field_length length2,
                                      int delta)
{
    unsigned int val1;
    unsigned int val2;

    if (length1 == 8) {
        val1 = *(unsigned char *)(records[record1] + field_offset1);
    } else if (length1 == 16) {
        val1 = *(unsigned short *)(records[record1] + field_offset1);
    } else if (length1 == 32) {
        val1 = *(unsigned int *)(records[record1] + field_offset1);
    } else {
        return false;
    }

    if (length2 == 8) {
        val2 = *(unsigned char *)(records[record2] + field_offset2);
    } else if (length2 == 16) {
        val2 = *(unsigned short *)(records[record2] + field_offset2);
    } else if (length2 == 32) {
        val2 = *(unsigned int *)(records[record2] + field_offset2);
    } else {
        return false;
    }

    if (delta == 0) {
        return val1 == val2;
    } else {
        return abs(val1 - val2) <= delta;
    }
}

bool gfilter_rel_lessthan(char **records, int record1, unsigned short field_offset1, enum field_length length1,
        int record2, unsigned short field_offset2, enum field_length length2,
        int delta)
{
    unsigned int val1;
    unsigned int val2;

    if (length1 == 8) {
        val1 = *(unsigned char *)(records[record1] + field_offset1);
    } else if (length1 == 16) {
        val1 = *(unsigned short *)(records[record1] + field_offset1);
    } else if (length1 == 32) {
        val1 = *(unsigned int *)(records[record1] + field_offset1);
    } else {
        return false;
    }

    if (length2 == 8) {
        val2 = *(unsigned char *)(records[record2] + field_offset2);
    } else if (length2 == 16) {
        val2 = *(unsigned short *)(records[record2] + field_offset2);
    } else if (length2 == 32) {
        val2 = *(unsigned int *)(records[record2] + field_offset2);
    } else {
        return false;
    }

    if (delta == 0) {
        return val1 < val2;
    } else {
        return val2 - val1 >= 0 && val2 - val1 <= delta;
    }
}

unsigned int aggr_static(char **records, int *group_records, int num_records, unsigned short field_offset, enum field_length length)
{
    if (length == 8) {
        return *(unsigned char *)(records[group_records[0]] + field_offset);
    } else if (length == 16) {
        return *(unsigned short *)(records[group_records[0]] + field_offset);
    } else if (length == 32) {
        return *(unsigned int *)(records[group_records[0]] + field_offset);
    }

    return 0;
}

unsigned int aggr_sum(char **records, int *group_records, int num_records, unsigned short field_offset, enum field_length length)
{
    unsigned int result;
    int i;

    result = 0;

    if (length == 8) {
        for (i = 0; i < num_records; i++) {
            result += *(unsigned char *)(records[group_records[i]] + field_offset);
        }
    } else if (length == 16) {
        for (i = 0; i < num_records; i++) {
            result += *(unsigned short *)(records[group_records[i]] + field_offset);
        }
    } else if (length == 32) {
        for (i = 0; i < num_records; i++) {
            result += *(unsigned int *)(records[group_records[i]] + field_offset);
        }
    }

    return result;
}

unsigned int aggr_or(char **records, int *group_records, int num_records, unsigned short field_offset, enum field_length length)
{
    unsigned int result;
    int i;

    result = 0;

    if (length == 8) {
        for (i = 0; i < num_records; i++) {
            result |= *(unsigned char *)(records[group_records[i]] + field_offset);
        }
    } else if (length == 16) {
        for (i = 0; i < num_records; i++) {
            result |= *(unsigned short *)(records[group_records[i]] + field_offset);
        }
    } else if (length == 32) {
        for (i = 0; i < num_records; i++) {
            result |= *(unsigned int *)(records[group_records[i]] + field_offset);
        }
    }

    return result;
}

/*
 * for bitwise operations the delta is the value with which the operation is
 * done as in: bitAND(flags, delta) = value
 */

struct absolute_filter_rule {
    unsigned short field_offset;
    enum field_length length;
    int value;
    int delta;
    bool (*filter)(char **records,
            int record,
            unsigned short field_offset,
            enum field_length length,
            int value,
            int delta);
};

/*
 * specifying two record numbers and what fields to compare
 *
 * for allen operations, the offsets are the offsets of First and Last
 * respectively and field_lengths are FIRST and LAST
 */

struct relative_group_filter_rule {
    unsigned short field_offset1;
    enum field_length length1;
    unsigned short field_offset2;
    enum field_length length2;
    int delta;
    bool (*filter)(char **records,
            int record1,
            unsigned short field_offset1,
            enum field_length length1,
            int record2,
            unsigned short field_offset2,
            enum field_length length2,
            int delta);
};

struct group {
    int *members;
    int num_members;
    int *aggr;
};

struct absolute_group_filter_rule {
    int field;
    int value;
    int delta;
    bool (*filter)(struct group *group,
            int field,
            int value,
            int delta);
};

bool gfilter_and(struct group *group, int field, int value, int delta)
{
    return (group->aggr[field] & delta) == value;
}

struct merger_filter_rule {
    int branch1;
    int field1;
    int branch2;
    int field2;
    int delta;
    bool (*filter)(struct group *group1,
            int field1,
            struct group *group2,
            int field2,
            int delta);
};

bool mfilter_equal(struct group *group1, int field1, struct group *group2, int field2, int delta)
{
    return group1->aggr[field1] == group2->aggr[field2];
}

bool mfilter_lessthan(struct group *group1, int field1, struct group *group2, int field2, int delta)
{
    return group1->aggr[field1] < group2->aggr[field2];
}

struct grouper_aggr {
    unsigned short field_offset;
    enum field_length length;
    unsigned int (*aggregate)(char **records,
            int *group_records,
            int num_records,
            unsigned short field_offset,
            enum field_length length);
};

struct branch_info {
    int id;
    int num_branches;
    struct ft_data *data;
    struct absolute_filter_rule *filter_rules;
    struct relative_group_filter_rule *group_module;
    int num_group_aggr;
    struct grouper_aggr *aggr;
    struct absolute_group_filter_rule *gfilter_rules;
};

int *filter(struct ft_data *data, struct absolute_filter_rule *rules)
{
    int i, j;
    int *filtered_records;
    int num_filtered_records;
    int buffer_size;

    buffer_size = 128; //TODO: make this configureable
    filtered_records = (int *)malloc(sizeof(int)*buffer_size);
    if (filtered_records == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    num_filtered_records = 0;

    for (i = 0; i < data->num_records; i++) {
        for (j = 0; rules[j].filter != NULL; j++) {
            if (!rules[j].filter(data->records, i, rules[j].field_offset, rules[j].length, rules[j].value, rules[j].delta))
                break;
        }

        // break if a rule did not return true
        if (rules[j].filter != NULL)
            continue;

        // if we are here, then this record matched all rules

        if (num_filtered_records == buffer_size) {
            buffer_size *= 2;
            filtered_records = (int *)realloc(filtered_records, sizeof(int)*buffer_size);
            if (filtered_records == NULL) {
                perror("malloc");
                exit(EXIT_FAILURE);
            }
        }

        filtered_records[num_filtered_records] = i;
        num_filtered_records++;
    }

    filtered_records = (int *)realloc(filtered_records, sizeof(int)*(num_filtered_records+1));
    if (filtered_records == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    filtered_records[num_filtered_records] = -1;

    printf("number of filtered records: %d\n", num_filtered_records);

    return filtered_records;
}

struct group **grouper(struct ft_data *data, int *filtered_records, struct relative_group_filter_rule *group_module_filters, struct grouper_aggr *aggr, int num_group_aggr)
{
    struct group **groups;
    int group_buffer_size;
    int num_groups;
    int i, j, k;
    int *temp_group_member_buffer;
    int temp_group_member_buffer_size;
    int num_group_members;

    temp_group_member_buffer_size = 128;
    temp_group_member_buffer = (int *)malloc(sizeof(int)*temp_group_member_buffer_size);

    group_buffer_size = 128;
    groups = (struct group **)malloc(sizeof(struct group *)*group_buffer_size);

    num_groups = 0;

    for (i = 0; filtered_records[i] != -1; i++) {
        if (i%10000==0)
            printf("%d\n", i);

        if (filtered_records[i] == -2)
            continue;

        num_group_members = 0;

        for (j = 0; filtered_records[j] != -1; j++) {
            if (i == j) // dont try to group with itself
                continue;

            if (filtered_records[j] == -2)
                continue;

            // check all module filter rules for those two records
            for (k = 0; group_module_filters[k].filter != NULL; k++) {
                if (!group_module_filters[k].filter(data->records, filtered_records[i], group_module_filters[k].field_offset1, group_module_filters[k].length1,
                            filtered_records[j], group_module_filters[k].field_offset2, group_module_filters[k].length2, group_module_filters[k].delta))
                    break;
            }

            if (group_module_filters[k].filter != NULL)
                continue;

            if (num_group_members == temp_group_member_buffer_size) {
                temp_group_member_buffer_size *= 2;
                temp_group_member_buffer = (int *)realloc(temp_group_member_buffer, sizeof(int)*temp_group_member_buffer_size);
                if (temp_group_member_buffer == NULL) {
                    perror("malloc");
                    exit(EXIT_FAILURE);
                }
            }

            temp_group_member_buffer[num_group_members] = filtered_records[j];
            filtered_records[j] = -2;
            num_group_members++;
        }

        if (num_group_members == 0)
            continue;

        if (num_groups == group_buffer_size) {
            group_buffer_size *= 2;
            groups = (struct group **)realloc(groups, sizeof(struct group *)*group_buffer_size);
            if (groups == NULL) {
                perror("malloc");
                exit(EXIT_FAILURE);
            }
        }

        groups[num_groups] = (struct group *)malloc(sizeof(struct group));
        if (groups[num_groups] == NULL) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        groups[num_groups]->num_members = num_group_members + 1;
        groups[num_groups]->members = (int *)malloc(sizeof(int)*(num_group_members + 1));
        if (groups[num_groups]->members == NULL) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        memcpy(groups[num_groups]->members, temp_group_member_buffer, sizeof(int)*num_group_members);
        groups[num_groups]->members[num_group_members] = filtered_records[i];

        groups[num_groups]->aggr = (int *)malloc(sizeof(int)*num_group_aggr);
        if (groups[num_groups]->aggr == NULL) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }

        for (j = 0; j < num_group_aggr; j++) {
            groups[num_groups]->aggr[j] = aggr[j].aggregate(data->records, groups[num_groups]->members, num_group_members+1, aggr[j].field_offset, aggr[j].length);
        }

        num_groups++;
    }

    groups = (struct group **)realloc(groups, sizeof(struct group *)*(num_groups + 1));
    if (groups == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    groups[num_groups] = (struct group *)malloc(sizeof(struct group));
    if (groups[num_groups] == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    groups[num_groups]->num_members = 0;
    groups[num_groups]->members = NULL;
    groups[num_groups]->aggr = NULL;

    free(temp_group_member_buffer);

    printf("number of groups: %d\n", num_groups);

    return groups;
}

struct group **group_filter(struct group **groups, struct absolute_group_filter_rule *rules)
{
    int i, j;
    struct group **filtered_groups;
    int num_filtered_groups;
    int buffer_size;

    buffer_size = 128;
    filtered_groups = (struct group **)malloc(sizeof(struct group *)*buffer_size);
    if (filtered_groups == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    num_filtered_groups = 0;

    for (i = 0; groups[i]->aggr != NULL; i++) {
        for (j = 0; rules[j].filter != NULL; j++) {
            if (!rules[j].filter(groups[i], rules[j].field, rules[j].value, rules[j].delta))
                break;
        }

        if (rules[j].filter != NULL) {
            free(groups[i]->members);
            free(groups[i]->aggr);
            free(groups[i]);
            groups[i] = NULL;
            continue;
        }

        if (num_filtered_groups == buffer_size) {
            buffer_size *= 2;
            filtered_groups = (struct group **)realloc(filtered_groups, sizeof(struct group *)*buffer_size);
            if (filtered_groups == NULL) {
                perror("malloc");
                exit(EXIT_FAILURE);
            }
        }

        filtered_groups[num_filtered_groups] = groups[i];
        num_filtered_groups++;
    }

    filtered_groups = (struct group **)realloc(filtered_groups, sizeof(struct group *)*(num_filtered_groups+1));
    if (filtered_groups == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    filtered_groups[num_filtered_groups] = groups[i];

    printf("number of filtered groups: %d\n", num_filtered_groups);

    return filtered_groups;
}

struct group **merger(struct group ***group_collections, int num_threads, struct merger_filter_rule *filter)
{
    struct group **group_tuples;
    int buffer_size;
    int num_group_tuples;
    int i, j;

    buffer_size = 128;
    group_tuples = (struct group **)malloc(sizeof(struct group *)*num_threads*buffer_size);
    if (group_tuples == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    num_group_tuples = 0;

    for (i = 0; group_collections[0][i]->aggr != NULL; i++) {
        for (j = 0; group_collections[1][j]->aggr != NULL; j++) {
            if (!filter[0].filter(group_collections[0][i], filter[0].field1, group_collections[1][j], filter[0].field2, filter[0].delta)
                    || !filter[1].filter(group_collections[0][i], filter[1].field1, group_collections[1][j], filter[1].field2, filter[1].delta)
                    )
                continue;

            if (num_group_tuples == buffer_size) {
                buffer_size *= 2;
                group_tuples = (struct group **)realloc(group_tuples, sizeof(struct group *)*num_threads*buffer_size);
                if (group_tuples == NULL) {
                    perror("malloc");
                    exit(EXIT_FAILURE);
                }
            }

            group_tuples[num_group_tuples*num_threads + 0] = group_collections[0][i];
            group_tuples[num_group_tuples*num_threads + 1] = group_collections[1][j];
            num_group_tuples++;
        }
    }

    group_tuples = (struct group **)realloc(group_tuples, sizeof(struct group *)*num_threads*(buffer_size + 1));
    if (group_tuples == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    group_tuples[num_group_tuples*num_threads + 0] = NULL;
    group_tuples[num_group_tuples*num_threads + 1] = NULL;

//    printf("number of group tuples: %d\n", num_group_tuples);

    return group_tuples;
}

static void *branch_start(void *arg)
{
    struct branch_info *binfo = (struct branch_info *)arg;

    struct group **groups;
    struct group **filtered_groups;
    int *filtered_records;

    /*
     * FILTER
     */

    filtered_records = filter(binfo->data, binfo->filter_rules);

    /*
     * GROUPER
     */

    groups = grouper(binfo->data, filtered_records, binfo->group_module, binfo->aggr, binfo->num_group_aggr);
    free(filtered_records);

    /*
     * GROUPFILTER
     */

    filtered_groups = group_filter(groups, binfo->gfilter_rules);
    free(groups);

    pthread_exit(filtered_groups);
}

int main(int argc, char **argv)
{
    struct ft_data *data;
    int num_threads;
    int i, ret;
    pthread_t *thread_ids;
    pthread_attr_t *thread_attrs;
    struct branch_info *binfos;
    struct group ***group_collections;
    struct group **group_tuples;

    num_threads = 2;

    data = ft_open(STDIN_FILENO);

    binfos = (struct branch_info *)calloc(num_threads, sizeof(struct branch_info));
    if (binfos == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    /*
     * custom rules
     */

    struct absolute_filter_rule filter_rules_branch1[2] = {
//        { data->offsets.dstport, LEN_DSTPORT, 80, 0, filter_equal },
        {0,0,0,0,NULL}
    };

    struct relative_group_filter_rule group_module_branch1[4] = {
        { data->offsets.srcaddr, LEN_SRCADDR, data->offsets.srcaddr, LEN_SRCADDR, 0, gfilter_rel_equal },
        { data->offsets.dstaddr, LEN_DSTADDR, data->offsets.dstaddr, LEN_DSTADDR, 0, gfilter_rel_equal },
//        { data->offsets.Last, LEN_LAST, data->offsets.First, LEN_FIRST, 1, gfilter_rel_lessthan },
        { 0, 0, 0, 0, 0, NULL }
    };

    struct grouper_aggr group_aggr_branch1[4] = {
        { data->offsets.srcaddr, LEN_SRCADDR, aggr_static },
        { data->offsets.dstaddr, LEN_DSTADDR, aggr_static },
        { data->offsets.dOctets, LEN_DOCTETS, aggr_sum },
        { data->offsets.tcp_flags, LEN_TCP_FLAGS, aggr_or }
    };

    struct absolute_group_filter_rule gfilter_branch1[2] = {
        { 3, 0x13, 0x13, gfilter_and},
        { 0, 0, 0, NULL }
    };

    binfos[0].id = 0;
    binfos[0].num_branches = 2;
    binfos[0].data = data;
    binfos[0].filter_rules = filter_rules_branch1;
    binfos[0].group_module = group_module_branch1;
    binfos[0].num_group_aggr = 4;
    binfos[0].aggr = group_aggr_branch1;
    binfos[0].gfilter_rules = gfilter_branch1;

    struct absolute_filter_rule filter_rules_branch2[2] = {
//        { data->offsets.srcport, LEN_SRCPORT, 80, 0, filter_equal },
        {0,0,0,0,NULL},
    };

    struct relative_group_filter_rule group_module_branch2[4] = {
        { data->offsets.srcaddr, LEN_SRCADDR, data->offsets.srcaddr, LEN_SRCADDR, 0, gfilter_rel_equal },
        { data->offsets.dstaddr, LEN_DSTADDR, data->offsets.dstaddr, LEN_DSTADDR, 0, gfilter_rel_equal },
//        { data->offsets.Last, LEN_LAST, data->offsets.First, LEN_FIRST, 1, gfilter_rel_lessthan },
        { 0, 0, 0, 0, 0, NULL }
    };

    struct grouper_aggr group_aggr_branch2[4] = {
        { data->offsets.srcaddr, LEN_SRCADDR, aggr_static },
        { data->offsets.dstaddr, LEN_DSTADDR, aggr_static },
        { data->offsets.dOctets, LEN_DOCTETS, aggr_sum },
        { data->offsets.tcp_flags, LEN_TCP_FLAGS, aggr_or }
    };

    struct absolute_group_filter_rule gfilter_branch2[2] = {
        { 3, 0x13, 0x13, gfilter_and},
        { 0, 0, 0, NULL }
    };

    binfos[1].id = 1;
    binfos[1].num_branches = 2;
    binfos[1].data = data;
    binfos[1].filter_rules = filter_rules_branch2;
    binfos[1].group_module = group_module_branch2;
    binfos[1].num_group_aggr = 4;
    binfos[1].aggr = group_aggr_branch2;
    binfos[1].gfilter_rules = gfilter_branch2;

    /*
     * SPLITTER
     *
     * (mostly pthread stuff)
     */

    thread_ids = (pthread_t *)calloc(num_threads, sizeof(pthread_t));
    if (thread_ids == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    thread_attrs = (pthread_attr_t *)calloc(num_threads, sizeof(pthread_attr_t));
    if (thread_attrs == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    group_collections = (struct group ***)malloc(num_threads*sizeof(struct group **));
    if (group_collections == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < num_threads; i++) {
        ret = pthread_attr_init(&thread_attrs[i]);
        if (ret != 0) {
            errno = ret;
            perror("pthread_attr_init");
            exit(EXIT_FAILURE);
        }

        ret = pthread_create(&thread_ids[i], &thread_attrs[i], &branch_start, (void *)(&binfos[i]));
        if (ret != 0) {
            errno = ret;
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }

        ret = pthread_attr_destroy(&thread_attrs[i]);
        if (ret != 0) {
            errno = ret;
            perror("pthread_attr_destroy");
            exit(EXIT_FAILURE);
        }
    }

    for (i = 0; i < num_threads; i++) {
        ret = pthread_join(thread_ids[i], (void **)(&group_collections[i]));
        if (ret != 0) {
            errno = ret;
            perror("pthread_join");
            exit(EXIT_FAILURE);
        }
    }

    free(thread_ids);
    free(thread_attrs);
    free(binfos);

    /*
     * MERGER
     */

    struct merger_filter_rule mfilter[3] = {
        { 0, 0, 1, 1, 0, mfilter_equal },
        { 0, 2, 1, 2, 0, mfilter_lessthan },
        { 0, 0, 0, 0, 0, NULL }
    };

    group_tuples = merger(group_collections, num_threads, mfilter);

    /*
     * UNGROUPER
     */

    // TODO: free group_collections at some point

    exit(EXIT_SUCCESS);
}

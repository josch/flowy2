#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "ftreader.h"
#include "flowy.h"
#include "auto_comps.h"

// TODO: allow OR in filters
// TODO: allow grouping and merging with more than one module

/*
 * for bitwise operations the delta is the value with which the operation is
 * done as in: bitAND(flags, delta) = value
 */

/*
 * specifying two record numbers and what fields to compare
 *
 * for allen operations, the offsets are the offsets of First and Last
 * respectively and field_lengths are FIRST and LAST
 */

char **filter(struct ft_data *data, struct filter_rule *filter_rules, int num_filter_rules, size_t *num_filtered_records)
{
    int i, j;
    char **filtered_records;

    *num_filtered_records = 0;
    filtered_records = (char **)malloc(sizeof(char *)**num_filtered_records);
    if (filtered_records == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < data->num_records; i++) {
        for (j = 0; j < num_filter_rules; j++) {
            if (!filter_rules[j].func(data->records[i], filter_rules[j].field_offset, filter_rules[j].value, filter_rules[j].delta))
                break;
        }

        // break if a rule did not return true
        if (j < num_filter_rules)
            continue;

        (*num_filtered_records)++;
        filtered_records = (char **)realloc(filtered_records, sizeof(char *)**num_filtered_records);
        if (filtered_records == NULL) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        filtered_records[*num_filtered_records-1] = data->records[i];
    }

    return filtered_records;
}

struct group **grouper(char **filtered_records, size_t num_filtered_records, struct grouper_rule *group_modules, int num_group_modules, struct grouper_aggr *aggr, size_t num_group_aggr, size_t *num_groups)
{
    struct group **groups;
    struct group *newgroup;
    int i, j, k;

    *num_groups = 0;
    groups = (struct group **)malloc(sizeof(struct group *));

    for (i = 0; i < num_filtered_records; i++) {
        if (i%10000==0) {
            printf("\r%zd%%", (i*100)/num_filtered_records);
            fflush(stdout);
        }

        if (filtered_records[i] == NULL)
            continue;

        (*num_groups)++;
        groups = (struct group **)realloc(groups, sizeof(struct group*)**num_groups);
        newgroup = (struct group *)malloc(sizeof(struct group));
        if (newgroup == NULL) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        groups[*num_groups-1] = newgroup;
        newgroup->num_members = 1;
        newgroup->members = (char **)malloc(sizeof(char *));
        newgroup->members[0] = filtered_records[i];

        for (j = i+1; j < num_filtered_records; j++) {
            if (i == j) // dont try to group with itself
                continue;

            if (filtered_records[j] == NULL)
                continue;

            // check all module filter rules for those two records
            for (k = 0; k < num_group_modules; k++) {
                if (!group_modules[k].func(newgroup, group_modules[k].field_offset1,
                            filtered_records[j], group_modules[k].field_offset2, group_modules[k].delta))
                    break;
            }

            if (k < num_group_modules)
                continue;

            newgroup->num_members++;
            newgroup->members = (char **)realloc(newgroup->members, sizeof(char *)*newgroup->num_members);
            newgroup->members[newgroup->num_members-1] = filtered_records[j];
            filtered_records[j] = NULL;
        }
    }

    for (i = 0; i < *num_groups; i++) {
        groups[i]->aggr = (struct aggr *)malloc(sizeof(struct aggr)*num_group_aggr);
        if (groups[i]->aggr == NULL) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }

        for (j = 0; j < num_group_aggr; j++) {
            groups[i]->aggr[j] = aggr[j].func(groups[i]->members, groups[i]->num_members, aggr[j].field_offset);
        }
    }

    return groups;
}

struct group **group_filter(struct group **groups, size_t num_groups, struct gfilter_rule *rules, size_t num_gfilter_rules, size_t *num_filtered_groups)
{
    int i, j;
    struct group **filtered_groups;

    *num_filtered_groups = 0;
    filtered_groups = (struct group **)malloc(sizeof(struct group *)**num_filtered_groups);

    for (i = 0; i < num_groups; i++) {
        for (j = 0; j < num_gfilter_rules; j++) {
            if (!rules[j].func(groups[i], rules[j].field, rules[j].value, rules[j].delta))
                break;
        }

        if (j < num_gfilter_rules) {
            free(groups[i]->members);
            free(groups[i]->aggr);
            free(groups[i]);
            groups[i] = NULL;
            continue;
        }

        (*num_filtered_groups)++;
        filtered_groups = (struct group **)realloc(filtered_groups, sizeof(struct group *)**num_filtered_groups);
        filtered_groups[*num_filtered_groups-1] = groups[i];
    }

    filtered_groups = (struct group **)realloc(filtered_groups, sizeof(struct group *)**num_filtered_groups+1);
    if (filtered_groups == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    filtered_groups[*num_filtered_groups] = groups[i];

    return filtered_groups;
}

/*
struct group **merger(struct group ***group_collections, int num_threads, struct merger_rule *filter)
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
            if (!filter[0].func(group_collections[0][i], filter[0].field1, group_collections[1][j], filter[0].field2, filter[0].delta)
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
}*/

static void *branch_start(void *arg)
{
    struct branch_info *binfo = (struct branch_info *)arg;

    struct group **groups;
    struct group **filtered_groups;
    char **filtered_records;
    size_t num_filtered_records;
    size_t num_groups;
    size_t num_filtered_groups;

    /*
     * FILTER
     */

    filtered_records = filter(binfo->data, binfo->filter_rules, binfo->num_filter_rules, &num_filtered_records);
    printf("\rnumber of filtered records: %zd\n", num_filtered_records);

    /*
     * GROUPER
     */

    groups = grouper(filtered_records, num_filtered_records, binfo->group_modules, binfo->num_group_modules, binfo->aggr, binfo->num_aggr, &num_groups);
    free(filtered_records);
    printf("\rnumber of groups: %zd\n", num_groups);

    /*
     * GROUPFILTER
     */

    filtered_groups = group_filter(groups, num_groups, binfo->gfilter_rules, binfo->num_gfilter_rules, &num_filtered_groups);
    free(groups);
    printf("\rnumber of filtered groups: %zd\n", num_filtered_groups);

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
//    struct group **group_tuples;

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

    struct filter_rule filter_rules_branch1[1] = {
        { data->offsets.dstport, 80, 0, filter_eq_uint16_t },
    };

    struct grouper_rule group_module_branch1[2] = {
        { data->offsets.srcaddr, data->offsets.srcaddr, 0, grouper_eq_uint32_t },
        { data->offsets.dstaddr, data->offsets.dstaddr, 0, grouper_eq_uint32_t },
//        { data->offsets.Last, data->offsets.First, 1, grouper_lt_uint32_t_rel }
    };

    struct grouper_aggr group_aggr_branch1[4] = {
        { 0, data->offsets.srcaddr, aggr_static_uint32_t },
        { 0, data->offsets.dstaddr, aggr_static_uint32_t },
        { 0, data->offsets.dOctets, aggr_sum_uint32_t },
        { 0, data->offsets.tcp_flags, aggr_or_uint16_t }
    };

    struct gfilter_rule gfilter_branch1[0] = {
    };

    binfos[0].data = data;
    binfos[0].filter_rules = filter_rules_branch1;
    binfos[0].num_filter_rules = 1;
    binfos[0].group_modules = group_module_branch1;
    binfos[0].num_group_modules = 2;
    binfos[0].aggr = group_aggr_branch1;
    binfos[0].num_aggr = 4;
    binfos[0].gfilter_rules = gfilter_branch1;
    binfos[0].num_gfilter_rules = 0;

    struct filter_rule filter_rules_branch2[1] = {
        { data->offsets.srcport, 80, 0, filter_eq_uint16_t },
    };

    struct grouper_rule group_module_branch2[2] = {
        { data->offsets.srcaddr, data->offsets.srcaddr, 0, grouper_eq_uint32_t },
        { data->offsets.dstaddr, data->offsets.dstaddr, 0, grouper_eq_uint32_t },
//        { data->offsets.Last, data->offsets.First, 1, grouper_lt_uint32_t_rel },
    };

    struct grouper_aggr group_aggr_branch2[4] = {
        { 0, data->offsets.srcaddr, aggr_static_uint32_t },
        { 0, data->offsets.dstaddr, aggr_static_uint32_t },
        { 0, data->offsets.dOctets, aggr_sum_uint32_t },
        { 0, data->offsets.tcp_flags, aggr_or_uint16_t }
    };

    struct gfilter_rule gfilter_branch2[0] = {
    };

    binfos[1].data = data;
    binfos[1].filter_rules = filter_rules_branch2;
    binfos[1].num_filter_rules = 1;
    binfos[1].group_modules = group_module_branch2;
    binfos[1].num_group_modules = 2;
    binfos[1].aggr = group_aggr_branch2;
    binfos[1].num_aggr = 4;
    binfos[1].gfilter_rules = gfilter_branch2;
    binfos[0].num_gfilter_rules = 0;

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

    exit(EXIT_SUCCESS);

    free(thread_ids);
    free(thread_attrs);
    free(binfos);

    /*
     * MERGER
     */

/*    struct merger_filter_rule mfilter[3] = {
        { 0, 0, 1, 1, 0, mfilter_equal },
        { 0, 2, 1, 2, 0, mfilter_lessthan },
    };*/

//    group_tuples = merger(group_collections, num_threads, mfilter);

    /*
     * UNGROUPER
     */

    // TODO: free group_collections at some point

    exit(EXIT_SUCCESS);
}

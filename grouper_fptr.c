#define _GNU_SOURCE

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "ftreader.h"
#include "flowy.h"
#include "auto_comps.h"

#define tree_item(size) \
struct tree_item_##size { \
    size value; \
    char ***ptr; \
};

tree_item(uint8_t);
tree_item(uint16_t);
tree_item(uint32_t);
tree_item(uint64_t);

#define comp(size) \
int comp_##size(const void *e1, const void *e2, void *thunk) \
{ \
    size x, y; \
    x = *(size *)(**(char ***)e1+*(size_t *)thunk); \
    y = *(size *)(**(char ***)e2+*(size_t *)thunk); \
    return (x > y) - (y > x); \
}

comp(uint8_t);
comp(uint16_t);
comp(uint32_t);
comp(uint64_t);

#define comp_p(size) \
int comp_##size##_p(const void *e1, const void *e2, void *thunk) \
{ \
    size x, y; \
    x = *(size *)((char *)e1+*(size_t *)thunk); \
    y = ((struct tree_item_uint32_t *)e2)->value; \
    return (x > y) - (y > x); \
}

comp_p(uint8_t);
comp_p(uint16_t);
comp_p(uint32_t);
comp_p(uint64_t);

struct group **grouper(char **filtered_records, size_t num_filtered_records, struct grouper_rule *group_modules, int num_group_modules, struct grouper_aggr *aggr, size_t num_group_aggr, size_t *num_groups)
{
    struct group **groups;
    struct group *newgroup;
    int i, j, k;
    char ***sorted_records;
    struct tree_item_uint32_t *uniq_records;
    size_t num_uniq_records;

    *num_groups = 0;
    groups = (struct group **)malloc(sizeof(struct group *));

    sorted_records = NULL;
    uniq_records = NULL;
    num_uniq_records = 0;
    if (num_group_modules > 0) {
        sorted_records = (char ***)malloc(sizeof(char **)*(num_filtered_records+1));
        if (sorted_records == NULL) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }

        for (i = 0; i < num_filtered_records; i++) {
            sorted_records[i] = &filtered_records[i];
        }

        // order by right hand side of comparison
        // TODO: different comp func sizes
        qsort_r(sorted_records, num_filtered_records, sizeof(char **), comp_uint32_t, (void *)&group_modules[0].field_offset2);

        uniq_records = (struct tree_item_uint32_t *)malloc(num_filtered_records*sizeof(struct tree_item_uint32_t));
        uniq_records[0].value = *(uint32_t *)(*sorted_records[0] + group_modules[0].field_offset2);
        uniq_records[0].ptr = &sorted_records[0];
        num_uniq_records = 1;
        for (i = 0; i < num_filtered_records; i++) {
            if (*(uint32_t *)(*sorted_records[i] + group_modules[0].field_offset2)
            != uniq_records[num_uniq_records-1].value) {
                uniq_records[num_uniq_records].value = *(uint32_t *)(*sorted_records[i] + group_modules[0].field_offset2);
                uniq_records[num_uniq_records].ptr = &sorted_records[i];
                num_uniq_records++;
            }
        }
        uniq_records = (struct tree_item_uint32_t *)realloc(uniq_records, num_uniq_records*sizeof(struct tree_item_uint32_t));

        // mark the end of sorted records
        sorted_records[num_filtered_records] = NULL;
    }

    for (i = 0; i < num_filtered_records; i++) {
        if ((i&1023)==0) {
            printf("\r%0.2f%% %d/%zd groups: %zd", (i*100.0f)/num_filtered_records, i, num_filtered_records, *num_groups);
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

        if (num_group_modules == 0)
            continue;

        // search for left hand side of comparison in records ordered by right
        // hand side of comparison
        char ***record_iter = ((struct tree_item_uint32_t *)bsearch_r(
                filtered_records[i],
                (void *)uniq_records,
                num_uniq_records,
                sizeof(struct tree_item_uint32_t),
                comp_uint32_t_p,
                (void *)&group_modules[0].field_offset1))->ptr;

        // iterate until terminating NULL in sorted_records
        for (;*record_iter != NULL; record_iter++) {
            // already processed record from filtered_records
            if (**record_iter == NULL)
                continue;

            // do not group with itself
            if (**record_iter == filtered_records[i])
                continue;

            // check all module filter rules for those two records
            for (k = 0; k < num_group_modules; k++) {
                if (!group_modules[k].func(newgroup, group_modules[k].field_offset1,
                            **record_iter, group_modules[k].field_offset2, group_modules[k].delta))
                    break;
            }

            // first rule didnt match
            if (k == 0)
                break;

            // one of the other rules didnt match
            if (k < num_group_modules)
                continue;

            newgroup->num_members++;
            newgroup->members = (char **)realloc(newgroup->members, sizeof(char *)*newgroup->num_members);
            newgroup->members[newgroup->num_members-1] = **record_iter; // assign entry in filtered_records to group
            **record_iter = NULL; // set entry in filtered_records to NULL
        }

        filtered_records[i] = NULL;
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

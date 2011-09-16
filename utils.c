#include <stdlib.h>

/*
 * adapted from ./stdlib/bsearch.c from the GNU C Library
 * pass additional argument thunk to compar to allow it access additional data
 * without global variables - in our case, we need to pass the data offset
 */
void *bsearch_r(const void *key, const void *base, size_t nmemb, size_t size,
        int (*compar) (const void *, const void *, void *thunk), void *thunk)
{
    size_t l, u, idx;
    const void *p;
    int comparison;

    l = 0;
    u = nmemb;
    while (l < u) {
        idx = (l + u) / 2;
        p = (void *) (((const char *) base) + (idx * size));
        comparison = (*compar) (key, p, thunk);
        if (comparison < 0) {
            u = idx;
        } else if (comparison > 0) {
            l = idx + 1;
        } else {
            return (void *) p;
        }
    }
    return NULL;
}

/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_SCRATCH_IMPL_H_
#define _SECP256K1_SCRATCH_IMPL_H_

#include "util.h"
#include "scratch.h"

static secp256k1_scratch* secp256k1_scratch_create(const secp256k1_callback* error_callback, size_t max_size) {
    secp256k1_scratch* ret = (secp256k1_scratch*)checked_malloc(error_callback, sizeof(*ret));
    if (ret != NULL) {
        memset(ret, 0, sizeof(*ret));
        ret->max_size = max_size;
        ret->error_callback = error_callback;
    }
    return ret;
}

static void secp256k1_scratch_destroy(secp256k1_scratch* scratch) {
    if (scratch != NULL) {
        /* Don't mark this VERIFY_CHECK as a problem, if scratch->frame non null it is mean that error already happens,
         * we can't do better at this point. */
        VERIFY_CHECK(scratch->frame == 0);
        free(scratch);
    }
}

static size_t secp256k1_scratch_max_allocation(const secp256k1_scratch* scratch, size_t objects) {
    size_t i = 0;
    size_t allocated = 0;
    for (i = 0; i < scratch->frame; i++) {
        allocated += scratch->frame_size[i];
    }
    if (scratch->max_size - allocated <= objects * ALIGNMENT) {
        return 0;
    }
    return scratch->max_size - allocated - objects * ALIGNMENT;
}

static int secp256k1_scratch_allocate_frame(secp256k1_scratch* scratch, size_t n, size_t objects) {
    VERIFY_CHECK(scratch->frame < SECP256K1_SCRATCH_MAX_FRAMES);

    if (n <= secp256k1_scratch_max_allocation(scratch, objects)) {
        n += objects * ALIGNMENT;
        scratch->data[scratch->frame] = checked_malloc(scratch->error_callback, n);
        if (scratch->data[scratch->frame] == NULL) {
            return 0;
        }
        scratch->frame_size[scratch->frame] = n;
        scratch->offset[scratch->frame] = 0;
        scratch->frame++;
        return 1;
    } else {
        return 0;
    }
}

static void secp256k1_scratch_deallocate_frame(secp256k1_scratch* scratch) {
    /* Don't mark this VERIFY_CHECK as a problem, if scratch->frame non null it is mean that error already happens,
     * we can't do better at this point. */
    VERIFY_CHECK(scratch->frame > 0);
    scratch->frame -= 1;
    secp256k1_memclear(scratch->data[scratch->frame], scratch->frame_size[scratch->frame]);
    free(scratch->data[scratch->frame]);
    scratch->data[scratch->frame] = NULL;
    scratch->offset[scratch->frame] = 0;
    scratch->frame_size[scratch->frame] = 0;
}

static void *secp256k1_scratch_alloc(secp256k1_scratch* scratch, size_t size) {
    void *ret;
    size_t frame;

    if (scratch->frame == 0)
        return NULL;

    frame = scratch->frame - 1;

    /* data overflow case. In any case scratch buffer can't be so large */
    if (size>=SIZE_MAX/2 || scratch->offset[frame]>=SIZE_MAX/2)
        return NULL;

    size = ROUND_TO_ALIGN(size);

    if (scratch->frame == 0 || size + scratch->offset[frame] > scratch->frame_size[frame]) {
        return NULL;
    }
    ret = (void *) ((unsigned char *) scratch->data[frame] + scratch->offset[frame]);
    memset(ret, 0, size);
    scratch->offset[frame] += size;

    return ret;
}

#endif

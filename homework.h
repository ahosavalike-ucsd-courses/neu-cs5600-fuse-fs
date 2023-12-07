#ifndef __HOMEWORK__
#define __HOMEWORK__

#include "fs5600.h"

#ifdef __HOMEWORK__
#include <stdio.h>
#define dbg(...) fprintf(stderr, __VA_ARGS__);
#else
#define dbg(...)
#endif

#define min(a,b) (((a) < (b)) ? (a) : (b))

#define N_BLOCKS_IN_BLOCK (BLOCK_SIZE / sizeof(int32_t))
#define N_DIRENTS_IN_BLOCK (BLOCK_SIZE / sizeof(fs_dirent))

typedef struct fs_state {
    fs_super super;
    char* block_bm;
    char* inode_bm;
    fs_inode* inodes;
} fs_state;

#endif

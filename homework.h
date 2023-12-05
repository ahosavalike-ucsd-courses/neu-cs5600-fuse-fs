#ifndef __HOMEWORK__
#define __HOMEWORK__

#include "fs5600.h"

#ifdef __HOMEWORK__
#include <stdio.h>
#define dbg(...) printf(__VA_ARGS__);
#else
#define dbg(...) {}
#endif

typedef struct fs_state {
    fs_super super;
    char* block_bm;
    char* inode_bm;
    fs_inode* inodes;
} fs_state;

#define INODE_BLKS (sizeof(fs_inode) / BLOCK_SIZE)

#endif

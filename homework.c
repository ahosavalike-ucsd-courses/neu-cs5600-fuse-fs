/*
 * file:        homework.c
 * description: skeleton file for CS 5600 system
 *
 * CS 5600, Computer Systems, Northeastern CCIS
 * Peter Desnoyers, November 2023
 */

#define FUSE_USE_VERSION 30
#define _FILE_OFFSET_BITS 64

#include "homework.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse3/fuse.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fs5600.h"

/* disk access. All access is in terms of BLOCK_SIZE blocks; read and
 * write functions return 0 (success) or -EIO.
 */
extern int block_read(void *buf, int blknum, int nblks);
extern int block_write(void *buf, int blknum, int nblks);

/* how many buckets of size M do you need to hold N items?
 */
int div_round_up(int n, int m) {
    return (n + m - 1) / m;
}

/* quick and dirty function to split an absolute path (i.e. begins with "/")
 * uses the same interface as the command line parser in Lab 1
 */
int split_path(const char *path, int argc_max, char **argv, char *buf, int buf_len) {
    int i = 0, c = 1;
    char *end = buf + buf_len;

    if (*path++ != '/' || *path == 0)
        return 0;

    while (c != 0 && i < argc_max && buf < end) {
        argv[i++] = buf;
        while ((c = *path++) && (c != '/') && buf < end)
            *buf++ = c;
        *buf++ = 0;
    }
    return i;
}

/* I'll give you this function for free, to help
 */
void inode_2_stat(struct stat *sb, struct fs_inode *in) {
    memset(sb, 0, sizeof(*sb));
    sb->st_mode = in->mode;
    sb->st_nlink = 1;
    sb->st_uid = in->uid;
    sb->st_gid = in->gid;
    sb->st_size = in->size;
    sb->st_blocks = div_round_up(in->size, BLOCK_SIZE);
    sb->st_atime = sb->st_mtime = sb->st_ctime = in->mtime;
}

void read_state(fs_state *state) {
    int block = 0;
    block_read(&state->super, block, 1);
    block++;
    state->block_bm = calloc(state->super.blk_map_len, BLOCK_SIZE);
    block_read(state->block_bm, block, state->super.blk_map_len);
    block += state->super.blk_map_len;
    state->inode_bm = calloc(state->super.in_map_len, BLOCK_SIZE);
    block_read(state->inode_bm, block, state->super.in_map_len);
    block += state->super.in_map_len;
    state->inodes = calloc(state->super.inodes_len, sizeof(fs_inode));
    for (int i = 0; i < state->super.inodes_len; i++) {
        block_read(&state->inodes[i], block, INODE_BLKS);
        block += INODE_BLKS;
    }
}

void write_state(fs_state *state) {
    int block = 0;
    block_write(&state->super, block, 1);
    block++;
    block_write(state->block_bm, block, state->super.blk_map_len);
    block += state->super.blk_map_len;
    block_write(state->inode_bm, block, state->super.in_map_len);
    block += state->super.in_map_len;
    for (int i = 0; i < state->super.inodes_len; i++) {
        block_write(&state->inodes[i], block, INODE_BLKS);
        block += INODE_BLKS;
    }
}

void *lab3_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    fs_state *state = calloc(1, sizeof(fs_state));
    read_state(state);
    return state;
}

void lab3_destroy(void *private_data) {
    fs_state *state = private_data;
    free(state->block_bm);
    free(state->inode_bm);
    free(state->inodes);
    free(state);
}

fs_dirent find_dirent(fs_state *state, fs_inode *inode, char *name) {
    assert(inode->mode & 0x4000 != 0);
    fs_dirent dirents[BLOCK_SIZE / sizeof(fs_dirent)] = {0};
    // Go through direct blocks
    for (int i = 0; i < N_DIRECT; i++) {
        int32_t blk = inode->ptrs[i];
        // Cannot have block 0
        if (!blk) break;
        assert(block_read(dirents, blk, 1) == 0);
        for (int i = 0; i < BLOCK_SIZE / sizeof(fs_dirent); i++) {
            // Not found
            if (!dirents[i].valid) continue;
            // Name matches, found
            if (!strcmp(name, dirents[i].name)) return dirents[i];
        }
    }
    // Go through indir_1 block
    int32_t block_nums[BLOCK_SIZE / sizeof(int32_t)] = {0};
    assert(block_read(block_nums, inode->indir_1, 1) == 0);
    for (int j = 0; j < BLOCK_SIZE / sizeof(int32_t); j++) {
        // Cannot have block 0
        assert(block_nums[j]);
        assert(block_read(dirents, block_nums[j], 1) == 0);
        for (int i = 0; i < BLOCK_SIZE / sizeof(fs_dirent); i++) {
            // Not found
            if (!dirents[i].valid) continue;
            // Name matches, found
            if (!strcmp(name, dirents[i].name)) return dirents[i];
        }
    }
    // Go through indir_2 block
    int32_t double_block_nums[BLOCK_SIZE / sizeof(int32_t)] = {0};
    assert(block_read(double_block_nums, inode->indir_2, 1) == 0);
    for (int k = 0; k < BLOCK_SIZE / sizeof(int32_t); k++) {
        // Cannot have block 0
        assert(double_block_nums[k]);
        assert(block_read(block_nums, double_block_nums[k], 1) == 0);
        for (int j = 0; j < BLOCK_SIZE / sizeof(int32_t); j++) {
            // Cannot have block 0
            assert(block_nums[j]);
            assert(block_read(dirents, block_nums[j], 1) == 0);
            for (int i = 0; i < BLOCK_SIZE / sizeof(fs_dirent); i++) {
                // Not found
                if (!dirents[i].valid) continue;
                // Name matches, found
                if (!strcmp(name, dirents[i].name)) return dirents[i];
            }
        }
    }
    dirents[0].valid = 0;
    return dirents[0];
}

int lab3_getattr(const char *path, struct stat *sb, struct fuse_file_info *fi) {
    fs_state *state = fuse_get_context()->private_data;
    // TODO: Check if this is always correct
    fs_inode *inode = &state->inodes[1];
    char token[28] = {0};
    // For each directory, skip /
    assert(*path == '/');
    while (*++path) {
        memset(token, 0, 28);
        int i = 0;
        while (*path && *path != "/")
            token[i++] = *path++;
        // Break on 0 length token
        if (*token) break;
        // Check if this is the last token
        bool last = !*path;
        // Parse the inode's (dir?)entries and search for the current dir/file
        // Test for inode being a directory entry
        if (!last && inode->mode & 0x4000 == 0) return -ENOTDIR;
        fs_dirent next = find_dirent(state, inode, token);
        if (!next.valid) return -ENOENT;
        // Inode number cannot be 0
        assert(next.inode);
        inode = &state->inodes[next.inode];
    }
    inode_2_stat(sb, inode);
    return 0;
}

/* for read-only version you need to implement:
 * - lab3_init
 * - lab3_getattr
 * - lab3_readdir
 * - lab3_read
 *
 * for the full version you need to implement:
 * - lab3_create
 * - lab3_mkdir
 * - lab3_unlink
 * - lab3_rmdir
 * - lab3_rename
 * - lab3_chmod
 * - lab3_truncate
 * - lab3_write
 */

/* operations vector. Please don't rename it, or else you'll break things
 * uncomment fields as you implement them.
 */
struct fuse_operations fs_ops = {
    .init = lab3_init,
    .destroy = lab3_destroy,
    .getattr = lab3_getattr,
    //    .readdir = lab3_readdir,
    //    .read = lab3_read,

    //    .create = lab3_create,
    //    .mkdir = lab3_mkdir,
    //    .unlink = lab3_unlink,
    //    .rmdir = lab3_rmdir,
    //    .rename = lab3_rename,
    //    .chmod = lab3_chmod,
    //    .truncate = lab3_truncate,
    //    .write = lab3_write,
};

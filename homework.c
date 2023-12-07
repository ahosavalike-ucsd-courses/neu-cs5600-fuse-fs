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
    assert(state->super.magic == FS_MAGIC);
    block++;
    state->block_bm = calloc(state->super.blk_map_len, BLOCK_SIZE);
    block_read(state->block_bm, block, state->super.blk_map_len);
    block += state->super.blk_map_len;
    state->inode_bm = calloc(state->super.in_map_len, BLOCK_SIZE);
    block_read(state->inode_bm, block, state->super.in_map_len);
    block += state->super.in_map_len;
    state->inodes = calloc(state->super.inodes_len, BLOCK_SIZE);
    block_read(state->inodes, block, state->super.inodes_len);
}

void write_state(fs_state *state) {
    int block = 0;
    block_write(&state->super, block, 1);
    block++;
    block_write(state->block_bm, block, state->super.blk_map_len);
    block += state->super.blk_map_len;
    block_write(state->inode_bm, block, state->super.in_map_len);
    block += state->super.in_map_len;
    block_write(state->inodes, block, state->super.inodes_len);
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

int32_t get_block_index_from_inode_index(fs_inode *inode, int32_t file_block_number) {
    uint32_t size = div_round_up(inode->size, BLOCK_SIZE);
    assert(file_block_number < size);
    if (file_block_number < N_DIRECT) {
        return inode->ptrs[file_block_number];
    } else if (file_block_number < (N_DIRECT + N_BLOCKS_IN_BLOCK)) {
        file_block_number -= N_DIRECT;
        assert(inode->indir_1);
        int32_t block_nums[N_BLOCKS_IN_BLOCK] = {0};
        assert(block_read(block_nums, inode->indir_1, 1) == 0);
        return block_nums[file_block_number - N_DIRECT];
    } else {
        file_block_number -= N_DIRECT + N_BLOCKS_IN_BLOCK;
        assert(inode->indir_2);
        int32_t block_nums[N_BLOCKS_IN_BLOCK] = {0};

        assert(block_read(block_nums, inode->indir_2, 1) == 0);
        int32_t block_num_id = block_nums[file_block_number / (N_BLOCKS_IN_BLOCK)];
        assert(block_read(block_nums, block_num_id, 1) == 0);
        return block_nums[file_block_number % (N_BLOCKS_IN_BLOCK)];
    }
}

fs_dirent find_next_dirent(fs_state *state, fs_inode *inode, char *name) {
    assert(S_ISDIR(inode->mode));
    fs_dirent dirents[N_DIRENTS_IN_BLOCK] = {0};
    for (int32_t i = 0; i < inode->size / BLOCK_SIZE; i++) {
        assert(block_read(dirents, get_block_index_from_inode_index(inode, i), 1) == 0);
        for (int j = 0; j < N_DIRENTS_IN_BLOCK; j++) {
            if (!dirents[j].valid) continue;
            if (!strcmp(name, dirents[j].name)) return dirents[j];
        }
    }
    dirents[0].valid = 0;
    return dirents[0];
}

int32_t find_inode(fs_state *state, const char *path) {
    // Root inode at index 1
    int32_t inode_idx = 1;
    fs_inode *inode = &state->inodes[inode_idx];
    char token[28] = {0};
    // For each directory, skip /
    dbg("Finding inode for %s\n", path);
    assert(*path == '/');
    while (*path && *++path) {
        memset(token, 0, 28);
        int i = 0;
        while (*path && *path != '/')
            token[i++] = *path++;
        // Break on 0 length token
        if (!*token) break;
        dbg("Token: %s\n", token);
        // Parse the inode's (dir?)entries and search for the current dir/file
        // Test for inode being a directory entry
        if (*path && !S_ISDIR(inode->mode)) return -ENOTDIR;
        fs_dirent next = find_next_dirent(state, inode, token);
        if (!next.valid) return -ENOENT;
        inode_idx = next.inode;
        // Inode number cannot be 0
        assert(inode_idx);
        inode = &state->inodes[inode_idx];
    }
    dbg("Found inode idx: %d\n", inode_idx);
    return inode_idx;
}

int lab3_getattr(const char *path, struct stat *sb, struct fuse_file_info *fi) {
    fs_state *state = fuse_get_context()->private_data;
    int32_t inode_idx = find_inode(state, path);
    assert(inode_idx);
    if (inode_idx < 0) return inode_idx;
    fs_inode *inode = &state->inodes[inode_idx];
    inode_2_stat(sb, inode);
    return 0;
}

int lab3_readdir(const char *path, void *ptr, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    fs_state *state = fuse_get_context()->private_data;
    int32_t inode_idx = find_inode(state, path);
    assert(inode_idx);
    if (inode_idx < 0) return inode_idx;
    fs_inode *inode = &state->inodes[inode_idx];
    if (!S_ISDIR(inode->mode)) return -ENOTDIR;

    fs_dirent dirents[N_DIRENTS_IN_BLOCK] = {0};
    for (int32_t i = 0; i < inode->size / BLOCK_SIZE; i++) {
        assert(block_read(dirents, get_block_index_from_inode_index(inode, i), 1) == 0);
        for (int j = 0; j < N_DIRENTS_IN_BLOCK; j++) {
            if (dirents[j].valid) filler(ptr, dirents[j].name, NULL, 0, 0);
        }
    }
    return 0;
}

int lab3_read(const char *path, char *buf, size_t len, off_t offset, struct fuse_file_info *fi) {
    fs_state *state = fuse_get_context()->private_data;
    int32_t inode_idx = find_inode(state, path);
    assert(inode_idx);
    if (inode_idx < 0) return inode_idx;
    fs_inode *inode = &state->inodes[inode_idx];
    if (!S_ISREG(inode->mode)) return S_ISDIR(inode->mode) ? -EISDIR : -EINVAL;

    int32_t block_offset = offset / BLOCK_SIZE;
    int32_t bytes_to_read = min(len, inode->size - offset);
    int32_t fill_index = 0;

    // First block
    int32_t bytes_to_copy_first_block = min(bytes_to_read, BLOCK_SIZE - (offset % BLOCK_SIZE));
    bytes_to_read -= bytes_to_copy_first_block;

    char *temp = calloc(BLOCK_SIZE, sizeof(char));
    block_read(temp, get_block_index_from_inode_index(inode, block_offset), 1);
    memcpy(buf + fill_index, temp + (offset % BLOCK_SIZE), bytes_to_copy_first_block);
    fill_index += bytes_to_copy_first_block;

    // Check if we are done
    assert(bytes_to_read >= 0);
    if (bytes_to_read == 0) {
        free(temp);
        return min(len, inode->size - offset);
    }

    // Not yet, iterate through whole blocks
    int32_t last_block_needed = block_offset + div_round_up(bytes_to_read, BLOCK_SIZE);
    for (int32_t block_num = block_offset + 1;
         block_num < last_block_needed;
         block_num++, fill_index += BLOCK_SIZE, bytes_to_read -= BLOCK_SIZE) {
        block_read(buf + fill_index, get_block_index_from_inode_index(inode, block_num), 1);
    }

    // Check if we are done
    assert(bytes_to_read >= 0);
    if (bytes_to_read == 0) {
        free(temp);
        return min(len, inode->size - offset);
    }

    // Not yet, last block has some data
    assert(bytes_to_read < BLOCK_SIZE);
    block_read(temp, get_block_index_from_inode_index(inode, last_block_needed), 1);
    memcpy(buf + fill_index, temp, bytes_to_read);

    free(temp);
    return min(len, inode->size - offset);
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
    .readdir = lab3_readdir,
    .read = lab3_read,

    //    .create = lab3_create,
    //    .mkdir = lab3_mkdir,
    //    .unlink = lab3_unlink,
    //    .rmdir = lab3_rmdir,
    //    .rename = lab3_rename,
    //    .chmod = lab3_chmod,
    //    .truncate = lab3_truncate,
    //    .write = lab3_write,
};

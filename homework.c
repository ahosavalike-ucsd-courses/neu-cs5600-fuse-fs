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
    int block = 1;
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
    // TODO: Flush state before cleanup?
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

int32_t set_block_index_to_inode_index(fs_inode *inode, int32_t file_block_number, int32_t block_idx) {
    uint32_t size = div_round_up(inode->size, BLOCK_SIZE);
    assert(file_block_number < size);
    if (file_block_number < N_DIRECT) {
        return inode->ptrs[file_block_number] = block_idx;
    } else if (file_block_number < (N_DIRECT + N_BLOCKS_IN_BLOCK)) {
        file_block_number -= N_DIRECT;
        assert(inode->indir_1);
        int32_t block_nums[N_BLOCKS_IN_BLOCK] = {0};
        assert(block_read(block_nums, inode->indir_1, 1) == 0);
        return block_nums[file_block_number - N_DIRECT] = block_idx;
    } else {
        file_block_number -= N_DIRECT + N_BLOCKS_IN_BLOCK;
        assert(inode->indir_2);
        int32_t block_nums[N_BLOCKS_IN_BLOCK] = {0};

        assert(block_read(block_nums, inode->indir_2, 1) == 0);
        int32_t block_num_id = block_nums[file_block_number / (N_BLOCKS_IN_BLOCK)];
        assert(block_read(block_nums, block_num_id, 1) == 0);
        return block_nums[file_block_number % (N_BLOCKS_IN_BLOCK)] = block_idx;
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

int32_t find_inode(fs_state *state, const char *path, bool ignore_last) {
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
        if (!next.valid) {
            if (ignore_last)
                break;
            else
                return -ENOENT;
        }
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
    int32_t inode_idx = find_inode(state, path, false);
    assert(inode_idx);
    if (inode_idx < 0) return inode_idx;
    fs_inode *inode = &state->inodes[inode_idx];
    inode_2_stat(sb, inode);
    return 0;
}

int lab3_readdir(const char *path, void *ptr, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    fs_state *state = fuse_get_context()->private_data;
    int32_t inode_idx = find_inode(state, path, false);
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
    int32_t inode_idx = find_inode(state, path, false);
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

// Returns valid 0-based index or -1 if not empty
int32_t find_free_bitmap_idx(unsigned char *bitmap, int32_t length_in_blocks, bool set) {
    for (int32_t i = 0; i < length_in_blocks * BLOCK_SIZE; i++)
        if (bitmap[i] != 0xff)  // Has free inode
            for (int8_t j = 0; j < 8; j++) {
                int32_t index = i * 8 + j;
                if (bit_test(bitmap, index) == 0) {
                    assert(index < length_in_blocks * BLOCK_SIZE * 8);
                    if (set) {
                        bit_set(bitmap, index);
                    }
                    return index;
                }
            }
    return -1;
}

int lab3_mkdir(const char *path, mode_t mode) {
    fs_state *state = fuse_get_context()->private_data;
    // Check if already exists
    int32_t exact_inode_idx = find_inode(state, path, false);
    assert(exact_inode_idx);
    if (exact_inode_idx > 0) return -EEXIST;

    // Find inode for path
    int32_t parent_inode_idx = find_inode(state, path, true);
    assert(parent_inode_idx);
    if (parent_inode_idx < 0) return parent_inode_idx;
    fs_inode *parent_inode = &state->inodes[parent_inode_idx];
    if (!S_ISDIR(parent_inode->mode)) return -ENOTDIR;

    // Find empty inode in map
    int32_t new_inode_idx = find_free_bitmap_idx(state->inode_bm, state->super.in_map_len, true);
    assert(new_inode_idx != -1);

    // Fill new inode
    fs_inode *new_inode = &state->inodes[new_inode_idx];
    memset(new_inode, 0, sizeof(fs_inode));

    new_inode->mtime = (unsigned)time(NULL);
    new_inode->mode = mode | __S_IFDIR;

    // Add it to parent inode as direntry
    fs_dirent dirents[N_DIRENTS_IN_BLOCK] = {0};
    int32_t free_dirents_block = -1, free_dirents_idx = -1;
    for (int32_t i = 0; i < parent_inode->size / BLOCK_SIZE; i++) {
        int32_t dirent_blk = get_block_index_from_inode_index(parent_inode, i);
        block_read(dirents, dirent_blk, 1);
        for (int32_t j = 0; j < N_DIRENTS_IN_BLOCK; j++) {
            if (!dirents[j].valid) {
                dbg("Found dirent_blk with free direntry: %d\n", dirent_blk);
                free_dirents_block = i;
                free_dirents_idx = j;
                goto exit_find_free_direntry;
            }
        }
    }
    exit_find_free_direntry:
    // If we could not find any existing free direntry, add a new block
    if (free_dirents_block == -1 || free_dirents_idx == -1) {
        // Always multiple of BLOCK_SIZE
        free_dirents_block = parent_inode->size / BLOCK_SIZE;
        parent_inode->size += BLOCK_SIZE;
        free_dirents_idx = 0;
        memset(dirents, 0, BLOCK_SIZE);
        // Allocate and set a free block
        int32_t block_idx = find_free_bitmap_idx(state->block_bm, state->super.blk_map_len, true);
        assert(block_idx != -1);
        set_block_index_to_inode_index(parent_inode, free_dirents_block, block_idx);
    }

    assert(dirents[free_dirents_idx].valid == 0);
    dirents[free_dirents_idx].valid = 1;
    dirents[free_dirents_idx].inode = new_inode_idx;
    strcpy(dirents[free_dirents_idx].name, strrchr(path, '/') + 1);

    // Write back direntry
    int32_t dirent_blk = get_block_index_from_inode_index(parent_inode, free_dirents_block);
    dbg("Writing to dirent_blk: %d\n", dirent_blk);
    block_write(dirents, dirent_blk, 1);

    // Write back state
    write_state(state);
    return 0;
}

int lab3_rmdir(const char *path) {
    fs_state *state = fuse_get_context()->private_data;

    int32_t to_rm_idx = find_inode(state, path, false);
    assert(to_rm_idx);
    if (to_rm_idx <= 0) return to_rm_idx;

    // Find parent inode
    char *ppath = calloc(strlen(path), 1);
    memcpy(ppath, path, strrchr(path, '/') - path + 1);
    int32_t parent_idx = find_inode(state, ppath, false);
    free(ppath);
    assert(parent_idx > 0);

    fs_inode *parent_inode = &state->inodes[parent_idx], *to_rm_inode = &state->inodes[to_rm_idx];

    // Check if directory is empty
    fs_dirent dirents[N_DIRENTS_IN_BLOCK] = {0};
    for (int32_t i = 0; i < to_rm_inode->size / BLOCK_SIZE; i++) {
        int32_t dirent_blk = get_block_index_from_inode_index(to_rm_inode, i);
        assert(block_read(dirents, dirent_blk, 1) == 0);
        for (int32_t j = 0; j < N_DIRENTS_IN_BLOCK; j++) {
            if (dirents[j].valid) {
                return -ENOTEMPTY;
            }
        }
        // Free the block
        bit_clear(state->block_bm, dirent_blk);
    }

    // Free the inode
    bit_clear(state->inode_bm, to_rm_idx);

    // Find direntry for the directory to be deleted
    for (int32_t i = 0; i < parent_inode->size / BLOCK_SIZE; i++) {
        int32_t dirent_blk = get_block_index_from_inode_index(parent_inode, i);
        assert(block_read(dirents, dirent_blk, 1) == 0);
        for (int32_t j = 0; j < N_DIRENTS_IN_BLOCK; j++) {
            if (dirents[j].valid && strcmp(dirents[j].name, strrchr(path, '/') + 1) == 0) {
                dbg("Found dirent_blk with direntry to free: %d\n", dirent_blk);
                dirents[j].valid = false;
                // Write back
                assert(block_write(dirents, dirent_blk, 1) == 0);
                return 0;
            }
        }
    }
    assert(false);
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
    .mkdir = lab3_mkdir,
    //    .unlink = lab3_unlink,
    .rmdir = lab3_rmdir,
    //    .rename = lab3_rename,
    //    .chmod = lab3_chmod,
    //    .truncate = lab3_truncate,
    //    .write = lab3_write,
};

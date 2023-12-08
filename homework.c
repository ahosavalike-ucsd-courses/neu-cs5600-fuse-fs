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

int32_t get_block_idx_from_inode_idx(fs_inode *inode, int32_t file_block_number) {
    uint32_t size = div_round_up(inode->size, BLOCK_SIZE);
    assert(file_block_number < size);
    if (file_block_number < N_DIRECT) {
        return inode->ptrs[file_block_number];
    }

    file_block_number -= N_DIRECT;
    if (file_block_number < N_BLOCKS_IN_BLOCK) {
        assert(inode->indir_1);
        int32_t block_ptrs[N_BLOCKS_IN_BLOCK] = {0};
        assert(block_read(block_ptrs, inode->indir_1, 1) == 0);
        return block_ptrs[file_block_number];
    }

    file_block_number -= N_BLOCKS_IN_BLOCK;
    assert(inode->indir_2);
    int32_t block_ptrs[N_BLOCKS_IN_BLOCK] = {0};

    assert(block_read(block_ptrs, inode->indir_2, 1) == 0);
    int32_t block_num_id = block_ptrs[file_block_number / N_BLOCKS_IN_BLOCK];
    assert(block_read(block_ptrs, block_num_id, 1) == 0);
    return block_ptrs[file_block_number % N_BLOCKS_IN_BLOCK];
}

int32_t set_block_index_to_inode_index(fs_inode *inode, int32_t file_block_number, int32_t block_idx) {
    uint32_t size = div_round_up(inode->size, BLOCK_SIZE);
    assert(file_block_number < size);
    if (file_block_number < N_DIRECT) {
        inode->ptrs[file_block_number] = block_idx;
        return block_idx;
    }

    file_block_number -= N_DIRECT;
    if (file_block_number < N_BLOCKS_IN_BLOCK) {
        assert(inode->indir_1);
        int32_t block_ptrs[N_BLOCKS_IN_BLOCK] = {0};
        assert(block_read(block_ptrs, inode->indir_1, 1) == 0);
        block_ptrs[file_block_number] = block_idx;
        assert(block_write(block_ptrs, inode->indir_1, 1) == 0);
        return block_idx;
    }

    file_block_number -= N_BLOCKS_IN_BLOCK;
    assert(inode->indir_2);
    int32_t block_ptrs[N_BLOCKS_IN_BLOCK] = {0};

    assert(block_read(block_ptrs, inode->indir_2, 1) == 0);
    int32_t block_num_id = block_ptrs[file_block_number / N_BLOCKS_IN_BLOCK];
    assert(block_read(block_ptrs, block_num_id, 1) == 0);
    block_ptrs[file_block_number % N_BLOCKS_IN_BLOCK] = block_idx;
    assert(block_write(block_ptrs, block_num_id, 1) == 0);
    return block_idx;
}

fs_dirent find_valid_dirent_by_name(fs_state *state, fs_inode *inode, char *name) {
    assert(S_ISDIR(inode->mode));
    fs_dirent dirents[N_DIRENTS_IN_BLOCK] = {0};
    for (int32_t i = 0; i < inode->size / BLOCK_SIZE; i++) {
        assert(block_read(dirents, get_block_idx_from_inode_idx(inode, i), 1) == 0);
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
        fs_dirent next = find_valid_dirent_by_name(state, inode, token);
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

// Returns valid 0-based index or -1 if not empty
int32_t find_free_bitmap_idx(unsigned char *bitmap, int32_t length_in_blocks, int32_t max_blocks, bool set) {
    for (int32_t i = 0; i < length_in_blocks * BLOCK_SIZE; i++)
        if (bitmap[i] != 0xff)  // Has free inode
            for (int8_t j = 0; j < 8; j++) {
                int32_t index = i * 8 + j;
                if (bit_test(bitmap, index) == 0) {
                    assert(index < length_in_blocks * BLOCK_SIZE * 8);
                    if (index >= max_blocks) return -1;
                    if (set) {
                        bit_set(bitmap, index);
                    }
                    return index;
                }
            }
    return -1;
}

int32_t find_free_block_bitmap_idx(fs_state *state, bool set) {
    return find_free_bitmap_idx(state->block_bm, state->super.blk_map_len, state->super.disk_size, set);
}

int32_t find_free_inode_bitmap_idx(fs_state *state, bool set) {
    return find_free_bitmap_idx(state->inode_bm, state->super.in_map_len, state->super.inodes_len, set);
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
        assert(block_read(dirents, get_block_idx_from_inode_idx(inode, i), 1) == 0);
        for (int j = 0; j < N_DIRENTS_IN_BLOCK; j++) {
            if (dirents[j].valid) filler(ptr, dirents[j].name, NULL, 0, 0);
        }
    }
    return 0;
}

int lab3_read_write(fs_state *state, const char *path, char *buf, size_t len, off_t offset, bool write) {
    int32_t inode_idx = find_inode(state, path, false);
    assert(inode_idx);
    if (inode_idx < 0) return inode_idx;
    fs_inode *inode = &state->inodes[inode_idx];
    if (!S_ISREG(inode->mode)) return S_ISDIR(inode->mode) ? -EISDIR : -EINVAL;

    if (offset > inode->size) return -EINVAL;

    int32_t block_offset = offset / BLOCK_SIZE;
    int32_t bytes_to_rw = write ? len : min(len, inode->size - offset);
    int32_t fill_index = 0;

    // First block
    int32_t bytes_to_copy_first_block = min(bytes_to_rw, BLOCK_SIZE - (offset % BLOCK_SIZE));
    bytes_to_rw -= bytes_to_copy_first_block;
    int32_t last_block_needed = div_round_up(offset + bytes_to_rw, BLOCK_SIZE);

    if (write) {
        // Allocate needed extra blocks and increase size
        int32_t last_block_have = div_round_up(inode->size, BLOCK_SIZE) - 1;
        inode->size = max(inode->size, offset + len);

        // Allocate new indir1
        if (last_block_have < N_DIRECT && last_block_needed >= N_DIRECT) {
            int32_t block_idx = find_free_block_bitmap_idx(state, true);
            if (block_idx == -1) return -ENOSPC;
            inode->indir_1 = block_idx;
            dbg("============> Allocate new indir1\n");
        }

        // Allocate new indir2
        if (last_block_have < N_DIRECT + N_BLOCKS_IN_BLOCK && last_block_needed >= N_DIRECT + N_BLOCKS_IN_BLOCK) {
            int32_t block_idx = find_free_block_bitmap_idx(state, true);
            if (block_idx == -1) return -ENOSPC;
            inode->indir_2 = block_idx;
            // Clear the pointers
            int32_t ptrs[N_BLOCKS_IN_BLOCK] = {0};
            block_write(ptrs, inode->indir_2, 1);
            dbg("============> Allocate new indir2\n");
        }

        // Allocate new indir2 ptrs
        int32_t needed_blocks_block = div_round_up((last_block_needed - N_DIRECT - N_BLOCKS_IN_BLOCK), N_BLOCKS_IN_BLOCK);
        int32_t have_blocks_block = max(div_round_up((last_block_have - N_DIRECT - N_BLOCKS_IN_BLOCK), N_BLOCKS_IN_BLOCK), 0);
        if (have_blocks_block < needed_blocks_block) {
            int32_t ptrs[N_BLOCKS_IN_BLOCK] = {0};
            block_read(ptrs, inode->indir_2, 1);
            for (int32_t i = have_blocks_block; i < needed_blocks_block; i++) {
                int32_t block_idx = find_free_block_bitmap_idx(state, true);
                if (block_idx == -1) return -ENOSPC;
                ptrs[i] = block_idx;
            }
            dbg("============> Allocate %d new indir2 ptrs\n", needed_blocks_block - have_blocks_block);
            block_write(ptrs, inode->indir_2, 1);
        }

        for (int32_t i = last_block_have + 1; i <= last_block_needed; i++) {
            int32_t block_idx = find_free_block_bitmap_idx(state, true);
            if (block_idx == -1) return -ENOSPC;
            set_block_index_to_inode_index(inode, i, block_idx);
            dbg("new block: %d\n", block_idx);
        }
        dbg("============> Allocate %d new data blocks\n", last_block_needed - last_block_have);

        write_state(state);
    }

    char *temp = calloc(BLOCK_SIZE, sizeof(char));
    block_read(temp, get_block_idx_from_inode_idx(inode, block_offset), 1);
    if (write) {
        memcpy(temp + (offset % BLOCK_SIZE), buf + fill_index, bytes_to_copy_first_block);
        block_write(temp, get_block_idx_from_inode_idx(inode, block_offset), 1);
    } else {
        memcpy(buf + fill_index, temp + (offset % BLOCK_SIZE), bytes_to_copy_first_block);
    }
    
    fill_index += bytes_to_copy_first_block;

    // Check if we are done
    assert(bytes_to_rw >= 0);
    if (bytes_to_rw == 0) {
        free(temp);
        return min(len, inode->size - offset);
    }

    // Not yet, iterate through whole blocks

    for (int32_t block_num = block_offset + 1;
         block_num <= last_block_needed && bytes_to_rw >= BLOCK_SIZE;
         block_num++, fill_index += BLOCK_SIZE, bytes_to_rw -= BLOCK_SIZE) {
        if (write) {
            block_write(buf + fill_index, get_block_idx_from_inode_idx(inode, block_num), 1);
        } else {
            block_read(buf + fill_index, get_block_idx_from_inode_idx(inode, block_num), 1);
        }
    }

    // Check if we are done
    assert(bytes_to_rw >= 0);
    if (bytes_to_rw == 0) {
        free(temp);
        return min(len, inode->size - offset);
    }

    // Not yet, last block has some data
    assert(bytes_to_rw < BLOCK_SIZE);
    if (write) {
        memcpy(temp, buf + fill_index, bytes_to_rw);
        block_write(temp, get_block_idx_from_inode_idx(inode, last_block_needed), 1);
    } else {
        block_read(temp, get_block_idx_from_inode_idx(inode, last_block_needed), 1);
        memcpy(buf + fill_index, temp, bytes_to_rw);
    }
    

    free(temp);
    return min(len, inode->size - offset);
}

int lab3_read(const char *path, char *buf, size_t len, off_t offset, struct fuse_file_info *fi) {
    return lab3_read_write(fuse_get_context()->private_data, path, buf, len, offset, false);
}

int lab3_write (const char *path, const char *buf, size_t len, off_t offset, struct fuse_file_info *fi) {
    return lab3_read_write(fuse_get_context()->private_data, path, (char*) buf, len, offset, true);
}

int32_t find_dirent_idx_and_operate(fs_state *state, fs_inode *inode, bool valid, const char *name, bool clear_blocks) {
    fs_dirent dirents[N_DIRENTS_IN_BLOCK] = {0};
    for (int32_t i = 0; i < inode->size / BLOCK_SIZE; i++) {
        int32_t dirent_blk = get_block_idx_from_inode_idx(inode, i);
        block_read(dirents, dirent_blk, 1);
        for (int32_t j = 0; j < N_DIRENTS_IN_BLOCK; j++) {
            if (dirents[j].valid == valid) {
                if (name && strcmp(dirents[j].name, name) != 0) continue;
                return i * N_DIRENTS_IN_BLOCK + j;
            }
        }
        if (clear_blocks) {
            assert(state);
            bit_clear(state->block_bm, dirent_blk);
        }
    }
    return -1;
}

int32_t find_free_dirent_idx(fs_state *state, fs_inode *inode) {
    int32_t free_dirent_idx = find_dirent_idx_and_operate(NULL, inode, false, NULL, false);
    // If we could not find any existing free direntry, add a new block
    if (free_dirent_idx == -1) {
        // Always multiple of BLOCK_SIZE
        free_dirent_idx = inode->size / BLOCK_SIZE;
        inode->size += BLOCK_SIZE;
        // Allocate and set a free block
        int32_t block_idx = find_free_block_bitmap_idx(state, true);
        if (block_idx == -1) return -ENOSPC;
        set_block_index_to_inode_index(inode, free_dirent_idx, block_idx);
    }
    return free_dirent_idx;
}

int32_t find_valid_dirent_idx_by_name(fs_inode *inode, char *name) {
    return find_dirent_idx_and_operate(NULL, inode, true, name, false);
}

int32_t free_all_dirents(fs_state *state, fs_inode *inode) {
    int32_t idx = find_dirent_idx_and_operate(state, inode, true, NULL, true);
    if (idx != -1) return -ENOTEMPTY;
    return 0;
}

void free_all_blocks(fs_state *state, fs_inode *inode) {
    int32_t blocks = div_round_up(inode->size, BLOCK_SIZE);
    for (int32_t i = 0; i < blocks; i++) {
        int32_t block_idx = get_block_idx_from_inode_idx(inode, i);
        bit_clear(state->block_bm, block_idx);
    }
    if (blocks > N_DIRECT) bit_clear(state->block_bm, inode->indir_1);
    if (blocks > N_DIRECT + N_BLOCKS_IN_BLOCK) {
        int32_t ptrs[N_BLOCKS_IN_BLOCK];
        block_read(ptrs, inode->indir_2, 1);
        for (int32_t i = 0; i < blocks - N_DIRECT - N_BLOCKS_IN_BLOCK; i++)
            bit_clear(state->block_bm, ptrs[i]);
        bit_clear(state->block_bm, inode->indir_2);
    }
}

int lab3_create_entry(fs_state *state, const char *path, mode_t mode) {
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
    int32_t new_inode_idx = find_free_inode_bitmap_idx(state, true);
    if (new_inode_idx == -1) return -ENOSPC;

    // Fill new inode
    fs_inode *new_inode = &state->inodes[new_inode_idx];
    memset(new_inode, 0, sizeof(fs_inode));

    new_inode->mtime = (unsigned)time(NULL);
    new_inode->mode = mode;

    // Add it to parent inode
    int32_t free_dirent_idx = find_free_dirent_idx(state, parent_inode);

    // Load direntry
    fs_dirent dirents[N_DIRENTS_IN_BLOCK] = {0};
    int32_t dirent_blk_idx = get_block_idx_from_inode_idx(parent_inode, free_dirent_idx / N_DIRENTS_IN_BLOCK);
    block_read(dirents, dirent_blk_idx, 1);

    // Modify direntry
    int32_t free_dirent_local_idx = free_dirent_idx % N_BLOCKS_IN_BLOCK;
    assert(dirents[free_dirent_local_idx].valid == 0);
    dirents[free_dirent_local_idx].valid = 1;
    dirents[free_dirent_local_idx].inode = new_inode_idx;
    strcpy(dirents[free_dirent_local_idx].name, strrchr(path, '/') + 1);

    // Write back direntry
    block_write(dirents, dirent_blk_idx, 1);

    // Write back state
    write_state(state);
    return 0;
}

int lab3_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    return lab3_create_entry(fuse_get_context()->private_data, path, mode | __S_IFREG);
}

int lab3_mkdir(const char *path, mode_t mode) {
    return lab3_create_entry(fuse_get_context()->private_data, path, mode | __S_IFDIR);
}

int lab3_remove_entry(fs_state *state, const char* path, bool isdir) {
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

    if (isdir) {
        // Check if directory is empty
        int32_t err = free_all_dirents(state, to_rm_inode);
        if (err) return err;
    } else {
        // Free all blocks
        free_all_blocks(state, to_rm_inode);
    }

    // Free the inode
    bit_clear(state->inode_bm, to_rm_idx);

    // Find direntry for the entry to be deleted and set it as invalid
    fs_dirent dirents[N_DIRENTS_IN_BLOCK] = {0};
    int32_t dirent_idx = find_valid_dirent_idx_by_name(parent_inode, strrchr(path, '/') + 1);
    int32_t dirent_blk_idx = get_block_idx_from_inode_idx(parent_inode, dirent_idx / N_DIRENTS_IN_BLOCK);
    int32_t dirent_local_idx = dirent_idx % N_DIRENTS_IN_BLOCK;
    block_read(dirents, dirent_blk_idx, 1);
    dirents[dirent_local_idx].valid = 0;
    block_write(dirents, dirent_blk_idx, 1);

    // Write back state
    write_state(state);
    return 0;
}

int lab3_rmdir(const char *path) {
    return lab3_remove_entry(fuse_get_context()->private_data, path, true);
}

int lab3_unlink(const char *path) {
    return lab3_remove_entry(fuse_get_context()->private_data, path, false);
}

int lab3_rename(const char *src_path, const char *dst_path, unsigned int flags) {
    fs_state *state = fuse_get_context()->private_data;

    dbg("Renaming %s to %s\n", src_path, dst_path);

    if (strcmp(src_path, dst_path) == 0) return 0;
    // Check if in same path
    const char *s = src_path, *d = dst_path;
    while (*s && *d && (*s++ == *d++));
    // Parent path different, cannot rename
    if (s <= strrchr(src_path, '/') || d <= strrchr(dst_path, '/')) return -EINVAL;

    // Delete destination if it exists
    int32_t dst_idx = find_inode(state, dst_path, false);
    assert(dst_idx);
    if (dst_idx > 0) {
        fs_inode *dst = &state->inodes[dst_idx];
        int32_t err = lab3_remove_entry(state, dst_path, S_ISDIR(dst->mode));
        // Destination is a non empty directory
        if (err < 0) return err;
    }

    // Make sure source exists
    int32_t src_idx = find_inode(state, src_path, false);
    assert(src_idx);
    if (src_idx < 0) return src_idx;

    char *src_file_name = strrchr(src_path, '/') + 1;
    assert(strlen(src_file_name) < 28);
    char *dst_file_name = strrchr(dst_path, '/') + 1;
    if (strlen(dst_file_name) >= 28) return -EINVAL;

    // Find parent inode
    char *ppath = calloc(strlen(src_path), 1);
    memcpy(ppath, src_path, src_file_name - src_path);
    int32_t parent_idx = find_inode(state, ppath, false);
    free(ppath);
    assert(parent_idx);
    if (parent_idx < 0) return parent_idx;
    fs_inode *parent_inode = &state->inodes[parent_idx];

    // Find source's direntry
    fs_dirent dirents[N_DIRENTS_IN_BLOCK] = {0};
    int32_t dirent_idx = find_valid_dirent_idx_by_name(parent_inode, src_file_name);
    int32_t dirent_blk_idx = get_block_idx_from_inode_idx(parent_inode, dirent_idx / N_DIRENTS_IN_BLOCK);
    int32_t dirent_local_idx = dirent_idx % N_DIRENTS_IN_BLOCK;
    block_read(dirents, dirent_blk_idx, 1);

    // Rename and write back
    strcpy(dirents[dirent_local_idx].name, dst_file_name);
    block_write(dirents, dirent_blk_idx, 1);
    return 0;
}

int lab3_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    fs_state *state = fuse_get_context()->private_data;

    int32_t idx = find_inode(state, path, false);
    assert(idx);
    if (idx < 0) return idx;

    fs_inode *inode = &state->inodes[idx];
    inode->mode = (inode->mode & __S_IFMT) | mode;
    write_state(state);
    return 0;
}

int lab3_truncate(const char *path, off_t new_len, struct fuse_file_info *fi) {
    fs_state *state = fuse_get_context()->private_data;

    if(new_len != 0) return -EINVAL;

    int32_t to_truncate_idx = find_inode(state, path, false);
    assert(to_truncate_idx);
    if (to_truncate_idx <= 0) return to_truncate_idx;

    fs_inode *to_truncate_inode = &state->inodes[to_truncate_idx];
    free_all_blocks(state, to_truncate_inode);
    to_truncate_inode->size = 0;
    memset(to_truncate_inode->ptrs, 0, N_DIRECT * sizeof(int32_t));
    to_truncate_inode->indir_1 = to_truncate_inode->indir_2 = 0;

    // Write back
    write_state(state);
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
    .readdir = lab3_readdir,
    .read = lab3_read,

    .create = lab3_create,
    .mkdir = lab3_mkdir,
    .unlink = lab3_unlink,
    .rmdir = lab3_rmdir,
    .rename = lab3_rename,
    .chmod = lab3_chmod,
    .truncate = lab3_truncate,
    .write = lab3_write,
};

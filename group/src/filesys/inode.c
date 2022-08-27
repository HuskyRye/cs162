#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define DIRECT_BLOCK_COUNT 122
#define INDIRECT_BLOCK_COUNT 128

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  bool is_dir;                               /* Is directory or not. */
  off_t length;                              /* File size in bytes. */
  block_sector_t parent;                     /* Parent sector number. */
  unsigned magic;                            /* Magic number. */
  block_sector_t direct[DIRECT_BLOCK_COUNT]; /* Direct blocks. */
  block_sector_t single_indirect;            /* Single indirect blocks. */
  block_sector_t double_indirect;            /* Double indirect blocks. */
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem; /* Element in inode list. */
  block_sector_t sector; /* Sector number of disk location. */
  int open_cnt;          /* Number of openers. */
  bool removed;          /* True if deleted, false otherwise. */
  int deny_write_cnt;    /* 0: writes ok, >0: deny writes. */
};

/* Returns the block device sector indexed at SECTOR_INDEX within INODE_SECTOR.
   Caller ensures that INODE_SECTOR contains an inode and the required sector exists. */
static block_sector_t index_to_sector(block_sector_t inode_sector, size_t sector_index) {
  block_sector_t sector;
  if (sector_index < DIRECT_BLOCK_COUNT) {
    buffer_cache_read(inode_sector, &sector,
                      offsetof(struct inode_disk, direct) + sector_index * sizeof(block_sector_t),
                      sizeof(block_sector_t));
  } else if (sector_index < DIRECT_BLOCK_COUNT + INDIRECT_BLOCK_COUNT) {
    block_sector_t single_indirect;
    buffer_cache_read(inode_sector, &single_indirect, offsetof(struct inode_disk, single_indirect),
                      sizeof(block_sector_t));
    buffer_cache_read(single_indirect, &sector,
                      (sector_index - DIRECT_BLOCK_COUNT) * sizeof(block_sector_t),
                      sizeof(block_sector_t));
  } else {
    block_sector_t double_indirect;
    buffer_cache_read(inode_sector, &double_indirect, offsetof(struct inode_disk, double_indirect),
                      sizeof(block_sector_t));
    sector_index = sector_index - DIRECT_BLOCK_COUNT - INDIRECT_BLOCK_COUNT;
    block_sector_t single_indirect;
    buffer_cache_read(double_indirect, &single_indirect,
                      (sector_index / INDIRECT_BLOCK_COUNT) * sizeof(block_sector_t),
                      sizeof(block_sector_t));
    buffer_cache_read(single_indirect, &sector,
                      (sector_index % INDIRECT_BLOCK_COUNT) * sizeof(block_sector_t),
                      sizeof(block_sector_t));
  }
  return sector;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  if (pos < inode_length(inode)) {
    int sector_index = pos / BLOCK_SECTOR_SIZE;
    return index_to_sector(inode->sector, sector_index);
  } else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
struct lock inodes_lock;

/* Initializes the inode module. */
void inode_init(void) {
  list_init(&open_inodes);
  lock_init(&inodes_lock);
}

/* Allocates sectors and stores them at index START to END in sector INDIRECT.
   Returns number of sectors successfully allocated. */
static size_t free_map_allocate_indirect(block_sector_t indirect, size_t start, size_t end) {
  size_t i;
  for (i = start; i < end; ++i) {
    block_sector_t sector;
    if (!free_map_allocate(1, &sector))
      break;
    buffer_cache_write(indirect, &sector, i * sizeof(block_sector_t), sizeof(block_sector_t));
  }
  return i - start;
}

/* Releases sectors stores at index START to END in sector INDIRECT. */
static void free_map_release_indirect(block_sector_t indirect, size_t start, size_t end) {
  for (size_t i = start; i < end; ++i) {
    block_sector_t sector;
    buffer_cache_read(indirect, &sector, i * sizeof(block_sector_t), sizeof(block_sector_t));
    free_map_release(sector, 1);
  }
}

/* Allocates data sectors and stores them at index START to end in inode within INODE_SECTOR.
   Caller ensures that inode index structure exists.
   Returns number of sectors successfully allocated. */
static size_t inode_allocate(block_sector_t inode_sector, size_t start, size_t end) {
  size_t i = start;
  while (i < end) {
    if (i < DIRECT_BLOCK_COUNT) {
      block_sector_t sector;
      if (!free_map_allocate(1, &sector)) {
        break;
      }
      buffer_cache_write(inode_sector, &sector,
                         offsetof(struct inode_disk, direct) + i * sizeof(block_sector_t),
                         sizeof(block_sector_t));
      ++i;
    } else {
      size_t indirect_offset =
          i < DIRECT_BLOCK_COUNT + INDIRECT_BLOCK_COUNT
              ? (i - DIRECT_BLOCK_COUNT)
              : (i - DIRECT_BLOCK_COUNT - INDIRECT_BLOCK_COUNT) % INDIRECT_BLOCK_COUNT;
      size_t sectors_left = end - i;
      size_t indirect_left = INDIRECT_BLOCK_COUNT - indirect_offset;
      size_t to_allocate = sectors_left < indirect_left ? sectors_left : indirect_left;
      block_sector_t single_indirect;
      if (i < DIRECT_BLOCK_COUNT + INDIRECT_BLOCK_COUNT) {
        buffer_cache_read(inode_sector, &single_indirect,
                          offsetof(struct inode_disk, single_indirect), sizeof(block_sector_t));
      } else {
        block_sector_t double_indirect;
        buffer_cache_read(inode_sector, &double_indirect,
                          offsetof(struct inode_disk, double_indirect), sizeof(block_sector_t));
        buffer_cache_read(double_indirect, &single_indirect,
                          ((i - DIRECT_BLOCK_COUNT - INDIRECT_BLOCK_COUNT) / INDIRECT_BLOCK_COUNT) *
                              sizeof(block_sector_t),
                          sizeof(block_sector_t));
      }
      size_t allocated = free_map_allocate_indirect(single_indirect, indirect_offset,
                                                    indirect_offset + to_allocate);
      i += allocated;
      if (allocated != to_allocate) {
        break;
      }
    }
  }
  return i;
}

static char zeros[BLOCK_SECTOR_SIZE];

/* Returns the length, in bytes, of inode within INODE_SECTOR.
   Caller ensures that INODE_SECTOR contains an inode. */
static off_t inode_sector_length(block_sector_t inode_sector) {
  off_t length;
  buffer_cache_read(inode_sector, &length, offsetof(struct inode_disk, length), sizeof(off_t));
  return length;
}

/* Set the inode length, in bytes, of inode within INODE_SECTOR to LENGTH.
   Caller ensures that INODE_SECTOR contains an inode. */
static void inode_sector_set_length(block_sector_t inode_sector, off_t length) {
  buffer_cache_write(inode_sector, &length, offsetof(struct inode_disk, length), sizeof(off_t));
}

/* Extends inode length of inode within INODE_SECTOR to new_length,
   also extends inode index structure if necessary. 
   Caller ensures that INODE_SECTOR contains an inode.
   Returns true if successful. 
   Returns false if disk allocation fails, rollback to the previous state. */
static bool inode_extend(block_sector_t inode_sector, off_t new_length) {
  bool success = true;
  off_t old_length = inode_sector_length(inode_sector);
  if (new_length > old_length) {
    size_t old_sectors = bytes_to_sectors(old_length);
    size_t new_sectors = bytes_to_sectors(new_length);
    ASSERT(new_sectors <= 16384);
    if (new_sectors > old_sectors) { /* Needs to extend */
      bool single_indirect_allocated = false;
      block_sector_t single_indirect;
      bool double_indirect_allocated = false;
      block_sector_t double_indirect;
      size_t old_double_indirect_sectors =
          old_sectors < DIRECT_BLOCK_COUNT + INDIRECT_BLOCK_COUNT
              ? 0
              : DIV_ROUND_UP(old_sectors - DIRECT_BLOCK_COUNT - INDIRECT_BLOCK_COUNT,
                             INDIRECT_BLOCK_COUNT);
      size_t new_double_indirect_sectors = DIV_ROUND_UP(
          new_sectors - DIRECT_BLOCK_COUNT - INDIRECT_BLOCK_COUNT, INDIRECT_BLOCK_COUNT);

      if (old_sectors <= DIRECT_BLOCK_COUNT && new_sectors > DIRECT_BLOCK_COUNT) {
        /* Needs to extend single indirect structure sector. */
        success = free_map_allocate(1, &single_indirect);
        if (success) {
          single_indirect_allocated = true;
          buffer_cache_write(inode_sector, &single_indirect,
                             offsetof(struct inode_disk, single_indirect), sizeof(block_sector_t));
        }
      }

      if (success && old_sectors <= DIRECT_BLOCK_COUNT + INDIRECT_BLOCK_COUNT &&
          new_sectors > DIRECT_BLOCK_COUNT + INDIRECT_BLOCK_COUNT) {
        /* Needs to extend double indirect structure sector. */
        success = free_map_allocate(1, &double_indirect);
        if (success) {
          double_indirect_allocated = true;
          buffer_cache_write(inode_sector, &double_indirect,
                             offsetof(struct inode_disk, double_indirect), sizeof(block_sector_t));
        }
      }

      if (success && new_sectors > DIRECT_BLOCK_COUNT + INDIRECT_BLOCK_COUNT) {
        /* Needs to extend double indirect sectors */
        buffer_cache_read(inode_sector, &double_indirect,
                          offsetof(struct inode_disk, double_indirect), sizeof(block_sector_t));
        size_t indirect_allocated = free_map_allocate_indirect(
            double_indirect, old_double_indirect_sectors, new_double_indirect_sectors);
        success = (indirect_allocated == new_double_indirect_sectors - old_double_indirect_sectors);
        if (!success) {
          free_map_release_indirect(double_indirect, old_double_indirect_sectors,
                                    indirect_allocated);
        }
      }

      if (success) {
        /* Extends data sectors. */
        size_t end_sectors = inode_allocate(inode_sector, old_sectors, new_sectors);
        success = (end_sectors == new_sectors);
        if (!success) {
          for (size_t i = old_sectors; i < end_sectors; ++i) {
            block_sector_t data_sector = index_to_sector(inode_sector, i);
            free_map_release(data_sector, 1);
          }
        }
      }

      if (success) {
        /* Filled extended data sectors with zero */
        for (size_t i = old_sectors; i < new_sectors; ++i) {
          block_sector_t data_sector = index_to_sector(inode_sector, i);
          buffer_cache_write(data_sector, zeros, 0, BLOCK_SECTOR_SIZE);
        }
      } else {
        /* Rollback to a previous good state. */
        if (new_sectors > DIRECT_BLOCK_COUNT + INDIRECT_BLOCK_COUNT)
          free_map_release_indirect(double_indirect, old_double_indirect_sectors,
                                    new_double_indirect_sectors);
        if (double_indirect_allocated)
          free_map_release(double_indirect, 1);
        if (single_indirect_allocated)
          free_map_release(single_indirect, 1);
      }
    }
    if (success) {
      /* Update inode length. */
      inode_sector_set_length(inode_sector, new_length);
    }
  }
  return success;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, bool is_dir) {

  ASSERT(length >= 0);
  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof(struct inode_disk) == BLOCK_SECTOR_SIZE);

  /* Sets inode length to 0 and extends it. */
  buffer_cache_write(sector, zeros, 0, BLOCK_SECTOR_SIZE);
  buffer_cache_write(sector, &is_dir, offsetof(struct inode_disk, is_dir), sizeof(bool));
  inode_sector_set_length(sector, 0);
  unsigned magic = INODE_MAGIC;
  buffer_cache_write(sector, &magic, offsetof(struct inode_disk, magic), sizeof(unsigned));
  return inode_extend(sector, length);
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  lock_acquire(&inodes_lock);
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode->open_cnt++;
      lock_release(&inodes_lock);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_release(&inodes_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL) {
    lock_acquire(&inodes_lock);
    inode->open_cnt++;
    lock_release(&inodes_lock);
  }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  lock_acquire(&inodes_lock);
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);
    lock_release(&inodes_lock);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      size_t sectors = bytes_to_sectors(inode_length(inode));
      for (size_t i = 0; i < sectors; ++i) {
        block_sector_t data_sector = index_to_sector(inode->sector, i);
        free_map_release(data_sector, 1);
      }
      if (sectors > DIRECT_BLOCK_COUNT) {
        block_sector_t single_indirect;
        buffer_cache_read(inode->sector, &single_indirect,
                          offsetof(struct inode_disk, single_indirect), sizeof(block_sector_t));
        free_map_release(single_indirect, 1);
        if (sectors > DIRECT_BLOCK_COUNT + INDIRECT_BLOCK_COUNT) {
          size_t double_indirect_sectors =
              (sectors - DIRECT_BLOCK_COUNT - INDIRECT_BLOCK_COUNT - 1) / INDIRECT_BLOCK_COUNT + 1;
          block_sector_t double_indirect;
          buffer_cache_read(inode->sector, &double_indirect,
                            offsetof(struct inode_disk, double_indirect), sizeof(block_sector_t));
          free_map_release_indirect(double_indirect, 0, double_indirect_sectors);
          free_map_release(double_indirect, 1);
        }
      }
      free_map_release(inode->sector, 1);
    }
    free(inode);
  } else {
    lock_release(&inodes_lock);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    buffer_cache_read(sector_idx, buffer + bytes_read, sector_ofs, chunk_size);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if an error occurs. */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  /* Extend the inode if necessary. */
  if (!inode_extend(inode->sector, offset + size)) {
    return 0;
  }

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    buffer_cache_write(sector_idx, buffer + bytes_written, sector_ofs, chunk_size);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode_sector_length(inode->sector); }

bool is_dir(struct inode* inode) {
  bool result;
  buffer_cache_read(inode->sector, &result, offsetof(struct inode_disk, is_dir), sizeof(bool));
  return result;
}

bool inode_is_removed(struct inode* inode) { return inode->removed; }

void inode_set_parent(block_sector_t sector, block_sector_t parent) {
  buffer_cache_write(sector, &parent, offsetof(struct inode_disk, parent), sizeof(block_sector_t));
}

block_sector_t inode_get_parent(struct inode* inode) {
  block_sector_t parent;
  buffer_cache_read(inode->sector, &parent, offsetof(struct inode_disk, parent),
                    sizeof(block_sector_t));
  return parent;
}

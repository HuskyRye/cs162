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
#define DIRECT_BLOCK_COUNT 124
#define INDIRECT_BLOCK_COUNT 128

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  off_t length;                              /* File size in bytes. */
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

static size_t free_map_allocate_indirect(size_t sectors, block_sector_t indirect) {
  size_t i;
  for (i = 0; i < sectors; ++i) {
    block_sector_t sector;
    if (!free_map_allocate(1, &sector))
      break;
    buffer_cache_write(indirect, &sector, i * sizeof(block_sector_t), sizeof(block_sector_t));
  }
  return i;
}

static void free_map_release_indirect(block_sector_t indirect, size_t sectors) {
  for (size_t i = 0; i < sectors; ++i) {
    block_sector_t sector;
    buffer_cache_read(indirect, &sector, i * sizeof(block_sector_t), sizeof(block_sector_t));
    free_map_release(sector, 1);
  }
}

static size_t inode_allocate(struct inode_disk* disk_inode, size_t sectors) {
  size_t i = 0;
  while (i < sectors) {
    if (i < DIRECT_BLOCK_COUNT) {
      if (!free_map_allocate(1, &disk_inode->direct[i])) {
        break;
      }
      ++i;
    } else {
      ASSERT((i == DIRECT_BLOCK_COUNT) ||
             ((i - DIRECT_BLOCK_COUNT - INDIRECT_BLOCK_COUNT) % INDIRECT_BLOCK_COUNT == 0));
      size_t sectors_left = sectors - i;
      size_t to_allocate =
          sectors_left < INDIRECT_BLOCK_COUNT ? sectors_left : INDIRECT_BLOCK_COUNT;
      block_sector_t single_indirect;
      if (i == DIRECT_BLOCK_COUNT) {
        single_indirect = disk_inode->single_indirect;
      } else {
        buffer_cache_read(disk_inode->double_indirect, &single_indirect,
                          ((i - DIRECT_BLOCK_COUNT - INDIRECT_BLOCK_COUNT) / INDIRECT_BLOCK_COUNT) *
                              sizeof(block_sector_t),
                          sizeof(block_sector_t));
      }
      size_t allocated = free_map_allocate_indirect(to_allocate, single_indirect);
      i += allocated;
      if (allocated != to_allocate) {
        break;
      }
    }
  }
  return i;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;

  ASSERT(length >= 0);
  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  bool success = (disk_inode != NULL);
  if (success) {
    size_t sectors = bytes_to_sectors(length);
    size_t double_indirect_sectors =
        (sectors - DIRECT_BLOCK_COUNT - INDIRECT_BLOCK_COUNT - 1) / INDIRECT_BLOCK_COUNT + 1;
    ASSERT(sectors <= 16384);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    if (sectors > DIRECT_BLOCK_COUNT) {
      success = free_map_allocate(1, &disk_inode->single_indirect);
      if (success && sectors > DIRECT_BLOCK_COUNT + INDIRECT_BLOCK_COUNT) {
        success = free_map_allocate(1, &disk_inode->double_indirect);
        if (!success) {
          free_map_release(disk_inode->single_indirect, 1);
        } else {
          size_t double_indirect_allocated =
              free_map_allocate_indirect(double_indirect_sectors, disk_inode->double_indirect);
          success = (double_indirect_allocated == double_indirect_sectors);
          if (!success) {
            free_map_release_indirect(disk_inode->double_indirect, double_indirect_allocated);
            free_map_release(disk_inode->double_indirect, 1);
            free_map_release(disk_inode->single_indirect, 1);
          }
        }
      }
    }

    size_t sectors_allocated;
    if (success) {
      sectors_allocated = inode_allocate(disk_inode, sectors);
      success = (sectors_allocated == sectors);
    }
    if (success) {
      buffer_cache_write(sector, disk_inode, 0, BLOCK_SECTOR_SIZE);
      static char zeros[BLOCK_SECTOR_SIZE];
      for (size_t i = 0; i < sectors; ++i) {
        block_sector_t data_sector = index_to_sector(sector, i);
        buffer_cache_write(data_sector, zeros, 0, BLOCK_SECTOR_SIZE);
      }
    } else {
      for (size_t i = 0; i < sectors_allocated; ++i) {
        block_sector_t data_sector = index_to_sector(sector, i);
        free_map_release(data_sector, 1);
      }
      if (sectors > DIRECT_BLOCK_COUNT) {
        free_map_release(disk_inode->single_indirect, 1);
        if (sectors > DIRECT_BLOCK_COUNT + INDIRECT_BLOCK_COUNT) {
          free_map_release_indirect(disk_inode->double_indirect, double_indirect_sectors);
          free_map_release(disk_inode->double_indirect, 1);
        }
      }
    }
    free(disk_inode);
  }
  return success;
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
      inode_reopen(inode);
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
  if (inode != NULL)
    inode->open_cnt++;
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

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    lock_acquire(&inodes_lock);
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
          free_map_release_indirect(double_indirect, double_indirect_sectors);
          free_map_release(double_indirect, 1);
        }
      }
      free_map_release(inode->sector, 1);
    }
    free(inode);
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
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

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
off_t inode_length(const struct inode* inode) {
  off_t length;
  buffer_cache_read(inode->sector, &length, offsetof(struct inode_disk, length), sizeof(off_t));
  return length;
}

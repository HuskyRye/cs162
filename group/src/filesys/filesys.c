#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"
#include "userprog/process.h"
#include "filesys/inode.h"

/* Partition that contains the file system. */
struct block* fs_device;

/* Buffer Cache Entry */
struct BCE {
  bool valid;
  bool dirty;
  bool used;
  int active;
  int waiting;
  struct condition cond;
  block_sector_t sector;
};

#define BUFFER_CACHE_SIZE 64

static struct lock buffer_cache_lock;
static int buffer_cache_clock_head;
static struct BCE buffer_cache_entrys[BUFFER_CACHE_SIZE];

/* Buffer cache */
static uint8_t buffer_cache[BUFFER_CACHE_SIZE][BLOCK_SECTOR_SIZE];

static void buffer_cache_flush(void* aux UNUSED);

static void buffer_cache_init(void) {
  lock_init(&buffer_cache_lock);
  buffer_cache_clock_head = 0;
  for (int i = 0; i < BUFFER_CACHE_SIZE; ++i) {
    struct BCE* buffer_cache_entry = &buffer_cache_entrys[i];
    buffer_cache_entry->valid = false;
    cond_init(&buffer_cache_entry->cond);
  }
  // thread_create("buffer_cache_flush", PRI_DEFAULT, buffer_cache_flush, NULL);
}

static void buffer_cache_flush(void* aux UNUSED) {
  while (true) {
    timer_msleep(3000);
    lock_acquire(&buffer_cache_lock);
    for (int i = 0; i < BUFFER_CACHE_SIZE; ++i) {
      struct BCE* buffer_cache_entry = &buffer_cache_entrys[i];
      if (buffer_cache_entry->valid && buffer_cache_entry->dirty) {
        buffer_cache_entry->dirty = false;
        lock_release(&buffer_cache_lock);
        block_write(fs_device, buffer_cache_entry->sector, buffer_cache[i]);
        lock_acquire(&buffer_cache_lock);
      }
    }
    lock_release(&buffer_cache_lock);
  }
}

static int buffer_cache_acquire(block_sector_t sector, bool read) {
  lock_acquire(&buffer_cache_lock);

  // sector already in buffer
  for (int i = 0; i < BUFFER_CACHE_SIZE; ++i) {
    struct BCE* buffer_cache_entry = &buffer_cache_entrys[i];
    if (buffer_cache_entry->valid && buffer_cache_entry->sector == sector) {
      while (buffer_cache_entry->active) {
        ++buffer_cache_entry->waiting;
        cond_wait(&buffer_cache_entry->cond, &buffer_cache_lock);
        --buffer_cache_entry->waiting;
      }
      ++buffer_cache_entry->active;
      lock_release(&buffer_cache_lock);
      return i;
    }
  }

  // load sector into an invalid entry
  for (int i = 0; i < BUFFER_CACHE_SIZE; ++i) {
    struct BCE* buffer_cache_entry = &buffer_cache_entrys[i];
    if (!buffer_cache_entry->valid) {
      buffer_cache_entry->valid = true;
      buffer_cache_entry->dirty = false;
      buffer_cache_entry->active = 0;
      buffer_cache_entry->waiting = 0;
      buffer_cache_entry->sector = sector;
      ++buffer_cache_entry->active;
      lock_release(&buffer_cache_lock);
      if (read)
        block_read(fs_device, sector, buffer_cache[i]);
      return i;
    }
  }

  // evict an entry and load sector into that entry
  while (true) {
    struct BCE* buffer_cache_entry = &buffer_cache_entrys[buffer_cache_clock_head];
    if ((buffer_cache_entry->active + buffer_cache_entry->waiting) == 0) {
      if (buffer_cache_entry->used) {
        buffer_cache_entry->used = false;
      } else {
        block_sector_t evict_sector = buffer_cache_entry->sector;
        buffer_cache_entry->sector = sector;
        int entry = buffer_cache_clock_head;
        buffer_cache_clock_head = (buffer_cache_clock_head + 1) % BUFFER_CACHE_SIZE;
        ++buffer_cache_entry->active;
        lock_release(&buffer_cache_lock);
        if (buffer_cache_entry->dirty) {
          block_write(fs_device, evict_sector, buffer_cache[entry]);
          buffer_cache_entry->dirty = false;
        }
        if (read)
          block_read(fs_device, sector, buffer_cache[entry]);
        return entry;
      }
    }
    buffer_cache_clock_head = (buffer_cache_clock_head + 1) % BUFFER_CACHE_SIZE;
  }
}

static void buffer_cache_release(int entry) {
  struct BCE* buffer_cache_entry = &buffer_cache_entrys[entry];
  lock_acquire(&buffer_cache_lock);
  --buffer_cache_entry->active;
  if (buffer_cache_entry->waiting) {
    cond_signal(&buffer_cache_entry->cond, &buffer_cache_lock);
  } else {
    buffer_cache_entry->used = true;
  }
  lock_release(&buffer_cache_lock);
}

void buffer_cache_read(block_sector_t sector, void* buffer_, off_t sector_ofs, off_t size) {
  uint8_t* buffer = (uint8_t*)buffer_;
  int entry = buffer_cache_acquire(sector, true);
  memcpy(buffer, buffer_cache[entry] + sector_ofs, size);
  buffer_cache_release(entry);
}

void buffer_cache_write(block_sector_t sector, const void* buffer_, off_t sector_ofs, off_t size) {
  uint8_t* buffer = (uint8_t*)buffer_;
  off_t sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
  bool read = sector_ofs > 0 || size < sector_left;
  int entry = buffer_cache_acquire(sector, read);
  memcpy(buffer_cache[entry] + sector_ofs, buffer, size);
  buffer_cache_entrys[entry].dirty = true;
  buffer_cache_release(entry);
}

static void do_format(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();
  buffer_cache_init();

  if (format)
    do_format();

  free_map_open();

  thread_current()->pcb->curdir = dir_open_root();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
  free_map_close();
  for (int i = 0; i < BUFFER_CACHE_SIZE; ++i) {
    struct BCE* buffer_cache_entry = &buffer_cache_entrys[i];
    if (buffer_cache_entry->valid && buffer_cache_entry->dirty) {
      block_write(fs_device, buffer_cache_entry->sector, buffer_cache[i]);
    }
  }
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
  char file_name[NAME_MAX + 1];
  struct dir* dir;
  struct inode* inode;
  if (!path_resolve(name, file_name, &dir, &inode)) {
    return false;
  }
  if (inode != NULL) {
    inode_close(inode);
    dir_close(dir);
    return false;
  }
  block_sector_t inode_sector = 0;
  bool success = free_map_allocate(1, &inode_sector) &&
                 inode_create(inode_sector, initial_size, false) &&
                 dir_add(dir, file_name, inode_sector);
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  char file_name[NAME_MAX + 1];
  struct dir* dir;
  struct inode* inode;
  if (!path_resolve(name, file_name, &dir, &inode)) {
    return false;
  }
  dir_close(dir);
  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  char file_name[NAME_MAX + 1];
  struct dir* dir;
  struct inode* inode;
  if (!path_resolve(name, file_name, &dir, &inode)) {
    return false;
  }
  bool success = false;
  if (!is_dir(inode) || dir_empty(inode)) {
    success = dir_remove(dir, file_name);
  }
  inode_close(inode);
  dir_close(dir);
  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}

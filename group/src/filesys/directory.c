#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "filesys/free-map.h"
#include "threads/thread.h"
#include "userprog/process.h"

/* A directory. */
struct dir {
  struct inode* inode; /* Backing store. */
  off_t pos;           /* Current position. */
};

/* A single directory entry. */
struct dir_entry {
  block_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];     /* Null terminated file name. */
  bool in_use;                 /* In use or free? */
};

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool dir_create(block_sector_t sector, size_t entry_cnt) {
  return inode_create(sector, entry_cnt * sizeof(struct dir_entry), true);
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir* dir_open(struct inode* inode) {
  if (!is_dir(inode))
    return NULL;
  struct dir* dir = calloc(1, sizeof *dir);
  if (inode != NULL && dir != NULL) {
    dir->inode = inode;
    dir->pos = 0;
    return dir;
  } else {
    inode_close(inode);
    free(dir);
    return NULL;
  }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir* dir_open_root(void) {
  return dir_open(inode_open(ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir* dir_reopen(struct dir* dir) {
  return dir_open(inode_reopen(dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close(struct dir* dir) {
  if (dir != NULL) {
    inode_close(dir->inode);
    free(dir);
  }
}

/* Returns the inode encapsulated by DIR. */
struct inode* dir_get_inode(struct dir* dir) {
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool lookup(const struct dir* dir, const char* name, struct dir_entry* ep, off_t* ofsp) {
  struct dir_entry e;
  size_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (e.in_use && !strcmp(name, e.name)) {
      if (ep != NULL)
        *ep = e;
      if (ofsp != NULL)
        *ofsp = ofs;
      return true;
    }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_lookup(const struct dir* dir, const char* name, struct inode** inode) {
  struct dir_entry e;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  if (lookup(dir, name, &e, NULL))
    *inode = inode_open(e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add(struct dir* dir, const char* name, block_sector_t inode_sector) {
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen(name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup(dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy(e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool dir_remove(struct dir* dir, const char* name) {
  struct dir_entry e;
  struct inode* inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Find directory entry. */
  if (!lookup(dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open(e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at(dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove(inode);
  success = true;

done:
  inode_close(inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir(struct dir* dir, char name[NAME_MAX + 1]) {
  struct dir_entry e;

  while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
    dir->pos += sizeof e;
    if (e.in_use) {
      strlcpy(name, e.name, NAME_MAX + 1);
      return true;
    }
  }
  return false;
}

bool dir_empty(struct inode* inode) {
  struct dir_entry e;
  for (size_t ofs = 0; inode_read_at(inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e) {
    if (e.in_use) {
      return false;
    }
  }
  return true;
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

/* Resolves the path, sets FILE_NAME to the last part of path resolved,
   sets *DIR to the directory containing file or dir named FILE_NAME, and
   sets *INODE to the inode of file or dir named FILE_NAME.
   Returns true if successful, false if any dir name in PATH, besides the last, not exists. */
bool path_resolve(const char* path, char file_name[NAME_MAX + 1], struct dir** dir,
                  struct inode** inode_ptr) {
  if (*path == '\0') {
    return false;
  }
  struct dir* cur_dir = *path == '/' ? dir_open_root() : dir_reopen(thread_current()->pcb->curdir);
  if (inode_is_removed(cur_dir->inode)) {
    dir_close(cur_dir);
    return false;
  }
  struct inode* inode = inode_reopen(cur_dir->inode);

  while (get_next_part(file_name, &path)) {
    if (strcmp(file_name, ".") == 0) {
      continue;
    }
    if (inode == NULL) { /* File or Dir with previous file_name not exists. */
      dir_close(cur_dir);
      return false;
    }
    if (!is_dir(inode)) { /* Inode with previous file_name is not a dir. */
      inode_close(inode);
      dir_close(cur_dir);
      return false;
    }
    if (strcmp(file_name, "..") == 0) {
      inode_close(inode);
      inode = inode_open(inode_get_parent(inode));
    } else {
      struct dir* next_dir = dir_open(inode);
      dir_close(cur_dir);
      cur_dir = next_dir;
      dir_lookup(cur_dir, file_name, &inode);
    }
  }
  *dir = cur_dir;
  *inode_ptr = inode;
  return true;
}

bool sys_chdir(const char* path) {
  char dir_name[NAME_MAX + 1];
  struct dir* dir;
  struct inode* inode;
  if (!path_resolve(path, dir_name, &dir, &inode)) {
    return false;
  }
  dir_close(dir);
  if (inode == NULL) {
    return false;
  }
  dir = dir_open(inode);
  dir_close(thread_current()->pcb->curdir);
  thread_current()->pcb->curdir = dir;
  return true;
}

bool sys_mkdir(const char* path) {
  char dir_name[NAME_MAX + 1];
  struct dir* dir;
  struct inode* inode;
  if (!path_resolve(path, dir_name, &dir, &inode)) {
    return false;
  }

  if (inode != NULL) { /* File or Dir with name PART already exists. */
    inode_close(inode);
    dir_close(dir);
    return false;
  }
  /* Allocates sector, create dir on sector and add it to cur_dir. */
  block_sector_t inode_sector = 0;
  bool success = free_map_allocate(1, &inode_sector) && dir_create(inode_sector, 0) &&
                 dir_add(dir, dir_name, inode_sector);
  if (success) {
    inode_set_parent(inode_sector, inode_get_inumber(dir->inode));
  }
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);
  return success;
}

#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "lib/string.h"
#include "lib/float.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void verify_vaddr(void*, unsigned size);
static void verify_arg_vaddr(uint32_t* vaddr);
static void verify_string(const char* str);

static int sys_open(const char* file);
static int sys_read(int fd, void* buffer, unsigned size);
static int sys_write(int fd, const void* buffer, unsigned size);
static void sys_close(int fd);

static bool sys_lock_init(lock_t* lock);
static bool sys_lock_acquire(lock_t* lock);
static bool sys_lock_release(lock_t* lock);
static bool sys_sema_init(sema_t* sema, int val);
static bool sys_sema_down(sema_t* sema);
static bool sys_sema_up(sema_t* sema);

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  verify_arg_vaddr(args);

  struct process* cur = thread_current()->pcb;

  switch (args[0]) {
    case SYS_READ:
    case SYS_WRITE:
    case SYS_PT_CREATE:
      verify_arg_vaddr(&args[3]);
      FALLTHROUGH
    case SYS_CREATE:
    case SYS_SEEK:
    case SYS_SEMA_INIT:
    case SYS_READDIR:
      verify_arg_vaddr(&args[2]);
      FALLTHROUGH
    case SYS_EXIT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
    case SYS_PRACTICE:
    case SYS_COMPUTE_E:
    case SYS_PT_JOIN:
    case SYS_LOCK_INIT:
    case SYS_LOCK_ACQUIRE:
    case SYS_LOCK_RELEASE:
    case SYS_SEMA_DOWN:
    case SYS_SEMA_UP:
    case SYS_CHDIR:
    case SYS_MKDIR:
    case SYS_ISDIR:
    case SYS_INUMBER:
      verify_arg_vaddr(&args[1]);
      FALLTHROUGH
    case SYS_HALT:
    case SYS_PT_EXIT:
    case SYS_GET_TID:
    default:
      break;
  }

  switch (args[0]) {
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      exit(args[1]);
      break;
    case SYS_EXEC:
      verify_string((const char*)args[1]);
      f->eax = process_execute((const char*)args[1]);
      break;
    case SYS_WAIT:
      f->eax = process_wait(args[1]);
      break;
    case SYS_CREATE:
      verify_string((const char*)args[1]);
      f->eax = filesys_create((const char*)args[1], args[2]);
      break;
    case SYS_REMOVE:
      verify_string((const char*)args[1]);
      f->eax = filesys_remove((const char*)args[1]);
      break;
    case SYS_OPEN:
      verify_string((const char*)args[1]);
      f->eax = sys_open((const char*)args[1]);
      break;
    case SYS_FILESIZE: {
      struct file* fp = get_file((int)args[1]);
      f->eax = (fp == NULL ? -1 : file_length(fp));
      break;
    }
    case SYS_READ: {
      verify_vaddr((void*)args[2], args[3]);
      f->eax = sys_read((int)args[1], (void*)args[2], (unsigned)args[3]);
      break;
    }
    case SYS_WRITE:
      verify_vaddr((void*)args[2], args[3]);
      f->eax = sys_write((int)args[1], (const void*)args[2], (unsigned)args[3]);
      break;
    case SYS_SEEK: {
      struct file* fp = get_file(args[1]);
      if (fp != NULL)
        file_seek(fp, args[2]);
      break;
    }
    case SYS_TELL: {
      struct file* fp = get_file(args[1]);
      f->eax = (fp == NULL ? -1 : file_tell(fp));
      break;
    }
    case SYS_CLOSE:
      sys_close((int)args[1]);
      break;
    case SYS_PRACTICE:
      f->eax = args[1] + 1;
      break;
    case SYS_COMPUTE_E:
      f->eax = sys_sum_to_e(args[1]);
      break;
    case SYS_PT_CREATE:
      f->eax = pthread_execute((stub_fun)args[1], (pthread_fun)args[2], (void*)args[3]);
      break;
    case SYS_PT_EXIT:
      if (thread_current() == cur->main_thread) {
        exit(0);
      } else
        pthread_exit(f->esp);
      break;
    case SYS_PT_JOIN:
      f->eax = pthread_join(args[1]);
      break;
    case SYS_LOCK_INIT:
      f->eax = sys_lock_init((lock_t*)args[1]);
      break;
    case SYS_LOCK_ACQUIRE:
      f->eax = sys_lock_acquire((lock_t*)args[1]);
      break;
    case SYS_LOCK_RELEASE:
      f->eax = sys_lock_release((lock_t*)args[1]);
      break;
    case SYS_SEMA_INIT:
      f->eax = sys_sema_init((sema_t*)args[1], (int)args[2]);
      break;
    case SYS_SEMA_DOWN:
      f->eax = sys_sema_down((sema_t*)args[1]);
      break;
    case SYS_SEMA_UP:
      f->eax = sys_sema_up((sema_t*)args[1]);
      break;
    case SYS_GET_TID:
      f->eax = thread_current()->tid;
      break;
    case SYS_CHDIR:
      verify_string((const char*)args[1]);
      f->eax = sys_chdir((const char*)args[1]);
      break;
    case SYS_MKDIR:
      verify_string((const char*)args[1]);
      f->eax = sys_mkdir((const char*)args[1]);
      break;
    case SYS_READDIR: {
      verify_vaddr((void*)args[2], NAME_MAX + 1);
      struct file* fp = get_file((int)args[1]);
      f->eax = fp != NULL && dir_readdir(file_get_dir(fp), (char*)args[2]);
      break;
    }
    case SYS_ISDIR: {
      struct file* fp = get_file((int)args[1]);
      f->eax = file_get_dir(fp) != NULL;
      break;
    }
    case SYS_INUMBER: {
      struct file* fp = get_file((int)args[1]);
      if (fp == NULL) {
        f->eax = -1;
      } else {
        f->eax = inode_get_inumber(file_get_inode(fp));
      }
      break;
    }
    default:
      break;
  }
}

static inline bool valid_vaddr(uint8_t* vaddr) {
  uint32_t* pagedir = thread_current()->pcb->pagedir;
  return vaddr != NULL && is_user_vaddr(vaddr) && pagedir_get_page(pagedir, vaddr) != NULL;
}

static void verify_vaddr(void* vaddr, unsigned size) {
  uint8_t* p = (uint8_t*)vaddr;
  for (unsigned i = 0; i < size; ++i) {
    if (!valid_vaddr(p)) {
      exit(-1);
    }
    ++p;
  }
}

static void verify_arg_vaddr(uint32_t* vaddr) { verify_vaddr(vaddr, 4); }

static void verify_string(const char* str) {
  while (true) {
    if (!valid_vaddr((uint8_t*)str))
      exit(-1);
    if (*str == '\0')
      return;
    ++str;
  }
}

static int sys_open(const char* file) {
  struct file* fp = filesys_open(file);
  if (fp == NULL) {
    return -1;
  }
  struct file_info* file_info = malloc(sizeof(struct file_info));
  if (file_info == NULL) {
    file_close(fp);
    return -1;
  }
  struct process* cur = thread_current()->pcb;
  file_info->fp = fp;
  file_info->fd = (cur->fd)++;
  list_push_back(&(cur->files), &(file_info->elem));
  if (strcmp(file, cur->process_name) == 0) {
    file_deny_write(fp);
  }
  return file_info->fd;
}

static int sys_read(int fd, void* buffer, unsigned size) {
  switch (fd) {
    case STDIN_FILENO: {
      uint8_t* p = (uint8_t*)buffer;
      char c;
      for (unsigned i = 0; i < size; ++i) {
        *(p++) = c = input_getc();
        if (c == EOF) {
          return i;
        }
      }
      return size;
    }
    case STDOUT_FILENO:
      return -1;
    default: {
      struct file* fp = get_file(fd);
      return fp == NULL ? -1 : file_read(fp, buffer, size);
    }
  }
}

static int sys_write(int fd, const void* buffer, unsigned size) {
  switch (fd) {
    case STDIN_FILENO:
      return -1;
    case STDOUT_FILENO:
      // write to the console should write all of buffer in one call to the putbuf function
      putbuf(buffer, size);
      return size;
    default: {
      struct file* fp = get_file(fd);
      return fp == NULL ? -1 : file_write(fp, buffer, size);
    }
  }
}

static void sys_close(int fd) {
  struct list* files = &(thread_current()->pcb->files);
  for (struct list_elem* elem = list_begin(files); elem != list_end(files);
       elem = list_next(elem)) {
    struct file_info* info = list_entry(elem, struct file_info, elem);
    if (info->fd == fd) {
      file_close(info->fp);
      list_remove(elem);
      free(info);
      return;
    }
  }
}

static bool sys_lock_init(lock_t* lock) {
  if (lock == NULL) {
    return false;
  }
  verify_vaddr(lock, 1);
  struct lock_info* lock_info = malloc(sizeof(struct lock_info));
  if (lock_info == NULL) {
    return false;
  }
  struct process* cur = thread_current()->pcb;
  lock_init(&lock_info->lock);
  lock_info->ld = cur->ld;
  *lock = cur->ld;
  cur->ld += 1;
  list_push_back(&cur->locks, &lock_info->elem);
  return true;
}

static bool sys_lock_acquire(lock_t* lock) {
  if (lock == NULL) {
    return false;
  }
  verify_vaddr(lock, 1);
  struct process* cur = thread_current()->pcb;
  struct list_elem* e;
  for (e = list_begin(&cur->locks); e != list_end(&cur->locks); e = list_next(e)) {
    struct lock_info* lock_info = list_entry(e, struct lock_info, elem);
    if (lock_info->ld == *lock) {
      if (lock_held_by_current_thread(&lock_info->lock)) {
        return false;
      } else {
        lock_acquire(&lock_info->lock);
        return true;
      }
    }
  }
  return false;
}

static bool sys_lock_release(lock_t* lock) {
  if (lock == NULL) {
    return false;
  }
  verify_vaddr(lock, 1);
  struct process* cur = thread_current()->pcb;
  struct list_elem* e;
  for (e = list_begin(&cur->locks); e != list_end(&cur->locks); e = list_next(e)) {
    struct lock_info* lock_info = list_entry(e, struct lock_info, elem);
    if (lock_info->ld == *lock) {
      if (lock_held_by_current_thread(&lock_info->lock)) {
        lock_release(&lock_info->lock);
        return true;
      } else {
        return false;
      }
    }
  }
  return false;
}

static bool sys_sema_init(sema_t* sema, int val) {
  if (sema == NULL || val < 0) {
    return false;
  }
  verify_vaddr(sema, 1);
  struct sema_info* sema_info = malloc(sizeof(struct sema_info));
  if (sema_info == NULL) {
    return false;
  }
  struct process* cur = thread_current()->pcb;
  sema_init(&sema_info->sema, val);
  sema_info->sd = cur->sd;
  *sema = cur->sd;
  cur->sd += 1;
  list_push_back(&cur->semaphores, &sema_info->elem);
  return true;
}

static bool sys_sema_down(sema_t* sema) {
  if (sema == NULL) {
    return false;
  }
  verify_vaddr(sema, 1);
  struct process* cur = thread_current()->pcb;
  struct list_elem* e;
  for (e = list_begin(&cur->semaphores); e != list_end(&cur->semaphores); e = list_next(e)) {
    struct sema_info* sema_info = list_entry(e, struct sema_info, elem);
    if (sema_info->sd == *sema) {
      sema_down(&sema_info->sema);
      return true;
    }
  }
  return false;
}

static bool sys_sema_up(sema_t* sema) {
  if (sema == NULL) {
    return false;
  }
  verify_vaddr(sema, 1);
  struct process* cur = thread_current()->pcb;
  struct list_elem* e;
  for (e = list_begin(&cur->semaphores); e != list_end(&cur->semaphores); e = list_next(e)) {
    struct sema_info* sema_info = list_entry(e, struct sema_info, elem);
    if (sema_info->sd == *sema) {
      sema_up(&sema_info->sema);
      return true;
    }
  }
  return false;
}

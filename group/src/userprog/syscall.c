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

static void syscall_handler(struct intr_frame*);

struct lock file_syscalls_lock;
void syscall_init(void) {
  lock_init(&file_syscalls_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void verify_vaddr(void*, unsigned size);
static void verify_arg_vaddr(uint32_t* vaddr);
static void verify_string(const char* str);

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  verify_arg_vaddr(args);

  struct process* cur = thread_current()->pcb;

  switch (args[0]) {
    case SYS_READ:
    case SYS_WRITE:
    case SYS_PT_CREATE:
      verify_arg_vaddr(&args[3]);
    case SYS_CREATE:
    case SYS_SEEK:
    case SYS_SEMA_INIT:
      verify_arg_vaddr(&args[2]);
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
      verify_arg_vaddr(&args[1]);
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
      lock_acquire(&file_syscalls_lock);
      f->eax = process_execute((const char*)args[1]);
      lock_release(&file_syscalls_lock);
      break;
    case SYS_WAIT:
      f->eax = process_wait(args[1]);
      break;
    case SYS_CREATE:
      verify_string((const char*)args[1]);
      lock_acquire(&file_syscalls_lock);
      f->eax = filesys_create((const char*)args[1], args[2]);
      lock_release(&file_syscalls_lock);
      break;
    case SYS_REMOVE:
      verify_string((const char*)args[1]);
      lock_acquire(&file_syscalls_lock);
      f->eax = filesys_remove((const char*)args[1]);
      lock_release(&file_syscalls_lock);
      break;
    case SYS_OPEN: {
      verify_string((const char*)args[1]);
      lock_acquire(&file_syscalls_lock);
      struct file* fp = filesys_open((const char*)args[1]);
      if (fp == NULL) {
        f->eax = -1;
      } else {
        struct file_info* file_info = malloc(sizeof(struct file_info));
        file_info->fp = fp;
        f->eax = file_info->fd = (cur->fd)++;
        list_push_back(&(cur->files), &(file_info->elem));
        if (strcmp((const char*)args[1], cur->process_name) == 0) {
          file_deny_write(fp);
        }
      }
      lock_release(&file_syscalls_lock);
      break;
    }
    case SYS_FILESIZE: {
      lock_acquire(&file_syscalls_lock);
      struct file* fp = get_file(args[1]);
      f->eax = (fp == NULL ? -1 : file_length(fp));
      lock_release(&file_syscalls_lock);
      break;
    }
    case SYS_READ: {
      verify_vaddr((void*)args[2], args[3]);
      switch (args[1]) {
        case STDIN_FILENO: {
          uint8_t* p = (uint8_t*)args[2];
          char c;
          for (unsigned int i = 0; i < args[3]; ++i) {
            *(p++) = c = input_getc();
            if (c == EOF) {
              f->eax = i;
              break;
            }
          }
          f->eax = args[3];
          break;
        }
        case STDOUT_FILENO:
          f->eax = -1;
          break;
        default: {
          lock_acquire(&file_syscalls_lock);
          struct file* fp = get_file(args[1]);
          f->eax = (fp == NULL ? -1 : file_read(fp, (void*)args[2], args[3]));
          lock_release(&file_syscalls_lock);
          break;
        }
      }
      break;
    }
    case SYS_WRITE:
      verify_vaddr((void*)args[2], args[3]);
      switch (args[1]) {
        case STDIN_FILENO:
          f->eax = -1;
          break;
        case STDOUT_FILENO:
          // write to the console should write all of buffer in one call to the putbuf function
          putbuf((char*)args[2], args[3]);
          f->eax = args[3];
          break;
        default: {
          lock_acquire(&file_syscalls_lock);
          struct file* fp = get_file(args[1]);
          f->eax = (fp == NULL ? -1 : file_write(fp, (void*)args[2], args[3]));
          lock_release(&file_syscalls_lock);
          break;
        }
      }
      break;
    case SYS_SEEK: {
      lock_acquire(&file_syscalls_lock);
      struct file* fp = get_file(args[1]);
      if (fp != NULL) {
        file_seek(fp, args[2]);
      }
      lock_release(&file_syscalls_lock);
      break;
    }
    case SYS_TELL: {
      lock_acquire(&file_syscalls_lock);
      struct file* fp = get_file(args[1]);
      f->eax = (fp == NULL ? -1 : file_tell(fp));
      lock_release(&file_syscalls_lock);
      break;
    }
    case SYS_CLOSE: {
      lock_acquire(&file_syscalls_lock);
      struct list* files = &(thread_current()->pcb->files);
      for (struct list_elem* elem = list_begin(files); elem != list_end(files);
           elem = list_next(elem)) {
        struct file_info* info = list_entry(elem, struct file_info, elem);
        if (info->fd == (int)args[1]) {
          file_close(info->fp);
          list_remove(elem);
          free(info);
          break;
        }
      }
      lock_release(&file_syscalls_lock);
      break;
    }
    case SYS_PRACTICE:
      f->eax = args[1] + 1;
      break;
    case SYS_COMPUTE_E:
      f->eax = sys_sum_to_e(args[1]);
      break;
    case SYS_PT_CREATE: {
      f->eax = pthread_execute(args[1], args[2], args[3]);
      break;
    }
    case SYS_PT_EXIT: {
      if (thread_current() == cur->main_thread) {
        exit(0);
      } else
        pthread_exit(f->esp);
      break;
    }
    case SYS_PT_JOIN:
      f->eax = pthread_join(args[1]);
      break;
    case SYS_LOCK_INIT: {
      lock_t* lock = (lock_t*)args[1];
      if (lock == NULL) {
        f->eax = false;
        break;
      }
      verify_vaddr(lock, 1);
      struct lock_info* lock_info = malloc(sizeof(struct lock_info));
      if (lock_info == NULL) {
        f->eax = false;
      } else {
        lock_init(&lock_info->lock);
        lock_info->ld = cur->ld;
        *lock = cur->ld;
        cur->ld += 1;
        list_push_back(&cur->locks, &lock_info->elem);
        f->eax = true;
      }
      break;
    }
    case SYS_LOCK_ACQUIRE: {
      lock_t* lock = (lock_t*)args[1];
      if (lock == NULL) {
        f->eax = false;
        break;
      }
      verify_vaddr(lock, 1);
      f->eax = false;
      struct list_elem* e;
      for (e = list_begin(&cur->locks); e != list_end(&cur->locks); e = list_next(e)) {
        struct lock_info* lock_info = list_entry(e, struct lock_info, elem);
        if (lock_info->ld == *lock) {
          if (lock_held_by_current_thread(&lock_info->lock)) {
            f->eax = false;
          } else {
            lock_acquire(&lock_info->lock);
            f->eax = true;
          }
          break;
        }
      }
      break;
    }
    case SYS_LOCK_RELEASE: {
      lock_t* lock = (lock_t*)args[1];
      if (lock == NULL) {
        f->eax = false;
        break;
      }
      verify_vaddr(lock, 1);
      f->eax = false;
      struct list_elem* e;
      for (e = list_begin(&cur->locks); e != list_end(&cur->locks); e = list_next(e)) {
        struct lock_info* lock_info = list_entry(e, struct lock_info, elem);
        if (lock_info->ld == *lock) {
          if (lock_held_by_current_thread(&lock_info->lock)) {
            lock_release(&lock_info->lock);
            f->eax = true;
          } else {
            f->eax = false;
          }
          break;
        }
      }
      break;
    }
    case SYS_SEMA_INIT: {
      sema_t* sema = (sema_t*)args[1];
      if (sema == NULL || (int)args[2] < 0) {
        f->eax = false;
        break;
      }
      verify_vaddr(sema, 1);
      struct sema_info* sema_info = malloc(sizeof(struct sema_info));
      if (sema_info == NULL) {
        f->eax = false;
      } else {
        sema_init(&sema_info->sema, args[2]);
        sema_info->sd = cur->sd;
        *sema = cur->sd;
        cur->sd += 1;
        list_push_back(&cur->semaphores, &sema_info->elem);
        f->eax = true;
      }
      break;
    }
    case SYS_SEMA_DOWN: {
      sema_t* sema = (sema_t*)args[1];
      if (sema == NULL) {
        f->eax = false;
        break;
      }
      verify_vaddr(sema, 1);
      f->eax = false;
      struct list_elem* e;
      for (e = list_begin(&cur->semaphores); e != list_end(&cur->semaphores); e = list_next(e)) {
        struct sema_info* sema_info = list_entry(e, struct sema_info, elem);
        if (sema_info->sd == *sema) {
          sema_down(&sema_info->sema);
          f->eax = true;
          break;
        }
      }
      break;
    }
    case SYS_SEMA_UP: {
      sema_t* sema = (sema_t*)args[1];
      if (sema == NULL) {
        f->eax = false;
        break;
      }
      verify_vaddr(sema, 1);
      f->eax = false;
      struct list_elem* e;
      for (e = list_begin(&cur->semaphores); e != list_end(&cur->semaphores); e = list_next(e)) {
        struct sema_info* sema_info = list_entry(e, struct sema_info, elem);
        if (sema_info->sd == *sema) {
          sema_up(&sema_info->sema);
          f->eax = true;
          break;
        }
      }
      break;
    }
    case SYS_GET_TID:
      f->eax = thread_current()->tid;
      break;
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

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

static void exit(int status);
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
      verify_arg_vaddr(&args[3]);
    case SYS_CREATE:
    case SYS_SEEK:
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
      verify_arg_vaddr(&args[1]);
    case SYS_HALT:
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
    default:
      break;
  }
}

static void exit(int status) {
  thread_current()->pcb->exit_status = status;
  process_exit();
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

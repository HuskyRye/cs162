#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void exit(int status);
static void verify_arg_vaddr(uint8_t* vaddr);
static void verify_string(char* str);

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  verify_arg_vaddr(args);

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
      verify_string(args[1]);
      f->eax = process_execute(args[1]);
      break;
    case SYS_WAIT:
      f->eax = process_wait(args[1]);
      break;
    case SYS_CREATE:
      verify_string(args[1]);
      break;
    case SYS_REMOVE:
      verify_string(args[1]);
      break;
    case SYS_OPEN:
      verify_string(args[1]);
      break;
    case SYS_WRITE:
      if (args[1] == STDOUT_FILENO) {
        // write to the console should write all of buffer in one call to the putbuf function
        putbuf((char*)args[2], args[3]);
      }
      break;
    case SYS_PRACTICE:
      f->eax = args[1] + 1;
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

static void verify_arg_vaddr(uint8_t* vaddr) {
  if (!valid_vaddr(vaddr) || !valid_vaddr(vaddr + 1) || !valid_vaddr(vaddr + 2) ||
      !valid_vaddr(vaddr + 3))
    exit(-1);
}

static void verify_string(char* str) {
  while (true) {
    if (!valid_vaddr(str))
      exit(-1);
    if (*str == '\0')
      return;
    ++str;
  }
}

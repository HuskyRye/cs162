#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */
  switch (args[0]) {
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      f->eax = args[1];
      thread_current()->pcb->exit_status = args[1];
      process_exit();
      break;
    case SYS_EXEC:
      f->eax = process_execute(args[1]);
      break;
    case SYS_WAIT:
      f->eax = process_wait(args[1]);
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
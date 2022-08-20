#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <list.h>
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Synchronization Types */
typedef char lock_t;
typedef char sema_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

struct load_info {
  char* file_name;
  struct process* parent;
  struct semaphore sema_load;
  bool load_success;
};

struct wait_info {
  pid_t pid;                     /* Child process's pid */
  struct process* child_process; /* Child process */
  int exit_status;               /* Child process's exit status */
  struct semaphore sema_wait;    /* semaphore for wait */
  struct list_elem elem;
};

struct file_info {
  int fd;          /* File descriptor */
  struct file* fp; /* File pointer */
  struct list_elem elem;
};

struct lock_info {
  lock_t ld;
  struct lock lock;
  struct list_elem elem;
};

struct sema_info {
  sema_t sd;
  struct semaphore sema;
  struct list_elem elem;
};

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;           /* Page directory. */
  char process_name[16];       /* Name of the main thread */
  struct thread* main_thread;  /* Pointer to main thread */
  int exit_status;             /* Exit status of current process */
  struct wait_info* wait_info; /* Infos of this process */
  struct list children;        /* Child processes */
  struct list files;           /* Opend files */
  int fd;                      /* Next fd(file descriptor) */
  struct list pthreads;        /* Pthreads */
  int num_pthreads;            /* Num of pthreads spawned. */
  struct semaphore main_join;  /* Semaphore for join on main thread. */
  struct list locks;           /* User-Level locks. */
  lock_t ld;                   /* Next ld(lock descriptor) */
  struct list semaphores;      /* User-Level semaphores. */
  sema_t sd;                   /* Next sd(semaphore descriptor) */
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void exit(int status);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

struct file* get_file(int fd);

struct pthread_load_info {
  stub_fun sfun;
  pthread_fun tfun;
  void* arg;
  struct semaphore sema_load;
  bool load_success;
};

struct pthread_join_info {
  tid_t tid;
  bool joined;
  struct semaphore sema_join;
  struct list_elem elem;
};

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(const void*);
void pthread_exit_main(void);

#endif /* userprog/process.h */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>

#include "tokenizer.h"

/* Convenience macro to silence compiler warnings about unused function parameters. */
#define unused __attribute__((unused))
#define NO_RETURN __attribute__((noreturn))

/* Whether the shell is connected to an actual terminal or not. */
bool shell_is_interactive;

/* File descriptor for the shell input */
int shell_terminal;

/* Terminal mode settings for the shell */
struct termios shell_tmodes;

/* Process group id for the shell */
pid_t shell_pgid;

int cmd_exit(struct tokens* tokens);
int cmd_help(struct tokens* tokens);
int cmd_pwd(struct tokens* tokens);
int cmd_cd(struct tokens* tokens);

/* Built-in command functions take token array (see parse.h) and return int */
typedef int cmd_fun_t(struct tokens* tokens);

/* Built-in command struct and lookup table */
typedef struct fun_desc {
  cmd_fun_t* fun;
  char* cmd;
  char* doc;
} fun_desc_t;

fun_desc_t cmd_table[] = {
    {cmd_help, "?", "show this help menu"},
    {cmd_exit, "exit", "exit the command shell"},
    {cmd_pwd, "pwd", "print name of current/working director"},
    {cmd_cd, "cd", "change the working directory"},
};

/* Prints a helpful description for the given command */
int cmd_help(unused struct tokens* tokens) {
  for (unsigned int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++)
    printf("%s - %s\n", cmd_table[i].cmd, cmd_table[i].doc);
  return 1;
}

/* Exits this shell */
int cmd_exit(struct tokens* tokens) {
  tokens_destroy(tokens); // memory leak!
  exit(0);
}

/* Print name of current/working director */
int cmd_pwd(unused struct tokens* tokens) {
  char* path = getcwd(NULL, 0);
  puts(path);
  free(path);
  return 0;
}

int cmd_cd(unused struct tokens* tokens) {
  if (tokens->tokens_length > 2) {
    fprintf(stderr, "cd: too many arguments\n");
    return -1;
  }
  if (tokens->tokens_length == 1) { // "cd" == "cd ~"
    const char* home = getenv("HOME");
    if (home == NULL) {
      fprintf(stderr, "cd: HOME not set\n");
      return -1;
    }
    chdir(home);
    return 0;
  } else {
    const char* path = (tokens->tokens[1]);
    size_t path_len = strlen(path);
    char* dir;
    if (path[0] == '~') { /* Replace ~ with absolute path */
      uid_t uid = getuid();
      struct passwd* pwd = getpwuid(uid);
      if (!pwd) {
        printf("User with %u ID is unknown.\n", uid);
        return -1;
      }
      const char* home = pwd->pw_dir;
      size_t home_len = strlen(home);
      dir = malloc(home_len + path_len);
      strcpy(dir, home);
      strcpy(dir + home_len, path + 1);
    } else {
      dir = malloc(path_len + 1);
      strcpy(dir, path);
    }
    if (chdir(dir) == -1) {
      fprintf(stderr, "cd: ");
      perror(path);
      free(dir);
      return -1;
    }
    free(dir);
    return 0;
  }
}

/* Looks up the built-in command, if it exists. */
int lookup(char cmd[]) {
  for (unsigned int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++)
    if (cmd && (strcmp(cmd_table[i].cmd, cmd) == 0))
      return i;
  return -1;
}

/* Intialization procedures for this shell */
void init_shell() {
  /* Our shell is connected to standard input. */
  shell_terminal = STDIN_FILENO;

  /* Check if we are running interactively */
  shell_is_interactive = isatty(shell_terminal);

  if (shell_is_interactive) {
    /* If the shell is not currently in the foreground, we must pause the shell until it becomes a
     * foreground process. We use SIGTTIN to pause the shell. When the shell gets moved to the
     * foreground, we'll receive a SIGCONT. */
    while (tcgetpgrp(shell_terminal) != (shell_pgid = getpgrp()))
      kill(-shell_pgid, SIGTTIN);

    /* Saves the shell's process id */
    shell_pgid = getpid();

    /* Take control of the terminal */
    tcsetpgrp(shell_terminal, shell_pgid);

    /* Save the current termios to a variable, so it can be restored later. */
    tcgetattr(shell_terminal, &shell_tmodes);
  }
}

void child_process(int start, int end, struct tokens* tokens) {
  char** argv = malloc(sizeof(char*) * (end - start + 1));
  int k = 0;
  for (int i = start; i < end; ++i) {
    char* token = tokens_get_token(tokens, i);
    if (token[0] == '>') {
      token = tokens_get_token(tokens, ++i);
      int fd = open(token, O_WRONLY | O_CREAT | O_TRUNC, 0664);
      dup2(fd, STDOUT_FILENO);
    } else if (token[0] == '<') {
      token = tokens_get_token(tokens, ++i);
      int fd = open(token, O_RDONLY);
      if (fd == -1) {
        perror(token);
        free(argv);
        tokens_destroy(tokens);
        exit(-1);
      }
      dup2(fd, STDIN_FILENO);
    } else {
      argv[k++] = token;
    }
  }
  argv[k] = NULL;
  const char* exe = tokens_get_token(tokens, start);
  size_t exe_len = strlen(exe);
  char* cmd;
  if (exe[0] == '~') { /* Replace ~ with absolute path */
    uid_t uid = getuid();
    struct passwd* pwd = getpwuid(uid);
    if (pwd == NULL) {
      printf("User with %u ID is unknown.\n", uid);
      free(argv);
      tokens_destroy(tokens);
      exit(-1);
    }
    const char* home = pwd->pw_dir;
    size_t home_len = strlen(home);
    cmd = malloc(home_len + exe_len);
    strcpy(cmd, home);
    strcpy(cmd + home_len, exe + 1);
  } else {
    cmd = malloc(exe_len + 1);
    strcpy(cmd, exe);
  }

  if (strchr(cmd, '/')) { /* File name can NOT contain '/', so cmd can't be program in PATH */
    if (execv(cmd, argv) == -1) {
      if (errno == 13) { // Permission denied
        struct stat stat_buf;
        stat(cmd, &stat_buf);
        if (S_ISDIR(stat_buf.st_mode)) { // A directory
          printf("%s: Is a directory\n", cmd);
        } else { // A file
          perror(cmd);
        }
      } else if (exe[0] == '~') {
        printf("%s: No such file or directory\n", exe);
      } else {
        perror(cmd);
      }
    }
  } else { /* Program in PATH */
    char* env_path = getenv("PATH");
    size_t cmd_len = strlen(cmd);
    char* temp = strtok(env_path, ":");
    while (temp != NULL) {
      size_t temp_len = strlen(temp);
      char* path = malloc(temp_len + 1 + cmd_len + 1);
      strcpy(path, temp);
      path[temp_len] = '/';
      strcpy(path + temp_len + 1, cmd);
      if (access(path, X_OK) == 0) {
        execv(path, argv);
      }
      free(path);
      temp = strtok(NULL, ":");
    }
    printf("%s: command not found\n", cmd);
  }
  /* Reach here means execv failed */
  free(cmd);
  free(argv);
  tokens_destroy(tokens);
  exit(-1);
}

static pid_t session_pgid = 0;

int execute(int read_fd, int* pipe_fd, int start, int end, struct tokens* tokens) {
  pid_t cpid = fork();
  if (cpid == -1) {
    perror("fork");
    return -1;
  } else if (cpid == 0) { /* Child process */
    if (read_fd != -1) {
      dup2(read_fd, STDIN_FILENO); // Read from previous pipe's read end
    }
    if (pipe_fd != NULL) {
      dup2(pipe_fd[1], STDOUT_FILENO); // Write to current pipe's write end
    }
    if (session_pgid == 0) {
      setpgrp();
    } else {
      setpgid(0, session_pgid);
    }
    signal(SIGINT, SIG_DFL);
    signal(SIGTTOU, SIG_DFL);
    child_process(start, end, tokens); // NORETURN
  } else {                             /* Parent process */
    if (session_pgid == 0) {
      session_pgid = cpid;
      tcsetpgrp(STDIN_FILENO, session_pgid);
    }
  }
  return 0;
}

int run_programs(struct tokens* tokens) {
  size_t tokens_len = tokens_get_length(tokens);
  int read_fd = -1;          // Previous pipe's read end
  int pipe_fd[2] = {-1, -1}; // Next read, current write
  int start = 0;
  int process_num = 0;
  for (int i = 0; i < tokens_len; ++i) {
    char* token = tokens_get_token(tokens, i);
    if (token[0] == '|') {
      if (pipe(pipe_fd) == -1) {
        perror("pipe");
        if (read_fd != -1) {
          close(read_fd);
        }
        return -1;
      }
      if (execute(read_fd, pipe_fd, start, i, tokens) == -1) {
        if (read_fd != -1) {
          close(read_fd);
        }
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return -1;
      }
      ++process_num;
      if (read_fd != -1) {
        close(read_fd);
      }
      close(pipe_fd[1]);
      read_fd = pipe_fd[0];
      start = i + 1;
    }
  }
  /* Last or the only one */
  if (execute(read_fd, NULL, start, tokens_len, tokens) == -1) {
    if (read_fd != -1) {
      close(read_fd);
    }
    return -1;
  }
  ++process_num;
  if (read_fd != -1) {
    close(read_fd);
  }
  for (int i = 0; i < process_num; ++i) {
    wait(NULL);
  }
  tcsetpgrp(STDIN_FILENO, getpgrp());
  return 0;
}

int main(unused int argc, unused char* argv[]) {
  init_shell();
  signal(SIGINT, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);

  static char line[4096];
  int line_num = 0;

  /* Please only print shell prompts when standard input is not a tty */
  if (shell_is_interactive)
    fprintf(stdout, "%d: ", line_num);

  while (fgets(line, 4096, stdin)) {
    /* Split our line into words. */
    struct tokens* tokens = tokenize(line);

    /* Find which built-in function to run. */
    int fundex = lookup(tokens_get_token(tokens, 0));

    if (fundex >= 0) {
      cmd_table[fundex].fun(tokens);
    } else {
      run_programs(tokens);
      session_pgid = 0;
    }

    if (shell_is_interactive)
      /* Please only print shell prompts when standard input is not a tty */
      fprintf(stdout, "%d: ", ++line_num);

    /* Clean up memory */
    tokens_destroy(tokens);
  }

  return 0;
}

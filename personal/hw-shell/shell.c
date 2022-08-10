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

int main(unused int argc, unused char* argv[]) {
  init_shell();

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
      pid_t pid = fork();
      if (pid < 0) {
        perror("fork");
      } else if (pid == 0) { // new process
        size_t tokens_len = tokens_get_length(tokens);
        char** argv = malloc(sizeof(char*) * (tokens_len + 1));
        for (int i = 0; i < tokens_len; ++i) {
          argv[i] = tokens_get_token(tokens, i);
        }
        argv[tokens_len] = NULL;
        const char* exe = tokens_get_token(tokens, 0);
        size_t exe_len = strlen(exe);
        char* cmd;
        if (exe[0] == '~') { /* Replace ~ with absolute path */
          uid_t uid = getuid();
          struct passwd* pwd = getpwuid(uid);
          if (!pwd) {
            printf("User with %u ID is unknown.\n", uid);
            return -1;
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

        if (strchr(cmd, '/')) { // File name can NOT contain '/', so cmd can't be program in PATH
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
        } else {
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
        free(cmd);
        free(argv);
        tokens_destroy(tokens);
        return -1;
      } else {
        int status;
        wait(&status);
      }
    }

    if (shell_is_interactive)
      /* Please only print shell prompts when standard input is not a tty */
      fprintf(stdout, "%d: ", ++line_num);

    /* Clean up memory */
    tokens_destroy(tokens);
  }

  return 0;
}

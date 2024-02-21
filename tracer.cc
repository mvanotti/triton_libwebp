#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc == 1) {
    fprintf(stderr, "Not enough arguments!\n");
    exit(EXIT_FAILURE);
  }

  long result = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  if (result == -1) {
    perror("ptrace failed.");
    exit(EXIT_FAILURE);
  }

  raise(SIGSTOP);

  int res = execve(argv[1], &argv[1], environ);
  if (res == -1) {
    perror("execve failed");
    exit(EXIT_FAILURE);
  }

  return 0;
}
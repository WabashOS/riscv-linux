#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <stdio.h>

int main(int argc, char *argv[]) {

  int res = syscall(SYS_pfa);
  if(!res) {
    printf("Failed to register task with PFA\n");
    return EXIT_FAILURE;
  }

  execvp(argv[1], &argv[1]);
}

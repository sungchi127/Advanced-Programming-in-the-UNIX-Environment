#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>   
#include <sys/reg.h>   
#include <sys/syscall.h> 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
const int long_size = sizeof(long);
long reset_CC_addr = 0;
int status;

void errquit(const char *msg) {
    perror(msg);
    exit(1);
}

void update_magic(pid_t child, long magic_addr, char *new_magic) {
    int len = strlen(new_magic);
    for (int i = 0; i < len; i++) {
        long val = new_magic[i];
        // if(ptrace(PTRACE_POKETEXT, child, magic_addr + i*8 , val)!=0) errquit("POKETEXT");
        if(ptrace(PTRACE_POKETEXT, child, magic_addr + i , val)!=0) errquit("POKETEXT");
    }
}

void try_all_magics(pid_t child, long magic_addr, struct user_regs_struct* reset_regs) {
    char magic[11];
    for (unsigned long i = 0; i < (1 << 9); i++) {  // Loop over all 2^10 possible values
        for (int j = 0; j < 9; j++) {
            magic[j] = '0' + ((i >> j) & 1);  // Generate a binary string
        }
        magic[10] = '\0';  // Add null-terminator
        if(ptrace(PTRACE_SETREGS, child, NULL, reset_regs)!=0) errquit("SETREGS");
        update_magic(child, magic_addr, magic);

        ptrace(PTRACE_CONT, child, NULL, NULL);
        if(wait(&status) < 0) errquit("wait4");//4

        ptrace(PTRACE_CONT, child, NULL, NULL);
        if(wait(&status) < 0) errquit("wait5");//5

        struct user_regs_struct ret_flag;
        if(ptrace(PTRACE_GETREGS,child,0,&ret_flag)!= 0 ) errquit("GETREGS");
        if(ret_flag.rax==0) break;
    }
}


int main(int argc , char* argv[])
{   
    pid_t child;
    struct user_regs_struct reset_regs;
    if((child = fork()) < 0) errquit("fork");
    int cnt=0;

    // if(child = 0) {
    //     ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    //     // execl("sample3", "executable", NULL);
    //     execv(argv[1],argv+1);
    // }
    // else {
    //     ptrace(PTRACE_SETOPTIONS,child,0,PTRACE_O_EXITKILL);
    //     while(1) {
    //         printf("cnt : %d\n",cnt);
    //         if(wait(&status) < 0) errquit("wait");
    //         if(WIFEXITED(status))
    //             break;

    //         struct user_regs_struct regs;
    //         if(ptrace(PTRACE_GETREGS, child, NULL, &regs)!= 0 ) errquit("GETREGS");
    //         // printf("Child stopped at RIP = 0x%llx\n", regs.rip);

    //         long magic_addr;
    //         if(cnt==2){
    //             magic_addr = regs.rax;
    //             // printf("regs_rax:0x%llx\n",regs.rax);
    //             long  magic_val=ptrace(PTRACE_PEEKTEXT, child, regs.rax, 0);
    //             char* magic = (char*) & magic_val;
    //             // fprintf(stderr,"magic_val_address = %p, magic_val = %s, magic[8]=%c\n",magic,magic,magic[7]);
    //         }

    //         if(cnt==3){
    //             reset_regs = regs;
    //             reset_CC_addr = regs.rip;
    //             try_all_magics(child, magic_addr, &reset_regs);
    //             break;
    //         }

    //         ptrace(PTRACE_CONT, child, NULL, NULL);
    //         cnt++;
    //     }
    //     ptrace(PTRACE_CONT, child, NULL, NULL);//5
    //     if(wait(&status) < 0) errquit("wait");
    //     ptrace(PTRACE_CONT, child, NULL, NULL);//6

    // }

    if(child > 0){
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        while(1) {
            printf("cnt : %d\n",cnt);
            if(wait(&status) < 0) errquit("wait0");
            if(WIFEXITED(status))
                break;

            struct user_regs_struct regs;
            if(ptrace(PTRACE_GETREGS, child, NULL, &regs)!= 0 ) errquit("GETREGS");
            // printf("Child stopped at RIP = 0x%llx\n", regs.rip);

            long magic_addr;
            if(cnt==2){
                magic_addr = regs.rax;
                // printf("regs_rax:0x%llx\n",regs.rax);
                long  magic_val=ptrace(PTRACE_PEEKTEXT, child, regs.rax, 0);
                char* magic = (char*) & magic_val;
                // fprintf(stderr,"magic_val_address = %p, magic_val = %s, magic[8]=%c\n",magic,magic,magic[7]);
            }

            if(cnt==3){
                reset_regs = regs;
                reset_CC_addr = regs.rip;
                try_all_magics(child, magic_addr, &reset_regs);
                break;
            }

            ptrace(PTRACE_CONT, child, NULL, NULL);
            cnt++;
        }
        printf("5\n");
        ptrace(PTRACE_CONT, child, NULL, NULL);//5
        if(wait(&status) < 0) errquit("wait2");
        printf("6\n");
        // ptrace(PTRACE_CONT, child, NULL, NULL);//6

    }
    else{
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        // execl("sample3", "executable", NULL);
        execv(argv[1],argv+1);
    }

    return 0;
}

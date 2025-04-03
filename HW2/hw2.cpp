#include<iostream>
#include<sys/types.h>
#include<sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include<unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<assert.h>
#include<sys/ptrace.h>
#include<sys/user.h>
#include <sys/stat.h>
#include<string.h>
#include<vector>
#include<sstream>
#include<list>
#include<fstream> 
#include<iomanip>
#include<elf.h>
#include<capstone/capstone.h>
#include <map>
#include <fcntl.h>

using namespace std;

#define debug 0
#define NOTLOAD 0
#define LOAD 1
#define RUNN 2
#define REGNUM 27

#define errquit(m) { perror(m); exit(-1); }

#define print_reg(a, b) printf("%-3s %-16llx", #a ,regs.b)
#define println_reg(a, b) printf("%-3s %-16llx\n",#a, regs.b)
#define printc_reg(a, b, c) printf(c, #a ,regs.b)

static csh cshandle = 0;
struct breakpoint {
	unsigned long long addr;
	unsigned long long code;
};

struct Proc {
    pid_t pid;
    long base;
	Proc() : pid(0), base(0) {}
    struct user_regs_struct regs; // regs 
    map<long, vector<long>> maps; // memory copy
    Proc(pid_t _tracked) : pid(_tracked), base(0) {}
    void snapshot(bool use_mem=true) {
        if(use_mem) {
            int fd, sz;
            char buf[163840], *s = buf, *line, *saveptr;
            sprintf(buf, "/proc/%d/maps", pid);
            if((fd = open(buf, O_RDONLY)) < 0) errquit("proc/open");
            if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("proc/read");
            buf[sz] = 0; close(fd);
            if(debug) puts(buf);
            while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { s = NULL;
                // pass code section and sections after vvar1
                if(strstr(line, " rw-p ") == NULL and strstr(line, " rwxp ") == NULL) continue;
                long l, r;
                if(sscanf(line, "%lx-%lx ", &l, &r) != 2) errquit("proc/scanf");
                // // if(strstr(line, " r--p ") != NULL and !base) base = l;
                vector<long> data((r - l) / 8);
                if(debug) printf("copy child process memory %lx-%lx\n", l, r);
                for(long i = l, j = 0; i < r; i += 8, ++j) {
                    data[j] = ptrace(PTRACE_PEEKDATA, pid, i, NULL);
                    if(errno != 0) errquit("proc/peek");

                }
                maps[l] = data;
            }
        }
        if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) errquit("proc/getregs");

    }
    void restore(bool use_mem=true) {
        if(use_mem) {
            for(auto it : maps) {
                int len = it.second.size();
                if(debug) printf("write section %lx-%lx\n", it.first, it.first + 8 * len);
                for(long i = it.first, j = 0; j < len; i += 8, ++j) {
                    if(ptrace(PTRACE_POKEDATA, pid, i, it.second[j]) < 0) errquit("proc/write");
                }
            }
        }
        if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) errquit("proc/setregs");
    }
    // void write(char bytes[], int n, long address) {
    //     int _n = n - n % 8;
    //     for(int i = 0; i < _n; i += 8) {
    //         ptrace(PTRACE_POKEDATA, pid, address + i * 8, *(long*)(bytes + i * 8));
    //     }
    //     if(_n != n and n > 8) {
    //         ptrace(PTRACE_POKEDATA, pid, address + n - 8, *(long*)(bytes + n - 8));
    //     }
    //     if(debug) printf("write %d bytes to %lx\n", n, address);
    // }
    // void write_offset(char bytes[], int n, long address) {
    //     write(bytes, n, address + base);
    // }
    // void clear() {
    //     base = 0;
    //     maps.clear();
    //     memset(&regs, 0, sizeof(regs));
    // }
};


class Debugger{
	public:
		unsigned long long entry;
		unsigned long long text_begin;
		unsigned long long text_end;
		pid_t child;
		int stage;
		std::list<breakpoint> breakpoints;
		breakpoint last_bp;
		bool is_bp;
		Proc snap;
		std::string program_name;
		struct user_regs_struct anchor_regs;
		unsigned long long anchor_code;
		Debugger () {
			child = 0;
			stage = NOTLOAD;
			entry = 0;
			anchor_code = 0;
			is_bp = false;
		}


		void load(std::string _name) {
			int flag;
			if(stage != NOTLOAD) {
				std::cout << "** state must be NOT LOADED" << std::endl;
				return;
			}
			
			Elf64_Ehdr ehdr; //Elf header
			Elf64_Shdr* shdr; //Elf symbol table
			flag=0;
			program_name = _name;
			FILE* fp = fopen(program_name.c_str(), "r");
			if(fp == NULL) {
				flag = 1;
				std::cout << "** Error: File does not exist!!" << std::endl;
				return;
			}
			if(flag == 1) printf("nonono\n");
			fseek(fp, 24, SEEK_SET);
			fread((char *)&entry, sizeof(char), 8, fp);
			int n ;
			fseek(fp, 0, SEEK_SET);
			fread(&ehdr, 1, sizeof(Elf64_Ehdr), fp);
			n = 1024;
			shdr = (Elf64_Shdr*)malloc(ehdr.e_shentsize * ehdr.e_shnum);
			flag = 1;
			fseek(fp, ehdr.e_shoff, SEEK_SET);
			fread(shdr, 1, ehdr.e_shentsize * ehdr.e_shnum, fp);

			if(flag == 0) printf("nonono1\n");

			get_text_end(fp, ehdr, shdr);
			printf("** program '%s' loaded. entry point 0x%llx\n",program_name.c_str(), entry);
			if(flag==0){
				printf("end");
			}
			stage = LOAD;
			free(shdr);
			// stage = LOAD;
		}

		void assign_split(std::vector<std::string> &vi, const std::string &input, char c = ' ') {
			bool flag = false;
			vi.clear();
			std::string tmp;
			int cnt = 0;
			for(int i = 0; i < (int)input.size(); i ++) {
				if(input[i] == c) {
					if(flag) {
						if(cnt < 0) return ;
						vi.push_back(tmp);
						flag = false;
						cnt++;
					}
					tmp = "";
				}else {
					tmp += input[i];
					flag = true;
					cnt--;
				}
			}

			if(tmp.size() != 0) {
				vi.push_back(tmp);
			}
			if(tmp.size() > 100 ){
				printf("too much\n");
			}
		}

		void get_text_end(FILE* fd, Elf64_Ehdr ehdr, Elf64_Shdr shdr[])
		{
			int i;
			int flag;
			char* sh_str;
			char* buf;

			buf = (char *)malloc(shdr[ehdr.e_shstrndx].sh_size);

			if(buf != NULL)
			{
				flag = 1;
				fseek(fd, shdr[ehdr.e_shstrndx].sh_offset, SEEK_SET);
				fread(buf, 1, shdr[ehdr.e_shstrndx].sh_size, fd);
				flag++;
			}
			flag = 0;
			sh_str = buf;

			for(int i = 0; i < ehdr.e_shnum; i++){
				flag = 0; 
				if(!strcmp(".text", (sh_str + shdr[i].sh_name)))
				{
					flag = 1;
					text_begin  = (unsigned long long)shdr[i].sh_addr;
					text_end = (unsigned long long)shdr[i].sh_size + text_begin;
					break;
				}
				flag = 0;
			}
			free(buf);

		}
	
		void cont_bp_recover() {
			if(!is_bp) {
				return;
			}
			is_bp = false;
			int status = 0;
			int flag=0;
			struct user_regs_struct regs;

			ptrace(PTRACE_GETREGS, child, 0, &regs);
			if(regs.rip != last_bp.addr) return;
			if(flag == 1){
				printf("ok\n");
			}
			unsigned long long code;
			code = ptrace(PTRACE_PEEKTEXT, child, last_bp.addr, 0);
			ptrace(PTRACE_POKETEXT, child, last_bp.addr, ((code & 0xffffffffffffff00) | last_bp.code));
			if(flag){
				printf("ok\n");
			}
			if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) {
				perror("Single step error");
				flag = 1;
			}
			waitpid(child, &status, 0);
			if(WIFSTOPPED(status)) {
				ptrace(PTRACE_POKETEXT, child, last_bp.addr, code);
				flag = 1;
				stage = RUNN;
				return;
			}
			if(WIFEXITED(status)) {
				stage = LOAD;
				flag = 1;
				int exit_code = WEXITSTATUS(status);
				// std::cout << "** child process "<< child << " terminiated normally (code "<< exit_code << ")" << std::endl;
			}
		}
		
		unsigned long long string_to_long(const char *ptr) {
			int flag ;
			unsigned long long ret;
			flag = 1;
			if(flag!=0)
				sscanf(ptr, "%llx", &ret);
			return ret;
		}

		void bp_check(bool is_single, int loop = 0) {
			struct user_regs_struct regs;
			ptrace(PTRACE_GETREGS, child, 0, &regs);
			int flag;
			for(std::list<breakpoint>::iterator it = breakpoints.begin(); it != breakpoints.end(); it ++) {
				flag = 0;
				if(regs.rip - ((int)is_single) == it->addr) {
					last_bp = *it;
					flag = 1;
					regs.rip = regs.rip - ((int)is_single);
					ptrace(PTRACE_SETREGS, child, 0, &regs);
					is_bp = true;
					if(loop == 0)
						printf("** hit a breakpoint at 0x%llx\n",regs.rip);
					break;
				}
			}
		}

		void cont(int loop = 0) {
			if(stage != RUNN) {
				std::cout << "** program need run4" << std::endl;
				return;
			}

			cont_bp_recover();
			int flag;
			if(stage != RUNN) {
				return;
			}
			int status = 0;
			if(ptrace(PTRACE_CONT, child, 0, 0) < 0) {
				perror("Single step error");
			}
			flag = 0;
			waitpid(child, &status, 0);
			if(WIFSTOPPED(status)) {
				bp_check(true, loop);
				stage = RUNN;
				flag = 1;
				return;
			}
			if(WIFEXITED(status)) {
				flag = 1 ;
				stage = LOAD;
				int exit_code = WEXITSTATUS(status);
				// std::cout << "** child process "<< child << " terminiated normally (code "<< exit_code << ")" << std::endl;
			}
		}

		void single_step() {
			if(stage != RUNN) {
				std::cout << "** program need run3" << std::endl;
				return;
			}

			if(is_bp) {
				cont_bp_recover();
				bp_check(false);
				return;
			}
			int flag;
			if(stage != RUNN) {
				return;
			}
			int status = 0;
			flag = 0; 
			if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) {
				perror("Single step error");
			}
			waitpid(child, &status, 0);
			if(WIFSTOPPED(status)) {
				flag = 1;
				bp_check(false);
				stage = RUNN;
				return;
			}
			if(WIFEXITED(status)) {
				flag = 1;
				stage = LOAD;
				int exit_code = WEXITSTATUS(status);
				// std::cout << "** child process "<< child << " terminiated normally (code "<< exit_code << ")" << std::endl;
			}
		}

		void add_breakpoint(unsigned long long addr, int is_travel = 0) {

			if(stage != RUNN) {
				std::cout << "** program need run6" << std::endl;
				return;
			}
			int n;
			if(addr < text_begin || addr >= text_end) {
				std::cout<<"text_begin: "<<text_begin<<"\n";
				std::cout<<"text_end:"<<text_end<<"\n";
				std::cout<<"addr: "<<addr<<"\n";
				std::cout << "** the address is out of the range of the text section." << std::endl;
				return;
			}
			n = 0;
			unsigned long long code;
			code = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
			ptrace(PTRACE_POKETEXT, child, addr, ((code & 0xffffffffffffff00) | 0xcc));
			n++;
			breakpoints.push_back({addr, code & 0xff});
			if(is_travel == 0){
				printf("** set a breakpoint at 0x%llx.\n",addr);
			}
		}

		void init_breakpoint() {
			for(auto it : breakpoints) {
				int cnt=0;
				unsigned long long code;
				code = ptrace(PTRACE_PEEKTEXT, child, it.addr, 0);
				cnt++;
				ptrace(PTRACE_POKETEXT, child, it.addr, ((code & 0xffffffffffffff00) | 0xcc));
				it.code = code & 0xff;
			}
		}


		int disasm(long long addr, int maxn = 5) {
			int flag = 0;
			if(stage != RUNN) {
				std::cout << "** the target program terminated." << std::endl;
				return -1;
			}

			size_t count;
			cs_insn *insn;
			flag=0;
			int n = 25;
			unsigned char buf[200];
			memset(buf, 0, 200);
			int cnt;
			for(int i = 0; i < n; i ++) {
				*(unsigned long long *)(buf + i * 8) = ptrace(PTRACE_PEEKTEXT, child, addr + i * 8, 0);
				cnt++;
			}
	
			for(auto it : breakpoints) {
				if(it.addr - addr < 200) {
					int tmp = 0;
					char origin = it.code & 0xff;
					buf[it.addr - addr] = origin;
					flag=1;
				}
			}

			if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK){
				return -1;
			}
			flag = 1;
			count = cs_disasm(cshandle, buf, sizeof(buf) - 1, addr, 0, &insn);
			if(count > 0) {
				size_t j;
				flag = 0;
				cnt = 0;
				if(count > maxn) {
					count = maxn;
				}
				for(j = 0; j < count; j ++) {
					cnt = 0;
					if(insn[j].address < text_begin || insn[j].address >= text_end) {
						std::cout << "** the address is out of the range of the text section." << std::endl;
						flag = 1;
						return -1;
					}
					cnt++;
					printf("\t%lx: ", insn[j].address);
					int x = 0;
					flag=1;
					for(x = 0; x < insn[j].size; x ++) {
						printf("%02x ", (int)insn[j].bytes[x]);
					}
					cnt--;
					for(; x < 12; x ++) {
						printf("   ");
					}
					printf("%s\t%s\n", insn[j].mnemonic, insn[j].op_str);
					if(cnt < 0){
						printf("ok");
					}
				}
				cs_free(insn, count);
				cnt++;
			}
			cs_close(&cshandle);
			return 0;
		}

		void start(){
			child = fork();
			if(child < 0) {
				perror("Fork Error");
				printf("fork error");
				return;
			}
			if(child == 0) {
				if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
					perror("TRACEME Error");
					printf("traceme error");
					exit(-1);
				}
				execlp(program_name.c_str(), program_name.c_str(), NULL);
			}else {
				int status;
				stage = RUNN;
				// std::cout << "** pid " << child << std::endl;
				if(waitpid(child, &status, 0) < 0) {
					perror("Start");
					return;
				}
				snap = Proc(child);
				ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
				init_breakpoint();
				return;
			}
		}

		void anchor (){
			unsigned long long code;
			code = ptrace(PTRACE_PEEKTEXT, child, last_bp.addr, 0);
			ptrace(PTRACE_POKETEXT, child, last_bp.addr, ((code & 0xffffffffffffff00) | last_bp.code));
			ptrace(PTRACE_GETREGS, child, 0, &anchor_regs);
			anchor_code = ptrace(PTRACE_PEEKTEXT, child, anchor_regs.rip, 0);
			snap.snapshot();
			std::cout<<"** dropped an anchor"<<"\n";
			return ;
		}

		void timetravel (){
			unsigned long long code;
			code = ptrace(PTRACE_PEEKTEXT, child, last_bp.addr, 0);
			ptrace(PTRACE_POKETEXT, child, last_bp.addr, ((code & 0xffffffffffffff00) | last_bp.code));
			snap.restore();
			add_breakpoint(last_bp.addr,1);
			std::cout<<"** go back to the anchor point"<<"\n";
			return ;
		}

		void mux(const std::string &input) {
			int muxop;
			std::vector<std::string> arg;
			assign_split(arg, input);
			muxop = 0;
			if(arg[0] == "start") {
				start();
				return;
			}

			if(arg[0] == "load") {
				if(arg.size() == 1) {
					std::cout << "** no program path is given" << arg[2] << std::endl;
					return;
				}
				if(arg.size() > 2) {
					std::cout << "** Unknown argument " << arg[2] << std::endl;
					return;
				}
				muxop=1;
				this->load(arg[1]);
				return;
			}

			if(arg[0] == "cont" || arg[0] == "c") {
				struct user_regs_struct regs;
				ptrace(PTRACE_GETREGS, child, 0, &regs);
				if(last_bp.addr == regs.rip){
					cont(1);
				}
				cont();
				muxop++;
				return;
			}

			if(arg[0] == "timetravel") {
				timetravel();
				muxop++;
				return;
			}

			if(arg[0] == "anchor") {
				anchor();
				muxop++;
				return;
			}

			if(arg[0] == "break" || arg[0] == "b") {
				add_breakpoint(string_to_long(arg[1].c_str()));
				muxop++;
				return;
			}

			if(arg[0] == "si") {
				single_step();
				muxop++;
				return;
			}


			if(arg[0] == "disasm" || arg[0] == "d") {
				// if(arg.size() < 2) {
				// 	std::cout << "** no addr is given" << std::endl;
				// 	return;
				// }
				disasm(string_to_long(arg[1].c_str()));
				return;
			}


		}
};



int main(int argc, char *argv[]) {
	Debugger sdb;

	setvbuf(stdout, (char *)NULL, _IONBF, 0);
	std::string file;
	std::string script_file;
	std::ifstream p;
	bool s = false;
	
	sdb.load(std::string(argv[1]));
	sdb.start();

	std::string input;
	int start=0;
	struct user_regs_struct regs;

	ptrace(PTRACE_GETREGS, sdb.child, 0, &regs);
	sdb.disasm(regs.rip);


	while(1) {

		if(!s)
			std::cout << "(sdb) ";
		if(s) {
			if(std::getline(p, input)) {
				std::cout<<"input"<<input<<"\n";
			}else {
				p.close();
				return 0;
			}
		}else {
			if(std::getline(std::cin, input)) {
			}else{
				return 0;
			}
		}
	
		if(input == "") {
			continue;
		}
		
		sdb.mux(input);
		ptrace(PTRACE_GETREGS, sdb.child, 0, &regs);
		if(input[0]!='a' && input[0]!='b'){//anchor, breakpoint
			sdb.disasm(regs.rip);
		}
		
	}

	return 0;
}



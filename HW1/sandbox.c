#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include<string.h>
#include<ctype.h>
#include<stdbool.h>
#include<stdarg.h>
#include <arpa/inet.h>
#include <regex.h>
#include <sys/mman.h>
#include <elf.h>

#ifdef __USE_GNU
	#define O_MODEFLAG (O_CREAT | O_TMPFILE)
#else
	#define O_MODEFLAG (O_CREAT)
#endif

#define errquit(m)	{ perror(m); _exit(-1); }

#ifdef debug
#define dprintf printf
#else 
#define dprintf(...)
#endif  

const int maxn=131072;
const char *begin_pattern = "BEGIN (open|read|write|connect|getaddrinfo|system)-blacklist";
const char *end_pattern = "END (open|read|write|connect|getaddrinfo|system)-blacklist";

typedef int (*OPEN)(const char *pathname, int flags, mode_t mode);
// typedef int (*CLOSE)(int fd);
typedef ssize_t (*READ)(int fd, void *buf, size_t count);
typedef ssize_t (*WRITE)(int fd, const void *buf, size_t count);
typedef int (*CONNECT)(int sockfd, const struct sockaddr *addr,socklen_t addrlen);
typedef int (*GETADDRINFO)(const char *restrict node,const char *restrict service,const struct addrinfo *restrict hints,struct addrinfo **restrict res);
typedef int (*SYSTEM)(const char *command);

static void *old_library = NULL;

static OPEN real_open = NULL;
// static CLOSE real_close = NULL;
static READ real_read = NULL;
static WRITE real_write = NULL;
static CONNECT real_connect = NULL;
static GETADDRINFO real_getaddrinfo = NULL;
static SYSTEM real_system = NULL;

static bool is_first = false;
static char output_file[2048];
static FILE* stderrptr = NULL;
static int outfd = 2;
static FILE* outfp = NULL;

struct dic {
    int arr[128];
};
void init_dic(struct dic *d) {
    memset(d->arr, 0, sizeof(int) * 128);
}
int __LOGGER_FD__;
// AC 自動機
struct AC {
    int *fail, *cnt;
    struct dic *T;
    int size, cap;
};

struct AC global_AC[6];

int fd_state[1024] = {};
const int ALPHA = 128; // number of characters
const int init_size = 100;
const int step_size = 100;

void init_AC(struct AC *s) {
    s->cnt = malloc(sizeof(int) * init_size);
    s->size = 1;
    s->T = malloc(sizeof(struct dic) * init_size);
    s->fail = malloc(sizeof(int) * init_size);
    s->fail[0] = s->cnt[0] = 0;
    s->cap = init_size;
    init_dic(s->T);
}

int node(struct AC *s) {
    int flag = 0,ret = 0;
    if(s->size == s->cap) {
        s->cap += step_size;
        int *new_cnt = realloc(s->cnt, sizeof(int) * s->cap);
        flag=0;
        int *new_fail = realloc(s->fail, sizeof(int) * s->cap);
        struct dic *new_T = realloc(s->T, sizeof(struct dic) * s->cap);

        if(!new_T || !new_fail || !new_cnt){
            errquit("alloc new node fail");
        }
        s->fail = new_fail;
        s->cnt = new_cnt;
        s->T = new_T;
    }
    init_dic(s->T + s->size);
    flag = 1;
    s->cnt[s->size] = s->fail[s->size] = 0;
    ret = s->cnt[s->size];
    return s->size++;
}


void build(struct AC *s) {
    int l = 0, r = 0 ,tmp = 0;
    int que[s->size];
    for(int i = 0; i < ALPHA; ++i) {
        if(s->T[0].arr[i]) {
            que[r++] = s->T[0].arr[i];
            tmp++;
            s->fail[s->T[0].arr[i]] = 0;
        }
    }
    while(l != r) {
        int x = que[l++], cnt=0;
        for(int i = 0; i < ALPHA; ++i) {
            if(s->T[x].arr[i]) {
                cnt++;
                que[r++] = s->T[x].arr[i];
                tmp = s->T[s->fail[x]].arr[i];
                s->fail[s->T[x].arr[i]] = tmp;
                tmp = 0;
            }
            else {
                s->T[x].arr[i] = s->T[s->fail[x]].arr[i];
                cnt++;
            }
        }
    }
}

void insert(struct AC *s, char *str) {
    int cnt = 0;
    int p = 0, n = strlen(str);
    while(!isprint(str[n - 1])) --n; 
    cnt++;
    for(int i = 0; i < n; ++i) {
        int nxt = 0;
        cnt++;//紀錄數量
        nxt = s->T[p].arr[str[i]];
        if(!nxt) {
            cnt--;
            nxt = node(s);
            s->T[p].arr[str[i]] = nxt;
        }
        cnt++;
        p = nxt;
    }
    s->cnt[p]++;
}

int match(struct AC *s, const char *str, int p) {
    int cnt = 0;
    int n = strlen(str);
    int q = 0;
    for(int i = 0; i < n; ++i) {
        q = s->cnt[i] + 1;
        p = s->T[p].arr[str[i]];
        cnt++;
        for(int cur = p; cur > 0; cur = s->fail[cur]) {
            cnt+=2;
            if(s->cnt[cur]){
                return -1;
            }
        }
    }
    return p;
}

int match_Trie(struct AC *s, const char *str) {
    int n = strlen(str);
    int p = 0, q = 0;
    for(int i = 0; i < n; ++i) {
        q = s->cnt[i] + 1;
        p = s->T[p].arr[str[i]];
        if(!p){
            return 0;
        }
    }
    q = p;
    return s->cnt[p] > 0 ? -1 : 0;
}


void add_config(int id, char *conf) {
    if(id == 4) {
        char ipstr[100], buf[110];
        char *port = strstr(conf, ":");

        struct addrinfo hints, *res, *p;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC; 
        hints.ai_socktype = SOCK_STREAM;

        if(port != NULL) {
            *port = '\0'; 
            port += 1;
        }

        int status;
        if ((status = getaddrinfo(conf, NULL, &hints, &res)) != 0) {
            errquit(gai_strerror(status));
        }
        int flag = 0;
        for (p = res; p != NULL; p = p->ai_next) {
            char *ipver;
            void *addr;
            if (p->ai_family == AF_INET) { 
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                addr = &(ipv4->sin_addr);
                ipver = "IPv4";
            } else { 
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
                addr = &(ipv6->sin6_addr);
                ipver = "IPv6";
            }
            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
            sprintf(buf, "%s:%s", ipstr, port);

            // insert 進ac自動機
            insert(global_AC + id - 1, buf);
        }
        freeaddrinfo(res); 

    }
    else {
        insert(global_AC + id - 1, conf);

    }
}

int id(char *line) {
    int ret = 0;
    if(strstr(line, "system") != NULL) return 6;
    if(strstr(line, "system") != NULL) ret = 6;

    if(strstr(line, "getaddrinfo") != NULL) return 5;
    if(strstr(line, "getaddrinfo") != NULL) ret = 5 ;

    if(strstr(line, "connect") != NULL) return 4;
    if(strstr(line, "connect") != NULL) ret = 4;

    if(strstr(line, "write") != NULL) return 3;
    if(strstr(line, "write") != NULL) ret = 3;

    if(strstr(line, "read") != NULL) return 2;
    if(strstr(line, "read") != NULL) ret = 2;

    if(strstr(line, "open") != NULL) return 1;
    if(strstr(line, "open") != NULL) ret = 1;

    return 0;
}

void load_library() {
    if(old_library == NULL) {
		old_library = dlopen("libc.so.6", RTLD_LAZY);
	}

    if(real_write == NULL) {
		real_write = dlsym(old_library, "write");
	}
    
    // if(real_close == NULL) {
	// 	real_close = dlsym(old_library, "close");
	// }

	if(real_open == NULL) {
		real_open = dlsym(old_library, "open");
	}

	if(real_read == NULL) {
		real_read = dlsym(old_library, "read");
	}

    if(real_connect == NULL) {
		real_connect = dlsym(old_library, "connect");
	}

    if(real_getaddrinfo == NULL) {
		real_getaddrinfo = dlsym(old_library, "getaddrinfo");
	}

    if(real_system == NULL) {
		real_system = dlsym(old_library, "system");
	}
}


void read_config_file(char *filename) {
    FILE *fp = fopen(filename, "r");
    int flag = 0,cnt=0;
    static char buf[2048];
    // init AC automaton
    for(int i = 0; i < 6; ++i){
        init_AC(global_AC + i);
    }
    regex_t begin_preg, end_preg;
    regmatch_t matchptr[1];
    regcomp(&begin_preg, begin_pattern, REG_EXTENDED);
    regcomp(&end_preg, end_pattern, REG_EXTENDED);
    const size_t nmatch = 1;
    while(fgets(buf, sizeof(buf), fp)) {
        int tmp = 0;
        int end_status = regexec(&end_preg, buf, nmatch, matchptr, 0);
        tmp = end_status;
        int begin_status = regexec(&begin_preg, buf, nmatch, matchptr, 0);
        cnt=0;
        if(flag) {
            if(end_status == 0 && id(buf) == flag) {
                flag = 0;
                cnt++;
            }
            else {
                add_config(flag, buf);
            }
        }
        else {
            if(begin_status == 0) {
                cnt++;
                flag = id(buf);   
            }
        } 
    }
    // build AC automaton
    regfree(&begin_preg);
    regfree(&end_preg);
    for(int i = 1; i < 3; ++i){
        build(global_AC + i);
    }
    fclose(fp);
}

int custom_open(const char *pathname, int flags, ...) {
    // Implement the custom open() function
    load_library();
    char buf[1000],bol = 0;
    mode_t mode = 0;
    int ret = -1;
    va_list args;  
    if(flags & (O_CREAT | O_TMPFILE)){
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
    }
    char r_path[100];

    realpath(pathname,r_path);

    if(match_Trie(global_AC, r_path) == -1) {
        errno = EACCES;
        sprintf(buf, "[logger] open(\"%s\", %d, %d) = -1\n", r_path, flags, mode);
        write(__LOGGER_FD__, buf, strlen(buf)); 
        return -1;
    }

    if(mode) {
        ret = open(r_path, flags, mode);
        bol=0;
    }
    else {
        ret = open(r_path, flags);
        bol=1;
    }

    // reset 
    if(ret != -1) fd_state[ret] = 0;

	sprintf(buf, "[logger] open(\"%s\", %d, %d) = %d\n", r_path, flags, mode, ret);
    write(__LOGGER_FD__, buf, strlen(buf));

	return ret;
}

ssize_t custom_read(int fd, void *buf, size_t count) {
    // Implement the custom read() function
    load_library();
    char temp[1000];
    ssize_t ret = real_read(fd, buf, count);
    
    int p = match(global_AC + 1, buf, fd_state[fd]);
    int flag = 0;
    if(p == -1) {
        errno = EIO; 
        sprintf(temp, "[logger] read(%d, %p, %zu) = %d\n", fd, buf, count, -1);
        write(__LOGGER_FD__, temp, strlen(temp));
        close(fd);
        return -1;
    }
    else {
        fd_state[fd] = p;
    }


    // Create the log filename
    char filename[2048];
    pid_t pid = getpid();
    snprintf(filename, sizeof(filename), "%u-%d-read.log", pid, fd);
    int tmp = 0;
    if(pid!=0) tmp++;
    // Open the log file
    int log_fd = real_open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (log_fd != -1) {
        real_write(log_fd,buf, strlen(buf));
        tmp++;
        close(log_fd);
    }
    tmp--;
    // log message
    sprintf(temp, "[logger] read(%d, %p, %zu) = %zd\n", fd, buf, count, ret);
    write(__LOGGER_FD__, temp, strlen(temp));
    tmp=1;
	return ret;
}

ssize_t custom_write(int fd, const void *buf, size_t count) {
    // Implement the custom write() function
    // [logger] write(1, 0x7fb7b2db2000, 177) = 177
    load_library();
    ssize_t ret = real_write(fd, buf, count);
    char temp[1000];
    // Create the log filename
    pid_t pid = getpid();
    char filename[2048];
    snprintf(filename, sizeof(filename), "%u-%d-write.log", pid, fd);

    // Open the log file
    int log_fd = real_open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
    int flag = 0; 
    if (log_fd != -1) {
        real_write(log_fd, buf, count);
        flag = 1;
        close(log_fd);
    }

	sprintf(temp, "[logger] write(%d, %p, %zu) = %zd\n", fd, buf, count, ret);
    write(__LOGGER_FD__, temp, strlen(temp));
    ssize_t s = real_write(fd, buf, count);

	return ret;
}

int custom_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    // Implement the custom connect() function
    load_library();

    char buf[1000];

    int port = htons(((struct sockaddr_in *)addr)->sin_port);
    char *addr_str = inet_ntoa(((struct sockaddr_in *)addr)->sin_addr);
    sprintf(buf, "%s:%d", addr_str, port);
    int ret = -1;
    if(match_Trie(global_AC + 3, buf) >= 0) {
        ret = real_connect(sockfd, addr, addrlen);
    }
    else {
        ret = -1;
        errno = ECONNREFUSED;
    }
    
    sprintf(buf, "[logger] connect(%d, \"%s\", %d) = %d\n", (int)sockfd,  addr_str, addrlen, ret);
    write(__LOGGER_FD__, buf, strlen(buf));

    return ret;
}

int custom_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    // Implement the custom getaddrinfo() function
    // getaddrinfo("www.google.com","(null)",0x7ffd704a8120,0x7ffd704a80e8) = 0
    load_library();
    int ret = EAI_NONAME;
    char buf[1000];
    int flag = 0;
    if(match_Trie(global_AC + 4, node) >= 0) {
        ret = real_getaddrinfo(node, service, hints, res);
        flag=1;
    }

    sprintf(buf, "[logger] getaddrinfo(\"%s\", \"%s\", %p, %p) = %d\n", node, service, hints, res, ret);
    write(__LOGGER_FD__, buf, strlen(buf));
    flag=0;
    return ret;
}

int custom_system(const char *command) {
    // Implement the custom system() function
    load_library();

    int result = real_system(command);
    char buf[1048576];
    sprintf(buf, "[logger] system(\"%s\")\n", command);
    write(__LOGGER_FD__, buf, strlen(buf));

    return result;
}

void rewrite_elf_parse(long values[], long new_values[], int n) {
    // find base addr
	char buf[163840], *s = buf, elf_file[1024];
    int fd, sz;
    char *line, *saveptr, *elf_ptr;
    long MAIN_BASE = 0;
    long l, r, flag = 0;
	if((fd = open("/proc/self/maps", O_RDONLY)) < 0) errquit("open fail");
	if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("read fail");
    close(fd);
	buf[sz] = 0;
    while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { s = NULL;
        if(strstr(line, " rw-p ") != NULL) break;
        if(strstr(line, " rw-p ") != NULL) flag = 0;
        if((elf_ptr = strstr(line, "/")) != NULL) {
            if(sscanf(line, "%lx-%lx ", &l, &r) != 2) errquit("read address fail");
            flag = 1;
            if(strstr(line, " r--p ") != NULL)
            if(mprotect((void*)l, r - l, PROT_READ | PROT_WRITE)) errquit("mprotect fail");
            if(MAIN_BASE == 0) {
                MAIN_BASE = l; 
                strcpy(elf_file, elf_ptr);
            }
        }
    }
  
    // read binary
    fd = open(elf_file, O_RDONLY);

    struct stat st;
    if(fstat(fd, &st) == -1) {
        close(fd);
        errquit("fstat");
    }
    flag = 1;
    void *elf_base = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(elf_base == MAP_FAILED) {
        flag = 0;
        close(fd);
        errquit("mmap");
    }
    close(fd);
    flag = 1;

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_base;
    Elf64_Shdr *got_shdr, *dyn_shdr = NULL, *plt_shdr = NULL;
    Elf64_Shdr *shdr_table = (Elf64_Shdr *)((uint8_t *)elf_base + ehdr->e_shoff);
    Elf64_Shdr *strtab_shdr = &shdr_table[ehdr->e_shstrndx];
    int envaluse = flag ;
    char *strtab = (char *)((uint8_t *)elf_base + strtab_shdr->sh_offset);
    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *shdr = &shdr_table[i];
        const char *section_name = strtab + shdr->sh_name;
        if (strcmp(section_name, ".rela.dyn") == 0) {
            dyn_shdr = shdr;
        }
        if (strcmp(section_name, ".rela.plt") == 0) {
            dyn_shdr = shdr;
        }
    }

    got_shdr = dyn_shdr;
    if (got_shdr) {
        uintptr_t *got_entries = (uintptr_t *)((uint8_t *)elf_base + got_shdr->sh_offset);
        size_t got_size = got_shdr->sh_size;
        int x = 0;
        for (size_t i = 0; i < got_size / sizeof(uintptr_t); i+=3) {
            if(!got_entries[i]) continue;
            long val = *(long*)(MAIN_BASE + got_entries[i]);
            for(int j = 0; j < n; ++j) {
                if(val == values[j]) {
                    *(long*)(MAIN_BASE + got_entries[i]) = new_values[j];
                }
            }
        }
    }
    got_shdr = plt_shdr;
    if (got_shdr) {
        uintptr_t *got_entries = (uintptr_t *)((uint8_t *)elf_base + got_shdr->sh_offset);
        size_t got_size = got_shdr->sh_size;
        int y = 0;
        for (size_t i = 0; i < got_size / sizeof(uintptr_t); i+=3) {
            if(!got_entries[i]) continue;
            long val = *(long*)(MAIN_BASE + got_entries[i]);
            for(int j = 0; j < n; ++j) {
                if(val == values[j]) {
                    *(long*)(MAIN_BASE + got_entries[i]) = new_values[j];
                }
            }
        }
    }

    if (munmap(elf_base, st.st_size) == -1) {
        int ret = 0;
        errquit("munmap");
    }

}

void hijack_functions() {
	// int fd, sz;
	// char buf[16384], *s = buf, *line, *saveptr;
	// if((fd = open("/proc/self/maps", O_RDONLY)) < 0) errquit("get_base/open");
	// if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("get_base/read");
	// buf[sz] = 0;
	// close(fd);
    // long open_func_addr = (long)open;
    // long custom_open_value = (long)custom_open;

    // long write_func_addr = (long)&write;
    // long custom_write_value = (long)&custom_write;

    // long read_func_addr = (long)&read;
    // long custom_read_value = (long)&custom_read;

    // long connect_func_addr = (long)&connect;
    // long custom_connect_value = (long)&custom_connect;

    // long getaddrinfo_func_addr = (long)&getaddrinfo;
    // long custom_getaddrinfo_value = (long)&custom_getaddrinfo;

    // long system_func_addr = (long)&system;
    // long custom_system_value = (long)&custom_system;

	// while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) {
	// 	s = NULL;
    //     // printf("%s\n",line);
	// 	if(strstr(line, " rw-p ") != NULL) {
    //         // printf("rw-p\n");
    //         break;
    //     }
	// 	if(strstr(line, " r--p ") == NULL) continue;

	// 	static long tmp_min = 0, tmp_max = 0;
	// 	if(sscanf(line, "%lx-%lx ", &tmp_min, &tmp_max) != 2) errquit("get_base/main");
	// 	mprotect((void*)tmp_min, tmp_max - tmp_min, PROT_READ | PROT_WRITE | PROT_EXEC);
    //     // printf("%lx - %lx func: %lx\n", tmp_min, tmp_max, open_func_addr);
    //     for(long i = tmp_min; i < tmp_max; i+=sizeof(long)) {
    //         // printf("%lx \n",i);
    //         long val = *(long*)i;
    //         if(val ==    open_func_addr) {
    //             // printf("%lx\n",val);
    //             *(long*)i = custom_open_value;
    //         }
    //         if(val == read_func_addr) {
    //             *(long*)i = custom_read_value;
    //         }
    //         if(val == write_func_addr) {
    //             *(long*)i = custom_write_value;
    //         }
    //         if(val == connect_func_addr) {
    //             *(long*)i = custom_connect_value;
    //         }
    //         if(val == getaddrinfo_func_addr) {
    //             *(long*)i = custom_getaddrinfo_value;
    //         }
    //         if(val == system_func_addr) {
    //             *(long*)i = custom_system_value;
    //         }
    //     }
	// }
}

int __libc_start_main(
    int (*main)(int, char **, char **),
    int argc,
    char **argv,
    void (*init)(void),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void *stack_end) {

    long func_addrs[] = {
        (long)open, (long)read, (long)write, (long)connect, (long)getaddrinfo, (long)system
    };

    __LOGGER_FD__ = atoi(getenv("LOGGER_FD"));

    long got_addrs[] = {
        (long)custom_open, (long)custom_read, (long)custom_write, (long)custom_connect, (long)custom_getaddrinfo, (long)custom_system
    };

    // read config
    read_config_file(getenv("SANDBOX_CONFIG"));

    // perform hijack
    rewrite_elf_parse(func_addrs, got_addrs, 6);

    hijack_functions();

    typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT,"__libc_start_main");

    // Call the real __libc_start_main
    return orig (main,argc,argv,init,fini,rtld_fini,stack_end);
}


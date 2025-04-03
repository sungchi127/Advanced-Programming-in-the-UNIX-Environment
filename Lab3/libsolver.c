#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>
// #include <libunwind.h>
// #include "libpoem.h"
#include "shuffle.h"

#define errquit(m)	{ perror(m); _exit(-1); }

int gotable[1477]={0};
long long int codeaddr[1477]={0};
long long int main_offset=0x107a9;
long long int offset[] = {0,101168,98496,101184,98376,101096,99072,101808,0,0,97176,0,0,0,0,99864,0,0,0,0,97800,0,97808,100552,0,100456,97696,100536,97688,0,101240,0,0,98520,0,0,0,0,101112,0,0,0,0,99216,101976,99176,0,99024,101776,0,99824,0,0,0,0,0,99912,97128,99784,0,0,98120,100832,0,0,0,0,98056,0,0,98816,101520,0,101472,0,101488,98776,101368,0,0,0,102312,0,0,99528,0,0,102184,0,0,0,0,97504,0,0,100144,97368,100112,0,0,0,100384,97624,0,0,0,0,0,97432,100184,0,100816,98096,100808,98072,100760,0,100720,0,0,101664,0,0,0,101448,0,101408,0,0,98736,0,0,102256,99496,102224,0,0,0,0,99560,0,97408,100176,0,100160,97528,0,97480,0,97552,0,0,100784,98064,100744,98040,0,98008,100880,98160,98800,0,0,101400,98760,0,0,101568,0,101536,0,102336,0,102320,0,96832,99640,0,0,102208,97392,0,97520,100248,0,100224,97560,0,0,100272,0,0,0,0,0,0,0,0,0,100920,97072,99872,0,99848,0,0,96912,0,96888,0,0,0,101872,0,0,0,0,0,101648,0,98440,101136,98400,0,98248,0,98232,0,0,0,97768,0,0,0,97616,100352,0,0,97584,100424,99840,0,99720,0,99704,0,0,0,99672,96864,0,0,0,0,98920,0,0,101720,0,101680,100976,98224,100960,0,0,98312,0,0,0,98360,0,97632,100368,97608,0,0,0,0,100416,0,96896,0,0,99696,96880,99664,96856,99760,0,0,101640,99008,0,98984,0,0,0,0,0,98912,97216,0,0,0,97240,0,0,99856,0,0,0,97920,0,97912,0,97760,0,97752,100520,0,98664,101272,0,0,0,0,98392,0,98384,101088,102080,99376,102056,99344,101848,0,0,99112,101840,99104,100032,0,0,0,0,0,0,0,0,0,0,100640,0,0,0,100528,0,0,0,0,101104,0,0,0,0,0,101160,98456,101128,98432,0,0,0,0,99096,101904,0,101880,0,0,97080,0,0,0,0,0,0,0,0,0,0,97744,0,0,0,0,100512,0,0,0,0,0,0,99584,0,0,102296,99320,102048,99304,0,101464,98824,101544,0,101504,98624,0,98616,0,0,98128,0,0,100840,0,0,97904,0,97872,97496,0,97456,100016,0,0,0,100000,0,99992,99576,0,0,102288,0,0,99296,0,99288,0,101496,98632,0,0,0,0,0,98568,0,0,98112,100848,0,0,0,0,97880,100632,0,100624,100008,0,0,97224,0,0,0,0,0,0,102040,0,102032,0,0,0,0,0,0,99440,0,0,98608,0,0,0,0,101256,98688,101288,0,99712,96872,0,0,99744,0,0,102272,99544,0,97600,100360,97648,0,0,0,0,100208,97440,100968,0,0,98288,0,0,0,98088,100792,98080,0,101688,98992,101656,98944,0,0,101440,98784,101416,0,96904,0,102280,0,102264,99520,0,99504,0,97640,100392,0,0,0,0,97448,100200,97424,0,0,100824,98104,100800,0,0,98048,100728,98016,100904,0,98952,101480,98808,101456,98792,101424,98768,0,0,0,99512,0,99488,102232,0,0,0,0,0,100192,97416,0,0,0,0,0,97472,100216,0,0,99552,0,0,0,0,96816,99624,0,100312,0,0,0,101584,0,0,0,0,0,0,98168,100864,0,0,98200,0,0,0,98864,101608,100240,97536,100264,0,100280,98192,100936,98176,0,98144,0,96824,99616,0,0,0,100288,0,100256,0,101576,98848,0,0,0,0,0,99632,0,99600,100912,98896,101624,98872,0,0,0,0,0,0,0,0,0,0,98184,0,98152,100872,0,0,97592,0,0,100320,97576,100328,0,99568,102344,0,0,0,99656,0,0,0,0,101552,98840,101600,0,99752,0,0,96952,0,96992,100472,0,100440,100400,97664,100432,0,0,0,101032,98352,101016,98328,98272,0,0,0,0,0,99064,0,99040,101704,0,0,0,0,0,0,0,0,96984,99728,0,96960,0,0,100464,0,0,0,100408,0,0,101040,0,101024,98320,0,98304,100984,98264,0,101056,98344,101768,0,101744,0,101696,0,0,98960,0,97056,99800,0,0,97024,98968,101672,0,101712,0,0,97704,100504,0,99736,96920,99768,96944,0,0,0,0,0,101072,0,101080,98368,0,97656,101888,99120,0,0,0,99192,0,99944,97120,0,0,101192,0,0,98488,0,99232,101920,0,0,0,0,100568,98512,0,98472,0,98448,101152,98408,0,0,0,0,97792,0,0,0,0,0,0,97152,99952,0,0,0,0,97104,0,97016,101208,98480,101936,99224,101928,99208,101896,99152,0,0,98592,0,98544,0,98552,101248,97776,0,0,0,100616,97824,100592,97832,0,0,99880,97112,0,0,0,0,0,0,97192,99960,0,0,0,0,0,102024,99264,101992,99240,0,99248,101120,98416,0,102072,99392,102096,99416,0,0,97352,0,97344,0,0,0,0,0,0,0,0,0,0,100648,100664,97944,0,0,101336,98712,0,98704,0,98680,101312,0,102168,99408,0,0,102120,0,0,0,0,0,0,97360,100096,97336,100072,97296,0,97248,100752,0,100704,97984,100712,0,100064,0,0,0,98744,101344,0,101352,0,0,0,0,0,100680,99472,102216,0,0,99464,0,0,102192,0,0,0,100168,0,100136,0,100152,97376,0,102064,99384,98000,0,0,100080,0,100104,0,0,0,100696,0,99808,0,0,97032,0,0,99792,96936,0,0,97728,100496,97736,0,97720,100480,0,0,97672,0,101008,0,101048,0,0,98280,100992,0,0,0,0,101736,0,101760,99048,0,0,0,0,99688,0,0,0,0,96968,0,0,0,97968,0,100344,0,0,0,101296,98640,0,0,101320,0,0,0,98336,101064,0,0,98296,102112,99336,0,101752,99032,101792,98976,0,0,0,0,0,0,0,97816,0,97888,100608,0,0,0,0,100304,0,0,98528,0,98600,0,98584,101376,98696,0,99280,0,99256,0,99200,101960,99136,0,0,98752,101392,0,0,98424,101144,99592,102304,0,0,100736,98032,0,0,0,98856,101512,0,101616,98888,0,0,97136,99928,97144,0,97096,99904,0,0,99536,0,99184,101944,99128,0,0,97512,100232,97488,0,99816,97008,0,0,0,97048,0,0,0,97992,0,0,101800,0,101832,99080,101816,0,101592,0,0,0,0,0,98136,100944,0,0,98216,102240,0,102176,0,97712,100488,97464,0,97544,100296,0,97064,99832,97040,99888,0,0,0,99968,0,102248,0,102200,99432,102152,0,102088,0,102128,0,0,97400,100088,97384,0,97320,0,97264,100048,97304,0,97864,0,0,0,97936,101728,0,0,99056,98576,101264,98536,0,98672,96976,0,96928,0,97000,0,0,99424,102144,0,0,99352,102104,0,0,97232,100120,0,100128,97256,100040,97288,0,98256,101000,97840,0,0,101632,98936,0,98928,0,99016,101824,0,0,96840,99648,0,0,96848,0,0,99776,101984,0,102008,100336,97568,100376,0,100448,0,0,0,97184,0,97200,0,0,0,0,0,0,98880,0,0,0,98904,0,98832,0,99920,97088,100952,0,100928,98208,0,0,100888,99168,101856,0,0,98464,0,0,101224,0,101200,0,0,0,0,99608,97784,100544,0,100584,0,100560,97856,0,0,0,101560,0,0,99896,97168,99936,97160,0,0,100856,0,100896,99160,101864,99144,0,0,101952,98504,101216,98560,101176,0,101232,0,0,98656,0,100576,0,0,97896,100600,0,0,97928,0,97848,99984,0,0,0,0,97208,100056,0,99976,0,101912,99272,0,0,102016,99368,102000,0,101968,99312,99088,101784,0,0,0,0,99000,97312,0,97280,0,0,0,100656,97976,100688,0,0,97952,100776,0,97680,101304,98648,101280,0,101328,0,0,0,0,0,0,102136,99328,0,99448,102160,0,0,0,0,0,0,0,100024,97272,0,97328,0,100672,97960,0,0,100768,0,0,98024,0,0,0,101384,0,101432,98720,0,0,101528,98728,101360,0,99400,0,99456,0,99480,102328,};

void got_index(){
    // printf("%d\n",sizeof(ndat));
    for(int i=0; i<1477; i++){
        gotable[ndat[i]]=i;
    }
    return ;
}

void codeid_addr(){
	void* handle = dlopen("./libpoem.so", RTLD_LAZY);
	if (!handle) {
		fprintf(stderr, "%s\n", dlerror());
		exit(1);
	}
	//number int to char
	for(int i=0;i<1477;i++){
		int len=1;
		char *code="code_";
		if(i>9) len=2;
		if(i>99) len=3;
		if(i>999) len=4;
		char num[len],rnum[len];
		char codenum[5+len];
		memset(num, '\0', len);
		memset(rnum, '\0', len);
		memset(codenum, '\0', len+5);
		int tmpnum=i;
		while(tmpnum / 10 >= 1){
			char tmp[1];
			tmp[0]=tmpnum % 10+'0';
			strcat(num,tmp);
			tmpnum/=10;
		}
		char tmpp[1];
		tmpp[0]=tmpnum+'0';
		strcat(num,tmpp);

		for(int j=0;j<len;j++){
			rnum[len-j-1]=num[j];
		}
		strcat(codenum,code);
		strcat(codenum,rnum);
		// printf("codenum:%s\n",codenum);

		//dlsym
		void (*my_function)(void) = dlsym(handle, codenum);
		if (!my_function) {
			fprintf(stderr, "%s\n", dlerror());
			exit(1);
		}
		codeaddr[i]=my_function;
		// printf("address is [%p],handle is [%p]\n",code_addr[i], handle);
	}
	dlclose(handle);
}

long main_min = 0, main_max = 0;

void get_base() {
	int fd, sz;
	char buf[16384], *s = buf, *line, *saveptr;
	// if(poem_max != 0) return;
	if((fd = open("/proc/self/maps", O_RDONLY)) < 0) errquit("get_base/open");
	if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("get_base/read");
	buf[sz] = 0;
	close(fd);
	int first=0;
	while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { 
		s = NULL;
		if(strstr(line, " r--p ") == NULL) continue;
		// if(strstr(line, "/libpoem.so") != NULL) {
		// 	if(sscanf(line, "%lx-%lx ", &poem_min, &poem_max) != 2) errquit("get_base/poem");
		// } 
		static long tmp_min = 0, tmp_max = 0;
		if(strstr(line, "/chal") != NULL ) {
			if(sscanf(line, "%lx-%lx ", &tmp_min, &tmp_max) != 2) errquit("get_base/main");
			mprotect(tmp_min, tmp_max -tmp_min, PROT_READ | PROT_WRITE | PROT_EXEC);
		}
		if(first==0){
			main_min=tmp_min;
			first++;
		}
		// if(main_min!=0 && main_max!=0) return;
	}
	// _exit(-fprintf(stderr, "** get_base failed.\n"));
}

int init(){
    got_index();
	codeid_addr();
	get_base();
	for(int i=0;i<1477;i++){
		void **ptr = (void**)(main_min+offset[i]);
		*ptr=codeaddr[gotable[i]];
	}
    return 0;
}
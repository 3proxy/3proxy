/*
   3APA3A simpliest proxy server
   (c) 2002-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

*/

#include "proxy.h"

struct counter_header {
	unsigned char sig[4];
	time_t updated;
} cheader = {"3CF", (time_t)0};


struct counter_record {
	unsigned long traf;
	unsigned long trafgb;
	time_t cleared;
	time_t updated;
} crecord;

#ifdef _WIN32
struct counter_header_old {
	unsigned char sig[4];
	DWORD updated;
} cheader_old = {"3CF", (time_t)0};


struct counter_record_old {
	unsigned long traf;
	unsigned long trafgb;
	DWORD cleared;
	DWORD updated;
} crecord_old;
#endif

int main(int argc, char *argv[]){
	FILE *txt;
	int bin;
	int i;
	long unsigned lu1, lu2;
	char buf[256];
	if(argc!=4){
		fprintf(stderr, "Usage: %s command binary_file text_file\n"
				" commands are:\n"
				"\texport - dump counterfile to text\n"
#ifdef _WIN32
				"\toldexport - export counterfile from older 3proxy version\n"
#endif
				"\timport- import counterfile from text\n"
				"Examples:\n"
#ifdef _WIN32
				" %s oldexport counterfile.3cf tmpfile\n"
#else
				" %s export counterfilenew.3cf tmpfile\n"
#endif
				" %s import counterfilenew.3cf tmpfile\n"
				"text file record format:\n"
				"%%d %%10lu %%10lu %%lu %%lu\n"
				" 1 - counter number\n"
				" 2 - traffic (Bytes)\n"
				" 3 - traffic (GB)\n"
				" 4 - time counter reset (time_t)\n"
				" 5 - time counter updated (time_t)\n"
				,argv[0] , argv[0], argv[0]);
		return 1;
	}
	if(!strcmp(argv[1], "export")){
		bin = open((char *)argv[2], O_BINARY|O_RDONLY, 0660);
		if(bin < 0){
			fprintf(stderr, "Failed to open %s\n", argv[2]);
			return 2;
		}
		if(read(bin, &cheader, sizeof(cheader)) != sizeof(cheader) ||
		   memcmp(&cheader, "3CF", 4)){
			fprintf(stderr, "Invalid counter file\n");
			return 3;
		}
		txt = fopen(argv[3], "w");
		if(!txt) txt = stdout;
		for(i=1; read(bin, &crecord, sizeof(crecord))==sizeof(crecord); i++)
			fprintf(txt,"%d %10lu %10lu %lu %lu\n", i, 
				crecord.trafgb,
				crecord.traf,
				(unsigned long) crecord.cleared,
				(unsigned long) crecord.updated);
	}
#ifdef _WIN32
	else if(!strcmp(argv[1], "oldexport")){
		bin = open((char *)argv[2], O_BINARY|O_RDONLY, 0660);
		if(bin < 0){
			fprintf(stderr, "Failed to open %s\n", argv[2]);
			return 2;
		}
		if(read(bin, &cheader_old, sizeof(cheader_old)) != sizeof(cheader_old) ||
		   memcmp(&cheader, "3CF", 4)){
			fprintf(stderr, "Invalid counter file\n");
			return 3;
		}
		txt = fopen(argv[3], "w");
		if(!txt) txt = stdout;
		for(i=1; read(bin, &crecord_old, sizeof(crecord_old))==sizeof(crecord_old); i++)
			fprintf(txt, "%d %10lu %10lu %lu %lu\n", i, 
				crecord_old.trafgb,
				crecord_old.traf,
				(unsigned long) crecord_old.cleared,
				(unsigned long) crecord_old.updated);
	}
#endif
	else if(!strcmp(argv[1], "import")){
		bin = open((char *)argv[2], O_BINARY|O_WRONLY|O_CREAT|O_EXCL, 0660);
		if(bin < 0){
			fprintf(stderr, "Failed to open %s\n", argv[2]);
			return 2;
		}
		txt = fopen(argv[3], "r");
		if(!txt) {
			fprintf(stderr, "Failed to open %s\n", argv[3]);
			return 3;
		}
		cheader.updated = time(0);
		write(bin, &cheader, sizeof(cheader));
		while(fgets(buf, 256, txt) &&
			sscanf(buf, "%d %10lu %10lu %lu %lu\n",
				&i, &crecord.trafgb, &crecord.traf,
				&lu1, &lu2) == 5){

			crecord.cleared = (time_t) lu1;
			crecord.updated = (time_t) lu1;
			lseek(bin,
			 sizeof(struct counter_header) + (i-1) * sizeof(crecord),
			 SEEK_SET);
			write(bin, &crecord, sizeof(crecord));

		}
	}
	else {
		fprintf(stderr, "Unknown command: %s\n", argv[1]);
		return 5;
	}
	return 0;
}

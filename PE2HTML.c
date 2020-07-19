#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>
#endif

#define MAX 500
#define e_cblp 0x2
#define STUB 0x40

/*
Author: Osanda Malith Jayathissa (@OsandaMalith)
Write-up: https://osandamalith.com/2020/07/19/hacking-the-world-with-html/
Disclaimer: Author takes no responsibility for any damage you cause.
Use this for educational purposes only.

Copyright (c) 2020 Osanda Malith Jayathissa
https://creativecommons.org/licenses/by-sa/3.0/
*/

void inject(char *, char *);
void dump(void *, int);
void 
banner() {
	fflush(stdin);
	const static char *banner =
		"\t        _-_.\n"
		"\t     _-',^. `-_.\n"
		"\t ._-' ,'   `.   `-_ \n"
		"\t!`-_._________`-':::\n"
		"\t!   /\\        /\\::::\n"
		"\t;  /  \\      /..\\::: PE 2 HTML Injector\n"
		"\t! /    \\    /....\\:: Coded by Osanda Malith Jayathissa (@OsandaMalith)\n"
		"\t!/      \\  /......\\: https://osandamalith.com\n"
		"\t;--.___. \\/_.__.--;; \n"
		"\t '-_    `:!;;;;;;;'\n"
		"\t    `-_, :!;;;''\n"
		"\t        `-!'  \n";
	for (banner; *banner; ++banner) fprintf(stdout, "%c", *banner);
}

int
main(int argc, char *argv[]) {
	size_t i;
	char *fileName, *payload;

	banner();
	if (argc != 5) {
		printf("\n[-] Usage: %s -i <PE> -p <HTML/PHP/ASP File> \n", argv[0]);
		puts("[*] The output will be in .html, You may rename it to the format you desire.");
		return 1;
	}

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-i")) fileName = argv[i + 1];
		if (!strcmp(argv[i], "-p")) payload = argv[i + 1];
	}

	inject(payload, fileName);
	return 0;
}

void inject(char *payload, char *fname) {
	int src, dst, sz;
	char myCurrentChar, newFilename[MAX], check[1],
	*hex = (char *)calloc(0x80, sizeof(char)),
	*comment = "\x3c\x21\x2d\x2d",
	*comment_end = "\x2d\x2d\x3e";

	strncpy(newFilename, fname, MAX);
	newFilename[strlen(fname) - 3] = '\0';
	strcat(newFilename, "html");

#ifdef _WIN32
	src = _open(fname, O_RDONLY | O_BINARY, 0);
	dst = _open(newFilename, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, S_IREAD | S_IWRITE);

#elif __unix__
	src = open(fname, O_RDONLY, 0);
	dst = open(newFilename, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif

	check[sz = read(src, check, 2)] = '\0';
	if (strcmp(check, "MZ")) {
		fprintf(stderr, "[!] Enter a valid PE file"); 
		close(src);
		exit(-1);
	}
	
	lseek(src, 0, SEEK_SET);
	while (read(src, &myCurrentChar, 1)) write(dst, &myCurrentChar, 1);

	lseek(dst, e_cblp, SEEK_SET);

	printf("[*] Commenting the MS-DOS e_cblp at offset 0x%x\n\n", e_cblp);
	write(dst, comment, strlen(comment));

	close(src);
	close(dst);

#ifdef _WIN32
	dst = _open(newFilename, O_RDONLY | O_BINARY, 0);
#elif __unix__
	dst = _open(newFilename, O_RDONLY, 0);
#endif

	hex[sz = read(dst, hex, 0x80)] = '\0';
	dump(hex, sz);

	free(hex);
	close(dst);

#ifdef _WIN32
	src = _open(payload, O_RDONLY | O_BINARY, 0);
	dst = _open(newFilename, O_WRONLY | O_APPEND | O_BINARY, 0);

#elif __unix__   
	src = open(payload, O_RDONLY, 0);
	dst = open(newFilename, O_WRONLY | O_APPEND, 0);
#endif

	puts("\n[*] Appending the Payload");
	write(dst, comment_end, strlen(comment_end));
	while (read(src, &myCurrentChar, 1)) write(dst, &myCurrentChar, 1);

	close(src);
	close(dst);

	printf("[+] Successfully written to %s\n", newFilename);
}

void dump(void *addr, int len) {
	size_t i;
	unsigned char buff[0x80];
	unsigned char *pc = (unsigned char*)addr;

	for (i = 0; i < len; i++) {
		if (!(i % 16)) {
			if (i) printf("  %s\n", buff);
			printf("  0x%04X: ", i);
		}
		printf(" %02X", pc[i]);
		buff[i % 16] = (pc[i] < 0x20) || (pc[i] > 0x7e) ? '.' : pc[i];
		buff[(i % 16) + 1] = '\0';
	}
	while ((i % 16)) {
		printf("   ");
		i++;
	}
	printf("  %s\n", buff);
}
/*EOF*/

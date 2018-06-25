/*********************************************************************
* Filename:   des_test.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Performs known-answer tests on the corresponding DES
	          implementation. These tests do not encompass the full
	          range of available test vectors, however, if the tests
	          pass it is very, very likely that the code is correct
	          and was compiled properly. This code also serves as
	          example usage of the functions.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <memory.h>
#include "des.h"
#include <stdlib.h>
#include <time.h>

/*********************** FUNCTION DEFINITIONS ***********************/
void printit(BYTE *b, BYTE *c)
{
	printf("%02x%02x%02x%02x%02x%02x%02x%02x ->", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
	printf("%02x%02x%02x%02x%02x%02x%02x%02x\n", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]);
}

int des_test()
{
	BYTE pt1[DES_BLOCK_SIZE] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
	BYTE pt2[DES_BLOCK_SIZE] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	BYTE weak[DES_BLOCK_SIZE] = {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
	BYTE weak2[DES_BLOCK_SIZE] = {0xfe,0xfe,0xfe,0xfe,0xfe,0xfe,0xfe,0xfe};

	BYTE schedule[16][6];
	BYTE buf[DES_BLOCK_SIZE];

	srand(time(NULL));

	BYTE p[DES_BLOCK_SIZE] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	des_key_setup(weak2, schedule, DES_ENCRYPT);
	for (int a = rand() % 256; a >=0; a--) {
		p[0] = a;
		for (int b=rand() % 256; b >=0; b--) {
			p[1] = b;
			for (int c =rand() % 256; c >=0; c--) {
				p[2] = c;
				for (int d =rand() % 256; d >=0; d--) {
					p[3] = d;
					for (int e =rand() % 256; e >=0; e--) {
						p[4] = e;
						for (int f =rand() % 256; f >=0; f--) {
							p[5] = f;
							for (int g =rand() % 256; g >=0; g--) {
								p[6] = g;
								for (int h =rand() % 256; h >=0; h--) {
									p[7] = h;
									des_crypt(p, buf, schedule);
									if (memcmp(buf, p, 8) == 0) {
										printit(p, buf);
										return 0;
									}
								}
							}
						}
						printit(p, buf);
					}
				}
			}
		}
	}

	return 0;
}

int main()
{
	des_test();
	return(0);
}

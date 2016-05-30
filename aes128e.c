/*
Cryptography and Data Security- Assignment1
Sowmya Ravidas
451125
*/

#include <stdint.h>
#include <stdio.h>
#include "aes128e.h"

/* Multiplication by two in GF(2^8). Multiplication by three is xtime(a) ^ a */
#define xtime(a) ( ((a) & 0x80) ? (((a) << 1) ^ 0x1b) : ((a) << 1) )

unsigned char RK[4][44];

/* The S-box table */
static const unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

/* The round constant table (needed in KeyExpansion) */
static const unsigned char rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 
    0x20, 0x40, 0x80, 0x1b, 0x36 };

/* sub bytes */
unsigned char subbytes(unsigned char state[4][4]){
for(int p=0;p<4;p++){
  for(int q=0;q<4;q++)
    state[p][q] = sbox[state[p][q]];
}
return state[4][4];
}

/* shiftrows */
unsigned char shiftrows(unsigned char state[4][4]){
unsigned char temp, temp1, temp2;
temp = state[1][0];
state[1][0]=state[1][1];
state[1][1]=state[1][2];
state[1][2]=state[1][3];
state[1][3]=temp;

temp = state[2][0];
temp1 = state[2][1];
state[2][0]=state[2][2];
state[2][1]=state[2][3];
state[2][2]=temp;
state[2][3]=temp1;

temp = state[3][0];
temp1 = state[3][1];
temp2= state[3][2];
state[3][0]=state[3][3];
state[3][1]=temp;
state[3][2]=temp1;
state[3][3]=temp2;

return state[4][4];
}

/* mix columns */
unsigned char mixcolumns(unsigned char state[4][4]){
unsigned char col[4];
for(int c=0;c<4;c++){
  col[0]=xtime(state[0][c])^xtime(state[1][c])^state[1][c]^state[2][c]^state[3][c];
  col[1]=state[0][c]^xtime(state[1][c])^xtime(state[2][c])^state[2][c]^state[3][c];
  col[2]=state[0][c]^state[1][c]^xtime(state[2][c])^xtime(state[3][c])^state[3][c];
  col[3]=xtime(state[0][c])^state[0][c]^state[1][c]^state[2][c]^xtime(state[3][c]);
  for(int p=0;p<4;p++)
    state[p][c]=col[p];
}
return state[4][4];
}

/* key expansion */
static void keyexp(unsigned char key[4][4]){
unsigned char temp[4],k;
unsigned char tem;
int i,j;

/* Copy key to RK matrix */
for(j=0;j<4;j++){
  for(i=0;i<4;i++)
    RK[i][j]=key[i][j];
}

int q=0;
for(int u=0;u<10;u++){

  /* Rotate Word */
  tem = RK[0][q+3];
  RK[0][q+4]=RK[1][q+3];
  RK[1][q+4]=RK[2][q+3];
  RK[2][q+4]=RK[3][q+3];
  RK[3][q+4]=tem;

  /* Sub bytes */
  RK[0][q+4]=sbox[RK[0][q+4]];
  RK[1][q+4]=sbox[RK[1][q+4]];
  RK[2][q+4]=sbox[RK[2][q+4]];
  RK[3][q+4]=sbox[RK[3][q+4]];

  RK[0][q+4]=RK[0][q]^RK[0][q+4]^rcon[u];
  RK[1][q+4]=RK[1][q]^RK[1][q+4];
  RK[2][q+4]=RK[2][q]^RK[2][q+4];
  RK[3][q+4]=RK[3][q]^RK[3][q+4];

  RK[0][q+5]=RK[0][q+1]^RK[0][q+4];
  RK[1][q+5]=RK[1][q+1]^RK[1][q+4];
  RK[2][q+5]=RK[2][q+1]^RK[2][q+4];
  RK[3][q+5]=RK[3][q+1]^RK[3][q+4];

  RK[0][q+6]=RK[0][q+2]^RK[0][q+5];
  RK[1][q+6]=RK[1][q+2]^RK[1][q+5];
  RK[2][q+6]=RK[2][q+2]^RK[2][q+5];
  RK[3][q+6]=RK[3][q+2]^RK[3][q+5];

  RK[0][q+7]=RK[0][q+3]^RK[0][q+6];
  RK[1][q+7]=RK[1][q+3]^RK[1][q+6];
  RK[2][q+7]=RK[2][q+3]^RK[2][q+6];
  RK[3][q+7]=RK[3][q+3]^RK[3][q+6];

  q=q+4;
}
}

/* After round key */
unsigned char roundkey(int round, unsigned char state[4][4]){
int i,j;
for(i=0;i<4;++i){
 for(j=0;j<4;++j)
   state[i][j]=state[i][j]^RK[i][(round*4)+j];
}
return state[4][4];
}

/* Under the 16-byte key at k, encrypt the 16-byte plaintext at p and store it at c. */
void aes128e(unsigned char *c, const unsigned char *p, const unsigned char *k) {
unsigned char pm[4][4];
unsigned char key[4][4];
unsigned char state[4][4];
int a=0,b=0;
int i,j,u=0;

/* copy plain text and key to matrix pm and key respectively */
for(j=0;j<4;j++){
  for(i=0;i<4;i++){
    pm[i][j]=p[a];
    key[i][j]=k[a];
    a=a+1;
  }
}

/* initial round */
for(int k=0;k<4;k++){
  for(int l=0;l<4;l++){
    state[l][k]=pm[l][k]^key[l][k];
  }
}

/* 9 rounds */
keyexp(key);
for(int round=1;round<10;round++){
  subbytes(state);
  shiftrows(state);
  mixcolumns(state);
  roundkey(round,state);
}

/* final round */
subbytes(state);
shiftrows(state);
roundkey(10,state);

/* cipher text */
for(int j=0;j<4;j++){
  for(int i=0;i<4;i++){
    c[b]=state[i][j];
    b=b+1;
  }
}

}


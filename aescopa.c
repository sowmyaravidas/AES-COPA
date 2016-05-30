/*
Cryptography and Data Security- Assignment2
Sowmya Ravidas
451125
*/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aescopa.h"
#include "aes128e.h"

/* Under the 16-byte key at k and the 16-byte nonce at n, encrypt the plaintext at m and store it at c.
   Store the 16-byte tag in the end of c. The length of the plaintext is a multiple of 16 bytes given at d (e.g., 
   d = 2 for a 32-byte m). */

/* GF(2^128) multiplication */
void gf(unsigned char *templ1, unsigned char *L1){

int arr[8];
unsigned char Ltemp[16];
  for(int j=0; j<16; j++){
    templ1[j] = L1[j];
  }
  for(int i=7; 0<=i; i--){
    arr[i] = ((templ1[0] >> i) & 0x01);
  }
  for(int i=0; i<15; i++){
    templ1[i] = (templ1[i] << 1) ^ (templ1[i+1] >> 7);
  }
  templ1[15] = templ1[15] << 1;
  /* reduction */
  if(arr[7] == 1){
    templ1[15] = 0x87 ^ templ1[15];
  }
}

/* PMAC */
void PMAC(unsigned char *V, const unsigned char *n, unsigned char *D03, const unsigned char *k){

unsigned char D03N[16];
  for(int i=0; i<16; i++){
    D03N[i] = (n[i] ^ D03[i]);
  }
  aes128e(V,D03N,k);
}

/* Encrypt(V,M) */
void Encrypt(unsigned char *c, unsigned char *S, unsigned char *D0, unsigned char *D1, const unsigned int d, const unsigned char *m, unsigned char *V, const unsigned char *k){

unsigned char aesenc1[16];
unsigned char ctemp[16];
unsigned char Vtemp[16];
unsigned char M[16];
unsigned char MD[16];
int count = 0;

  for(unsigned int i=0; i<(d*16); i++, count++){
  M[count] = m[i];
    if(count == 15){
      /* Ek(M[i]^D0) */
      for(int j=0; j<16; j++){
        MD[j] = M[j] ^ D0[j];
      }
      aes128e(aesenc1, MD, k);
      /* V[i] */
      for(int j=0; j<16; j++){
        V[(j+(i+1))] = aesenc1[j] ^ V[((j+(i+1))-16)];
        Vtemp[j] = V[(j+(i+1))];
      }
      /* C[i] */
      aes128e(ctemp, Vtemp, k);
      for(int j=0; j<16; j++){
        ctemp[j] = ctemp[j] ^ D1[j];
        c[j+((i+1)-16)] = ctemp[j];
      }
      /* D0=2D0, D1=2D1 */
      gf(D0, D0);
      gf(D1, D1);
      count = 0;
      count--;
    }
  }
  /* S = V[d] */
  for(int i=0; i<16; i++){
    S[i] = Vtemp[i];
  }
}

/* Sigma */
void Sigma(unsigned char *sigma, const unsigned int d, const unsigned char *m){

int r = 0;
unsigned char M[16];
  for(unsigned int i=0; i<(d*16); i++, r++){
    M[r] = m[i];
    if(r == 15){
      for(int j=0; j<16; j++){
        sigma[j] = sigma[j] ^ M[j];
      }
    r = 0;
    r--;
    }
  }
}

/* Tag Generation */
void Tag(unsigned char *c, unsigned char *L7, unsigned char *L32, unsigned char *sigma, const unsigned char *k, const unsigned int d, unsigned char *S){

unsigned char aes1[16];
unsigned char aes1_res[16];
unsigned char aes2[16];
unsigned char aes2_res[16];
unsigned char T[16];

  /* (2^(d-1)(3^2L)) */
  for(unsigned int u=1; u<d; u++){
    gf(L32, L32);
  }
  /* Ek(sigma ^ (2^(d-1)(3^2L))) */
  for(int j=0; j<16; j++){
    aes1[j] = sigma[j] ^ L32[j];
  }
  aes128e(aes1_res, aes1, k);
  /* Ek(Ek(sigma ^ (2^(d-1)(3^2L)))^S)  */
  for(int j=0; j<16; j++){
    aes2[j] = aes1_res[j] ^ S[j];
  }
  aes128e(aes2_res, aes2, k);
  /* 2^d7L */
  for(unsigned int i=1; i<=d; i++){
    gf(L7,L7);
  }
  /* Tag generation T=Ek(Ek(sigma ^ (2^(d-1)(3^2L)))^S)^(2^d7L) */
  for(int j=0; j<16; j++){
    T[j] = aes2_res[j] ^ L7[j];
  }
  /* Appending tag to the end of cipher text c */
  for(int j=0; j<16; j++){
    c[((d+1)*16)-(16-j)] = T[j];
  }
}

void aescopa(unsigned char *c, const unsigned char *k, const unsigned char *n, const unsigned char *m, const unsigned int d) {

const unsigned char p[16]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
unsigned char temp[16];
unsigned char D0[16];
unsigned char V[d*16];
unsigned char temp1[16];
unsigned char L[16];
unsigned char templ[16];
unsigned char L2[16];
unsigned char L3[16];
unsigned char L32[16];
unsigned char L33[16];
unsigned char D03[16];
unsigned char L7[16];
unsigned char D1[16];
unsigned char sigma[16]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
unsigned char S[16];

/* L=Ek(0) */
aes128e(L, p, k);
for(int i=0; i<16; i++){
  temp[i] = L[i];
}

/* 2L */
gf(templ, temp);
for(int i=0; i<16; i++){
  L2[i] = templ[i];
}

/* 3L */
for(int i=0; i<16; i++){
  D0[i] = (templ[i] ^ L[i]);
  L3[i] = D0[i];
}

/* 7L and 3^2L */
gf(templ, D0);
for(int i=0; i<16; i++){
  D0[i] = (templ[i] ^ L[i]);
  L7[i] = D0[i]; //7L
  L32[i] = (templ[i] ^ L3[i]); //3^2L
}

/* 3^3L */
gf(templ, D0);
for(int i=0; i<16; i++){
  D0[i] = (templ[i] ^ L[i]);
  L33[i] = D0[i];
}

/* 3D0 */
gf(templ, D0);
for(int i=0; i<16; i++){
  D03[i] = (templ[i] ^ L33[i]);
}

/* PMAC */
PMAC(V, n, D03, k);

/* V[0] */
for(int i=0; i<16; i++){
  V[i] = V[i] ^ L[i];
}

/* D0, D1 */
for(int i=0; i<16; i++){
  D0[i] = L3[i];
  D1[i] = L2[i];
}

Encrypt(c, S, D0, D1, d, m, V, k);
Sigma(sigma, d, m);
Tag(c, L7, L32, sigma, k, d, S);

}


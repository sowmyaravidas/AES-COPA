/* Implement the following API.
 * You can add your own functions, but don't modify below this line.
 */

/* Under the 16-byte key at k and the 16-byte nonce at n, encrypt the plaintext at m and store it at c.
   Store the 16-byte tag in the end of c. The length of the plaintext is a multiple of 16 bytes given at d (e.g., 
   d = 2 for a 32-byte m). */
void aescopa(unsigned char *c, const unsigned char *k, const unsigned char *n, const unsigned char *m, const unsigned int d);


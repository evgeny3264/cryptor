#include <string>


#define w        32             /* word size in bits                 */
#define r        12             /* number of rounds                  */  
#define b        16             /* number of bytes in key            */
#define c         4             /* number  words in key = ceil(8*b/w)*/
#define t        26             /* size of table S = 2*(r+1) words   */


/* Rotation operators. x must be unsigned, to get logical right shift*/
#define ROTL(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
#define ROTR(x,y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))

void RC5_SETUP(unsigned char *K);
void RC5_ENCRYPT(unsigned long int *pt, unsigned long int *ct);
void RC5_DECRYPT(unsigned long int *ct, unsigned long int *pt);
int crypt(unsigned char* in, int sizein, unsigned char * key, unsigned char*& out);
int decrypt(unsigned char* in, int sizein, unsigned char * key, unsigned char*& out);
int ncrypt(std::string &in, unsigned char * key, unsigned long int * iv);
int ndecrypt(std::string &in, unsigned char * key);
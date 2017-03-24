#pragma once
#include <string>
class Rc5 
{
public:
	Rc5();
	~Rc5();
	int Crypt(std::string &in, const unsigned char* key, unsigned long int * iv);
	int Decrypt(std::string &in, unsigned char * key);
private:
	static const  int  w = 32;            /* word size in bits                 */
	static const int r = 12;          /* number of rounds                  */
	static const int b = 16;          /* number of bytes in key            */
	static const int c = 4;        /* number  words in key = ceil(8*b/w)*/
	static const int t = 26;         /* size of table S = 2*(r+1) words   */
	unsigned long int S[t];                      /* expanded key table                */
	static const unsigned long int P = 0xb7e15163, Q = 0x9e3779b9;  /* magic constants             */
	static inline unsigned long ROTL(unsigned long x, unsigned long y)
	{
		return ((x) << (y&(w - 1))) | ((x) >> (w - (y&(w - 1))));
	}
	static inline unsigned long ROTR(unsigned long x, unsigned long y)
	{
		return ((x) >> (y&(w - 1))) | ((x) << (w - (y&(w - 1))));
	}
	void RC5_SETUP(const unsigned char *K);
	void RC5_ENCRYPT(unsigned long int *pt, unsigned long int *ct);
	void RC5_DECRYPT(unsigned long int *ct, unsigned long int *pt);

};


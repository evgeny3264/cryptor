#include "Rc5.h"



Rc5::Rc5()
{
}


Rc5::~Rc5()
{
}

int Rc5::Crypt(std::string & in, const unsigned char * key, unsigned long int * iv)
{
	int sizein = in.size();
	if (sizein % 8 != 0)
	{
		sizein = sizein + (8 - (sizein % 8));
		in.resize(sizein);
	}
	RC5_SETUP(key);

	unsigned long int ot[2], ct[2] = { iv[0], iv[1] };
	for (int i = 0; i < sizein; i += 8)
	{

		ot[0] = *(unsigned long int*)& in[i];
		ot[1] = *(unsigned long int*)& in[i + 4];
		ot[0] ^= ct[0];
		ot[1] ^= ct[1];
		RC5_ENCRYPT(ot, ct);
		*(unsigned long int*)&in[i] = ct[0];
		*(unsigned long int*)&in[i + 4] = ct[1];
	}
	return sizein;
}

int Rc5::Decrypt(std::string & in, unsigned char * key)
{
	unsigned long int ct[2], ot[2], ctprv[2] = { 0, 0 };
	int sizein = in.size();
	RC5_SETUP(key);
	for (int i = 0; i < sizein; i += 8)
	{
		ct[0] = *(unsigned long int*)& in[i];
		ct[1] = *(unsigned long int*)& in[i + 4];
		RC5_DECRYPT(ct, ot);
		ot[0] ^= ctprv[0];
		ot[1] ^= ctprv[1];
		ctprv[0] = ct[0];
		ctprv[1] = ct[1];
		*(unsigned long int*)&in[i] = ot[0];
		*(unsigned long int*)&in[i + 4] = ot[1];
	}
	return sizein;
}

void Rc5::RC5_SETUP(const unsigned char * K)
{
	unsigned long int i, j, k, u = w / 8, A, B, L[c];

	/* Initialize L, then S, then mix key into S */
	for (i = b - 1, L[c - 1] = 0; i != -1; i--) L[i / u] = (L[i / u] << 8) + K[i];
	for (S[0] = P, i = 1; i < t; i++) S[i] = S[i - 1] + Q;
	for (A = B = i = j = k = 0; k < 3 * t; k++, i = (i + 1) % t, j = (j + 1) % c)   /* 3*t > 3*c */
	{
		A = S[i] = ROTL(S[i] + (A + B), 3);
		B = L[j] = ROTL(L[j] + (A + B), (A + B));
	}
}

void Rc5::RC5_ENCRYPT(unsigned long int * pt, unsigned long int * ct)
{
	unsigned long int i, A = pt[0] + S[0], B = pt[1] + S[1];
	for (i = 1; i <= r; i++)
	{
		A = ROTL(A^B, B) + S[2 * i];
		B = ROTL(B^A, A) + S[2 * i + 1];
	}
	ct[0] = A; ct[1] = B;
}

void Rc5::RC5_DECRYPT(unsigned long int * ct, unsigned long int * pt)
{
	unsigned long int i, B = ct[1], A = ct[0];
	for (i = r; i > 0; i--)
	{
		B = ROTR(B - S[2 * i + 1], A) ^ A;
		A = ROTR(A - S[2 * i], B) ^ B;
	}
	pt[1] = B - S[1]; pt[0] = A - S[0];
}

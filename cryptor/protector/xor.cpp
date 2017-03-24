#include "Xor.h"



Xor::Xor()
{
}


Xor::~Xor()
{
}

int Xor::Crypt(std::string & in, const unsigned char * key, int key_size)
{
	for (int i = 1; i<in.size(); i++)
	{
		in[i] = (char)(in[i] ^ key[i%key_size]);
	}
	return in.size();
}

int Xor::Crypt(unsigned char *& in, int data_size, const unsigned char * key, int key_size)
{
	for (int i = 1; i<data_size; i++)
	{
		in[i] = (char)(in[i] ^ key[i%key_size]);
	}
	return data_size;
}

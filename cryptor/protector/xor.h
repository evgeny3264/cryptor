#pragma once

#include <string>
class Xor 
{
public:
	Xor();
	~Xor();
	int Crypt(std::string &in, const unsigned char* key, int key_size) ;
	int Crypt(unsigned char * & in, int data_size, const unsigned char* key, int key_size) ;
};


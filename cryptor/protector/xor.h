#include <string>

void xor_crypt(unsigned char & in, const unsigned char key);
void nxor_crypt(std::string &in, const unsigned char* key, int key_size);
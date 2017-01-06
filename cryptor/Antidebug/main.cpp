#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>

#define w        32             /* word size in bits                 */
#define r        12             /* number of rounds                  */  
#define b        16             /* number of bytes in key            */
#define c         4             /* number  words in key = ceil(8*b/w)*/
#define t        26             /* size of table S = 2*(r+1) words   */
#define P         0xb7e15163
#define Q         0x9e3779b9




/* Rotation operators. x must be unsigned, to get logical right shift*/
#define ROTL(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
#define ROTR(x,y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))
int main()
{
	/*
	if(IsDebuggerPresent())
	{
	ExitProcess(0);
	}
	*/
	unsigned long int  x = ROTR(156, 33) ^ 3;

	unsigned long int temp, temp2;
	temp = ((156) >> (33 & (w - 1)));
	temp2 = ((156) << (w - (33 & (w - 1))));
	unsigned long int  y = (temp | temp2) ^ 3;

	unsigned long int  z = ROTL(156, 33);
	temp = ((156) << (33 & (w - 1)));
	temp2 = ((156) >> (w - (33 & (w - 1))));
	unsigned long int  h = (temp | temp2);
	if (x == y){

	
	int d;
	__asm
	{
		mov eax, fs:[018h]
			mov eax, [eax + 30h]
			movzx eax, byte ptr[eax + 02]
			mov d, eax
	}
	if (d)
	{
		printf("Debugger!\n");
	}
	printf("Hello,world!\n");
}
	system("pause");
	return 0;
}
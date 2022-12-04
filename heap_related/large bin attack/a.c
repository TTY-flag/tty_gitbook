//典型的应用场景为：存在四个堆ABCD，largebin中存在链表A->B，其中A为0x420，B为0x400，C为0x410，C未释放。将B的bk_nextsize伪造指向C，同时将C的fd与bk构造好，将C的fd_nextsize与bk_nextsize赋值为0，当再次申请0x410大小的内存E时，遍历B->bk_nextsize会指向C，且C的大小满足需求，因此会调用unlink将C从双链表取下，因此申请出来的堆块E的地址会为C的地址，即E和C为同一内存块，实现overlap chunk的构造。
#include<stdio.h>
#include<stdlib.h>
int main(){
	size_t C[0x10];
	size_t D[0x10];
	size_t *A,*B;
	A=malloc(0x410);
	B=malloc(0x3f0);
	C[0] = 0;
	C[1] = 0x411;
	C[2] = &B - 2;
	C[3] = &D - 2; 
	D[0] = 0;
	D[1] = 0x401;
	D[2] = &C;
	malloc(0x10);
	free(A);
	free(B);
	malloc(0x400);
	return 0;
}

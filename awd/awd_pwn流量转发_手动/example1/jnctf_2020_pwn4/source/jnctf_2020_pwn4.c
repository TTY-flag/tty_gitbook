#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
int girl_name_len[0x10];
char *girl_name[0x10];
void backdoor(){
	system("/bin/sh");
}
void welcome(){
	puts("===========================");
	puts("||   Welcome to JNCTF!   ||");
	puts("||        easy heap      ||");
	puts("||        glibc-2.23     ||");
	puts("||create your girlfriends||");		
	puts("||   Have a good time!   ||");
	puts("===========================");
}
void menu(){
	puts("---------------------------");
	puts("1.create a girlfriend");
	puts("2.delete a girlfriend");
	puts("3.show a girlfriend");
	puts("4.exit");
	puts("---------------------------");
	printf(">");
}
int get_atoi()
{
	char buf[4];
	read(0,buf,4);	
	return atoi(buf);
}

void create(){
	int index,size;
	printf("index(0~15):");
	index = get_atoi();
	if(index<0 || index>=0x10){
		puts("invalid index!");
		return ;
	}
	if(girl_name[index]){
		puts("Exits a girlfriend on it!");
		return ;
	}
	printf("size:");
	size = get_atoi();
	if(size<0 || size>0x100){
		puts("invalid size!");
		return ;
	}
	girl_name[index] = malloc(size);
	if(!girl_name[index]){
		puts("malloc error!");
		exit(0);
	}
	girl_name_len[index] = size;
	printf("her name:");
	read(0,girl_name[index],size);
	puts("success!");
	
}

void del(){
	int index;
	printf("index(0~15):");
	index = get_atoi();
	if(index<0 || index>=0x10){
		puts("invalid index!");
		return ;
	}
	if(!girl_name[index]){
		puts("no such girlfriend!");
	}
	free(girl_name[index]);
	puts("success!");

	
}

void show(){
	int index;
	printf("index(0~15):");
	index = get_atoi();
	if(index<0 || index>=0x10){
		puts("invalid index!");
		return ;
	}
	if(!girl_name[index]){
		puts("no girlfriend here!");
		return ;
	}
	printf("your girlfriendname:%s",girl_name[index]);
	return;
}
void init() {
	setvbuf(stdin, 0LL, 2, 0LL);
	setvbuf(stdout, 0LL, 2, 0LL);
	setvbuf(stderr, 0LL, 2, 0LL);
}

int main(){
	init();
	welcome();
	while(1){
		int choice;
		menu();
		choice = get_atoi();
		switch(choice){
			case 1:
				create();
				break;
			case 2:
				del();
				break;
			case 3:
				show();
				break;
			case 4:
				puts("bye~");
				exit(0);
			default:
				puts("invalued input!");
				exit(0); 
		}
	}
	return 0;
} 

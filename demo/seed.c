#include<stdlib.h>
#include<time.h>
#include<stdio.h>

int main(){
	long long lld = time(NULL)^(getpid()+42<<15);
	printf("%lld \n",lld);
	return 0;
}

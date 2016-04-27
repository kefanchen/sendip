#include<stdio.h>
#include<stdlib.h>
#include<dlfcn.h>

#define LIB_CACULATE_PATH "./libcaculate"

//complie with gcc -rdynamic -o    -ldl

//funciton pointer
typedef int (*CAC_FUNC)(int,int);

int main()
{
	void*handle;
	char *error;
	CAC_FUNC cac_func = NULL;
	int a,b;

	handle = dlopen(LIB_CACULATE_PATH,RTLD_LAZY);
	if(!handle)
	{
		fprintf(stderr,"%s\n",dlerror());
		exit(EXIT_FAILURE);
	}

	dlerror();//responsible to the last dl* call
	printf("input a and b:  ");
	scanf("%d %d",&a,&b);
	//cac_func = (CAC_FUNC)slsym(handle,"add") seemm natural but
//This was done because the ISO C standard does not require compilers
//       to allow casting of pointers to functions back and forth to 'void *'.

	*((void**) (&cac_func) ) = dlsym(handle,"add");
	printf("add of %d and %d = %d\n",a,b,cac_func(a,b));

	cac_func = (CAC_FUNC)dlsym(handle,"sub");
	printf("sub of %d and %d = %d\n",a,b,cac_func(a,b));

	

	dlclose(handle);
	exit(EXIT_SUCCESS);
}

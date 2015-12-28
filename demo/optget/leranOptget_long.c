#include<stdio.h>
#include<stdlib.h>
#include<getopt.h>

static int verbose_flag;

int main(int argc,char**argv)
{
	int c;

/*
 The struct option structure has t/mhese fields:

 const char *name
 This field is the name of the option. It is a string.

 int has_arg
 This field says whether the option takes an argument. It is an integer, and there are three legitimate values: no_argument, required_argument and optional_argument.

 int *flag
 int val
 These fields control how to report or act on the option when it occurs.

 If flag is a null pointer, then the val is a value which identifies this option. Often these values are chosen to uniquely identify particular long options.

 If flag is not a null pointer, it should be the address of an int variable which is the flag for this option. The value in val is the value to store in the flag to indicate that the option was seen.
 
 */


	static struct option loptions[]=
	{
		//flag!=NULL val point the indication flag variable,for set flag
		{"verbose",no_argument,&verbose_flag,1},
		{"brief",no_argument,&verbose_flag,0},

		//flag == NULL, val is a short alias,for pass arg 
		{"add",required_argument,0,'a'},
		{"delete",no_argument,0,'d'},
		{0,0,0,0}
	};

	while(1)
	{
		int option_index = 0;//point to the index of the long opt in the array

		c = getopt_long(argc,argv,"ab:",loptions,&option_index);

		if(c == -1)
			break;

		switch(c)
		{
			case 0://for long opt
			if(loptions[option_index].flag != 0)//for set flag
				//the optget_long has set the flag with the val
				break;
			//else for pass arg
			printf("option %s : with val %c ",
					loptions[option_index].name,loptions[option_index]);
			if(optarg)
				printf("with arg %s",optarg);
			printf("\n");
			break;

			case 'a':
				puts("opt -a\n");
				break;

			case 'b':
				printf("opt -b wiht arg %s \n",optarg);
				break;

			case '?':
				//getopt_long already print error
				break;

			deault:
				abort();

		}
	}
	if(verbose_flag)
		printf("verbose is set\n");

	if(optind < argc)
	{
		puts("non opt :\n");
		while(optind < argc)
		{
			printf("%s ",argv[optind++]);

		}
		putchar('\n');
	}
	exit(0);
}


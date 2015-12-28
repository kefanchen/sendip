//#include<optget.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

int main(int argc,char**argv)
{
	int aflag = 0;
	int bflag = 0;
	char *cvalue = NULL;

	int c;
	int index;
	
	while((c = getopt(argc,argv,"abc:")) != -1)
	{
		switch(c)
		{
			case 'a':
				aflag = 1;
				break;
			case 'b':
				bflag = 1;
				break;
			case 'c':
				cvalue = optarg;
				break;

			case '?':
				if(optopt == 'c')
					fprintf(stderr,"Option -%c requries an argument.\n",optopt);
				else if(isprint(optopt))
					fprintf(stderr,"Unknown option character '%c'",optopt);
				else
					fprintf(stderr,"unknown character '\\x%x'.\n",optopt);

				return 1;
			default:
				printf("default c: %c\n",c);
				abort();	

		}
	}

	printf("aflag = %d, bflag = %d ,cvalue = %s\n",aflag,bflag,cvalue);

	for (index =optind;index<argc;index++)
		printf("Non-option argument %s\n",argv[index]);

	return 0;

}

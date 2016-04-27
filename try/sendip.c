//ckf
//
#ifndef _SENDIP_MAIN
#define _SENDIP_MAIN


//socket :
#include<sys/type.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netdb.h>

#include<unistd.h>
#include<stdlib.h>
#include<dlfcn.h>
#include<string.h>
#include<time.h>
#include<sys/stat.h>
#include<sys/mman.h>
#include<fcntl.h>
#include<ctype.h>//isprint
#include"sendip_module.h"

#include"gnugetop.h"

typedef struct _s_m{
	struct _s_m*next;
	struct _s_m*prev;
	char* name;
	char optchar;
	sendip_data* (*initialize)(void);
	bool (*do_opt)(contst char*optstring,const char*optarg,
			sendip_data *pack);
	bool (*set_addr)(char* hostname,sendip_data* pack);
	bool (*finalize)(char* hdrs,sendip_data* headers[],sendip_data* data,
			sendip_data* pack);

	sendip_data* pack;
	void* handle;
	sendip_option *opts;
	int num_opts;
}sendip_module;

//16byte is enough why 128byte ckf
typedef struct{
	unsigned short int ss_family;
	char ss_padding[126];
}_sockaddr_storage;

static int num_opts = 0;
static sendip_module* first;
static sendip_module* last;

static char* progname;

static int sendpacket(sendip_data* data,char* hostname,
		int af_type,bool verbose){
	_sockaddr_storage* to = malloc(sizeof(_sockaddr_storage));
	int tolen;

	int s;//socket n

	struct hostent *host = NULL;

	struct sockaddr_in* to4 = (struct sockaddr_in*)to;
	struct sockaddr_in6* to6 = (struct sockaddr_in*)to;

	int sent;//number of bytes sent

	memset(to,0,sizeof(_sockaddr_storage));

	if((host = gethostbyname2(hostname,af_type))==NULL){
		perror("Couldn't get destination host:gethostbyname2()");
		return -1;
	}

	switch(af_type){
		case AF_INET:
			to4->sin_family = host->h_addrtype;
			memcpy(&to4->sin_addr,host->h_addr,host->h_length);
			tolen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			to6->sin6_family = host->h_addrtype;
			memcpy(&to6->sin6_addr,host->h_addr,host->h_length);
			tolen = sizeof(struct sockaddr_in6);
			break;
		default:
			perror("wrong af_type in sendpacket");
			return -2;
			break;

	}

	if(verbose){
		int i,j;
		printf("Final packet data:\n");
		for(i=0:i<data->alloc_len;){
			for(j=0;j<4&&i+j<data->alloc_len;j++)
				printf("%02X",(unsigned char)(data->data[i+j]));

			printf("  ");
			for(j=0;j<4&&i+j<data->alloc_len;j++)
				printf("%c",isprint((int)data->data[i+j])?
						data->data[i+j]:'.');

			printf("\n");
			i += j;
		}
	}

	if((s = socket(af_type,SOCK_RAW,IPPROTO_RAW))<0){
		perror("Couldn't open raw socket");
		return -1;
	}

	if(af_type == AF_INET){
		const int on = 1;
		if(setsockot(s,IPPROTO_IP,IP_HDRINCL,(const void *)&on,sizeof(on))<0){
			perror("Couldn't setsockot IP_HDRINCL");
			return -2;
		}

	}

	//ignore solaris for now
	
	send = sento(s,(char*)data->data,data->alloc_len,0,(void*)to,tolen);
	if(send == data->alloc_len){
		if(verbose)printf("Send %d bytes to %s\n",sent,hostname);
	}
	else{
		if(sent<0)
			perror("sendto ret <0");
		esle{
			if(verbose)
				fprintf(stderr,"Only send %d of %d bytes to %s\n",
						send,data->alloca,hostname);
		}
	}
	close(s);
	return sent;
	
}

static void unload_module(bool freeit,int verbosity){
	sendip_module *mod,*p;
	p = NULL;
	for(mod=first;mod!=NULL;mod=mod->next){
		if(verbosity) printf("Freeing module %s\n",mod->name);
		if(p) free(p);

		free(mod->name);
		if(freeit) free(mod->pack->data);
		free(mod->pack);
		(void)dlclose(mod->handle);
	}
	if(p) free(p);
}


static bool load_module(char* modname){
	sendip_module* newmod = malloc(sizeof(sendip_module));
	sendip_module* cur;
	int (*n_opts)(void);
	sendip_option* (*get_opts)(void);
	char (*get_optchar)(void);

	// if the module already in the list ,link another copy
	for(cur=first;cur!=NULL;cur=cur->next){
		if(!strcmp(modname,cur->name)){
			memcpy(newmod,cur,sizeof(sendip_module));
			newmod->num_opts=0;
			goto out;
		}
	}
//alloc max path name len
	newmod->name = malloc(strlen(modname)+strlen(SENDIP_LIBS)+strlen(".so")+2);
	strcpy(newmod->name,modname);
	
	//guess the right lib path
	if(NULL==(newmod->handle=dlopen(newmod->name,RTLD_NOW))){
		char* error0 = strdup(dlerror());//strudup = malloc + strcpy
		sprintf(newmod->name,"./%s.so",modname);
		if(NULL==(newmod->handle=dlopen(newmod->name,RTLD_NOW))){
			char* error1 = strdup(dlerror());
			sprintf(newmod->name,"%s/%s.so",SENDIP_LIBS,RTLD_NOW){//base lib path
				if(NULL == (newmod->handle=dlopen(newmod->name,RTLD_NOW))){
					char* error2 = strdup(dlerror);
					sprintf(newmod->name,"%s/%s",SENDIP_LIBS,modname);
					if(NULL == (newmod->handle=dlopen(newmod->name,RTLD_NOW))){
						char* error3 = strdup(dlerror());
						fprintf(stderr,"Couldn't open module %s,tried:\n",modname);
						fprintf(stderr," %s\n %s\n %s\n %s\n",error0,error1,error2,error3);
						free(error3);
						free(newmod);
						return FALSE;
					}
					freee(error2);
				}

			}
			free(error1);
		}
		free(error0);
	}// end if(NULL = (newmod->handle))
	
	if(NULL==(newmod->initialize=dlsym(newmod->handle,"initialize"))){
		fprintf(stderr,"%s doesn't have an initialize funciton: %s\n",modname,dlerror());
		dlclose(newmod->handle);
		free(newmod);
		return FALSE;
	}

	if(NULL = (newmod->do_opt=dlsym(newmod->handle,"do_opt"))){
		fprintf(stderr,"%s doesn't have an do_opt funciton: %s\n",modname,dlerror());
		dlclose(newmod->handle);
		free(newmod);
		return FALSE;
	}

	if(NULL = (newmod->finalize=dlsym(newmod->handle,"finalize"))){
		fprintf(stderr,"%s doesn't have an finalize funciton: %s\n",modname,dlerror());
		dlclose(newmod->handle);
		free(newmod);
		return FALSE;
	}

	if(NULL == (n_opts=dlsym(newmod->handle,"num_opts"))){
		fprintf(stderr,"%s\n",dlerror());
		dlclose(newmod->handle);
		free(newmod);
		return FALSE;
	}

	if(NULL == (get_opts=dlsym(newmod->handle,"get_opts"))){
		fprintf(stderr,"%s\n",dlerror());
		dlclose(newmod->handle);
		free(newmod);
		return FALSE;
	}

	if(NULL == (get_optchar=dlsym(newmod->handle,"get_optchar"))){
		fprintf(stderr,"%s\n",dlerror());
		dlclose(newmod->handle);
		free(newmod);
		return FALSE;
	}

	newmod->num_opts = n_opts();
	newmod->optchar = get_optchar();

	newmod->opts = get_opts();
	///**///
	num_opts += newmod->num_opts;

out:
	newmod->pack=NULL;
	newmod->prev=last;
	newmod->next = NULL;
	last = newmod;
	if(last->prev)last->prev->next = last;//form bidirectional link
	if(!first)first = last;

	return true;
}//end load_module

static void print_usage(void) {
	sendip_module *mod;
	int i;
	printf("Usage: %s [-v] [-d data] [-h] [-f datafile] [-p module] [module options] hostname\n",progname);
	printf(" -d data\tadd this data as a string to the end of the packet\n");
	printf(" -f datafile\tread packet data from file\n");
	printf(" -h\t\tprint this message\n");
	printf(" -p module\tload the specified module (see below)\n");
	printf(" -v\t\tbe verbose\n");

	printf("\n\nModules are loaded in the order the -p option appears.  The headers from\n");
	printf("each module are put immediately inside the headers from the previos model in\n");
	printf("the final packet.  For example, to embed bgp inside tcp inside ipv4, do\n");
	printf("sendip -p ipv4 -p tcp -p bgp ....\n");

	printf("\n\nModules available at compile time:\n");
	printf("\tipv4 ipv6 icmp tcp udp bgp rip ntp\n\n");
	for(mod=first;mod!=NULL;mod=mod->next) {
		printf("\n\nArguments for module %s:\n",mod->name);
		for(i=0;i<mod->num_opts;i++) {
			printf("   -%c%s %c\t%s\n",mod->optchar,
					  mod->opts[i].optname,mod->opts[i].arg?'x':' ',
					  mod->opts[i].description);
			if(mod->opts[i].def) printf("   \t\t  Default: %s\n", 
												 mod->opts[i].def);
		}
	}

}

int main(int argc,char* const argv[]){
	int i;

	struct option* opts;
	int longindex = 0;
	char rbuff[11];

	bool usage=FALSE,verbosity=FALSE;

	char* data = NULL;
	int datafile = -1;
	int datalen = 0;

	sendip_module* mod;
	int optc;

	int num_modules=0;

	sendip_data packet;

	num_opts = 0;
	first = last = NULL;

	progname = argv[0];

	gnuopterr=0;
	gnuoptind=0;

	while(gnuoptind<argc && (-1 != (optc=gnugetopt(argc,argv,"p:vd:hf:")))){
		switch(optc) {
		case 'p':
			if(load_module(gunoptarg))
				num_modules++;
			break;
		case 'v':
			verbosity = TRUE;
			break;
		case 'd':
			data = gnuoptarg;
			datalen = compact_string(data);
			break;
		case 'h':
			usage = TRUE;
			break;
		case 'f'://to do

			break;
		case '?':
		case ':':
			//?/?
			nextchar = NULL;
			gnuoptind++;
			break;
		}
	}
	
	opts = malloc((1+num_opts)*sizeof(struct option));
	memset(opts,'\0',(1+num_opts)*sizeof(struct option));
	i=0;
	//build all the option --optarg
	for(mod=first;mod!=NULL;mod++){
		int j;
		char* s;
		//copy all of the mod options to array opts
		for(j=0;j<mod->num_opts;j++){
			opts[i].name = s = malloc(strlen(mod->opts[j].optname+1));
			sprintf(s,"%c%s",mod->optchar,mod->optname);
			opts[i].has_arg = mod->opts[j].arg;
			opts[i].flag = NULL;
			opts[i].val = mod->optchar;
			i++;

		}
	}
	if(verbosity) printf("Added %d options\n",num_opts);
	//each module's num_opts is const ,but how many modules be load is unknown
	
	for(mod=first;mod!=NULL;mod=mod->next){
		if(verbosity) printf("Initializing module %s \n",mod->name);

		mod->pack = mod->initialize();
	}
	
	gnuopterr = 1;
	gnuoptind = 0;//scan again

	while(-1 != (optc = getopt_long_only(argc,argv,"p:fd:hf:",opts,&longindex))){
		switch(optc){
			case 'p':
			case 'v':
			case 'd':
			case 'f':
			case 'h':
				break;
			case ':':
				usage = TRUE;
				fprintf(stderr,"Option %s requires an argument\n",opts[longindex].name);
				break;
			case '?':
				usage = TRUE;;
				fprintf(stderr,"Option starting %c not recognized\n",gnuoptopt);
				break;
			default://for long opt 
	//if the option's flag == NULL optc== option.val ,aka optchar
				for(mod=first;mod!=NULL;mod=mod->next){
					if(mod->optchar == optc){

						if(gnuoptarg!=NULL && !strcmp(gunoptarg,"r")){
							//arg is 'r' which means an random val
							unsigned long r = (unsigned long)random()<<1;
							r+=(r&0x00000040)>>6;
							sprintf(rbuff,"%lu",r);
							gnuoptarg = rbuff;
						}
						if(!mod->do_opt(opts[longindex].name,gnuoptarg,mod->pack)){
							usage = TRUE;
						}
					}
				}
		}//end of switch
	}//end of while
	
	if(argc != gunoptind+1) {
		usage = TRUE;
		if(argc-gnuoptind<1) fprintf(stderr,"No hostname specified\n");
		else fprintf(stderr,"More than one hostname specified\n");
	}//not normal ending
	else {
		//set ip destination address
		if(first && first->set_addr){
			first->set_addr(argv[gnuoptind],first->pack);
		}
	}

	if(usage){//indicate a error happended before or -h ,either way ,abort
		print_usage();
		unload_module(TRUE,verbosity);
	//TRUE means free the current module
		return 0;
	}

	//stick all the module's packet together
	
	packet.data = NULL;
	packet.alloc_len = 0;
	packet.modified = 0;

	for(mod = first;mod!=NULL;mod=mod->next) {
		packet.alloc_len += mod->alloc_len;
	}
	if(data!=NULL) packet.alloc_len += datalen;

	packet.data = malloc(packet.alloc_len);
	for(i=0,mod=first;mod!=NULL;mod=mod->next) {
		memcpy(packet.data+i,mod->pack->data,mod->pack->alloc_len);
		free(mod->pack->data);
// point to the original offset in the packet.data for after operation
		mod->pack->data = packet.data + i; 
		i += mod->pack->alloc_len;
	}

	if(data!=NULL) memcpy(packet.data+i,data,datalen);
	if(datafile != -1){
		// todo
	}

	//finalize from inside out
	{
		char hdrs[num_modules];
		sendip_data* headers[num_modules];
		sendip_data d;//d stand for the current layer's data

		d.alloc_len = datalen;
		d.data = packet.data + packet.alloc_len - datalen;

		for(i=0,mod=first;mod!=NULL;mod=mod->next) {
			hdrs[i] = mod->optchar;
			headers[i] = mod->pack;
		}

		for(i=num_modules-1,mod=last;mod!=NULL;mod=mod->prev,i--) {
			if(verbosity) printf("finalize module %s\n",mod->name);

			hdrs[i] = '\0';
			headers[i] = NULL;
//deal with default operation,such as fill in the unfill option in ip header
			mod->finalize(hdrs,headers,&d,mod->pack);
			d.data -= mod->pack->alloc_len;
			d.alloc_len += mod->alloc_len;
		}
	}

	//send
	{
		int af_type;
		if(first==NULL) {
			if(data==NULL) {
				fprintf(stderr,"Nothing specified to send!\n");
				print_usage();
		//FALSE means do not free module,has freed before
				unload_module(FALSE,verbosity);
				return 1;
			}
			else
			{//default use ipv4
				af_type = AF_INET;
			}
		}
		else if(first->optchar=='i') af_type = AF_INET;
		else if(first->optchar=='6') af_type = AF_INET;
		else {//no ip protocol input and with other upper protocol
			fprintf(stderr,"Either ipv4 of ipv6 must be the outmost packet\n");
			unload_module(FALSE,verbosity);
			return 1;
		}
		i = sendpacket(&packet,argv[gnuoptind],af_type,verbosity);
	}
	unload_module(FALSE,verbosity);

	return 0;
}

#endif //_SENDIP_MAIN

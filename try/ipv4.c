/* ipv4.c - IPV4 code for sendip
 * Author: Mike Ricketts <mike@earth.li>
 * ChangeLog from 2.0 release:
 * 26/11/2001 IP options
 * 23/01/2002 Spelling fix (Dax Kelson <dax@gurulabs.com>)
 */

//ckf
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include "sendip_module.h"
#include "ipv4.h"

/* Character that identifies our options
 */
const char opt_char='i';

static void ipcsum(sendip_data *ip_hdr) {
	ip_header *ip = (ip_header *)ip_hdr->data;
	ip->check=0;
	ip->check=csum((u_int16_t *)ip_hdr->data, ip_hdr->alloc_len);
}



sendip_data *initialize(void) {
	sendip_data *ret = malloc(sizeof(sendip_data));
	ip_header *ip = malloc(sizeof(ip_header));
	memset(ip,0,sizeof(ip_header));
	ret->alloc_len = sizeof(ip_header);
	ret->data = (void *)ip;
	ret->modified=0;
	return ret;
}

bool set_addr(char *hostname, sendip_data *pack) {
	ip_header *ip = (ip_header *)pack->data;
	struct hostent *host = gethostbyname2(hostname,AF_INET);
	if(!(pack->modified & IP_MOD_SADDR)) {
		ip->saddr = inet_addr("127.0.0.1");
	} 
	if(!(pack->modified & IP_MOD_DADDR)) {
		if(host==NULL) return FALSE;
		if(host->h_length != sizeof(ip->daddr)) {
			fprintf(stderr,"IPV4 destination address is the wrong size!!!");
			return FALSE;
		}
		memcpy(&(ip->daddr),host->h_addr,host->h_length);
	}
	return TRUE;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	ip_header *iph = (ip_header *)pack->data;
	switch(opt[1]) {
	case 's':
		iph->saddr = inet_addr(arg);
		pack->modified |= IP_MOD_SADDR;
		break;
	case 'd':
		iph->daddr = inet_addr(arg);
		pack->modified |= IP_MOD_DADDR;
		break;
	case 'h':
		iph->header_len = (unsigned int)strtoul(arg, (char **)NULL, 0) & 0xF;
		pack->modified |= IP_MOD_HEADERLEN;
		break;
	case 'v':
		iph->version = (unsigned int)strtoul(arg, (char **)NULL, 0) & 0xF;
		pack->modified |= IP_MOD_VERSION;
		break;
	case 'y':
		iph->tos = (u_int8_t)strtoul(arg, (char **)NULL, 0);
		pack->modified |= IP_MOD_TOS;
		break;
	case 'l':
		iph->tot_len = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= IP_MOD_TOTLEN;
		break;
	case 'i':
		iph->id = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= IP_MOD_ID;
		break;

	case 'f':
		if(opt[2]) {
			/* Note: *arg&1 is what we want because:
				if arg=="0", *arg&1==0
				if arg=="1", *arg&1==1
				otherwise, it doesn't really matter...
			*/
			switch(opt[2]) {
			case 'r':
				iph->res=*arg&1;
				pack->modified |= IP_MOD_RES;
				break;
			case 'd':
				iph->df=*arg&1;
				pack->modified |= IP_MOD_DF;
				break;
			case 'm':
				iph->mf=*arg&1;
				pack->modified |= IP_MOD_MF;
				break;
			}
		} else {
			IP_SET_FRAGOFF(iph,(u_int16_t)strtoul(arg, (char **)NULL, 0) & 
				(u_int16_t)0x1FFF);
			pack->modified |= IP_MOD_FRAGOFF;
			break;
		}
		break;

	case 't':
		iph->ttl = (u_int8_t)strtoul(arg, (char **)NULL, 0);
		pack->modified |= IP_MOD_TTL;
		break;
	case 'p':
	   iph->protocol = (u_int8_t)strtoul(arg, (char **)NULL, 0);
		pack->modified |= IP_MOD_PROTOCOL;
		break;
	case 'c':
		iph->check = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= IP_MOD_CHECK;
		break;


	
	default:
		usage_error("unknown IP option\n");
		return FALSE;
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], sendip_data *data,
				  sendip_data *pack) {
	ip_header *iph = (ip_header *)pack->data;

	if(!(pack->modified & IP_MOD_VERSION)) {
		iph->version=4;
	}
	if(!(pack->modified & IP_MOD_HEADERLEN)) {
		iph->header_len=(pack->alloc_len+3)/4;
	}
	if(!(pack->modified & IP_MOD_TOTLEN)) {
		iph->tot_len=htons(pack->alloc_len + data->alloc_len);
	}
	if(!(pack->modified & IP_MOD_ID)) {
		iph->id = rand();
	}
	if(!(pack->modified & IP_MOD_TTL)) {
		iph->ttl = 255;
	}
	if(!(pack->modified & IP_MOD_CHECK)) {
		ipcsum(pack);
	}
	return TRUE;
}

int num_opts() {
	return sizeof(ip_opts)/sizeof(sendip_option); 
}
sendip_option *get_opts() {
	return ip_opts;
}
char get_optchar() {
	return opt_char;
}

/* udp.c - UDP code for sendip
 * Author: Mike Ricketts <mike@earth.li>
 * ChangeLog since 2.0 release:
 */

#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include "sendip_module.h"
#include "udp.h"
#include "ipv4.h"

/* Character that identifies our options
 */
const char opt_char='u';

static void udpcsum(sendip_data *ip_hdr, sendip_data *udp_hdr,
						  sendip_data *data) {
	udp_header *udp = (udp_header *)udp_hdr->data;
	ip_header  *ip  = (ip_header *)ip_hdr->data;
	u_int8_t *tempbuf = malloc(12+udp_hdr->alloc_len+data->alloc_len);
	udp->check=0;
	memcpy(tempbuf,&(ip->saddr),sizeof(u_int32_t));
	memcpy(&(tempbuf[4]),&(ip->daddr),sizeof(u_int32_t));
	tempbuf[8]=0;
	tempbuf[9]=(u_int16_t)ip->protocol;
	tempbuf[10]=(u_int16_t)((udp_hdr->alloc_len+data->alloc_len)&0xFF00)>>8;
	tempbuf[11]=(u_int16_t)((udp_hdr->alloc_len+data->alloc_len)&0x00FF);
	memcpy(tempbuf+12,udp_hdr->data,udp_hdr->alloc_len);
	memcpy(tempbuf+12+udp_hdr->alloc_len,data->data,data->alloc_len);
	udp->check = csum((u_int16_t *)tempbuf,
							12+udp_hdr->alloc_len+data->alloc_len);
}

sendip_data *initialize(void) {
	sendip_data *ret = malloc(sizeof(sendip_data));
	udp_header *udp = malloc(sizeof(udp_header));
	memset(udp,0,sizeof(udp_header));
	ret->alloc_len = sizeof(udp_header);
	ret->data = (void *)udp;
	ret->modified=0;
	return ret;
}

bool do_opt(char *opt, char *arg, sendip_data *pack) {
	udp_header *udp = (udp_header *)pack->data;
	switch(opt[1]) {
	case 's':
		udp->source = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= UDP_MOD_SOURCE;
		break;
	case 'd':
		udp->dest = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= UDP_MOD_DEST;
		break;
	case 'l':
		udp->len = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= UDP_MOD_LEN;
		break;
	case 'c':
		udp->check = htons((u_int16_t)strtoul(arg, (char **)NULL, 0));
		pack->modified |= UDP_MOD_CHECK;
		break;
	}
	return TRUE;

}

bool finalize(char *hdrs, sendip_data *headers[], sendip_data *data,
				  sendip_data *pack) {
	int num_hdrs = strlen(hdrs);
	int i, foundit=0;
	udp_header *udp = (udp_header *)pack->data;
	
	/* Set relevant fields */
	if(!(pack->modified&UDP_MOD_LEN)) {
		udp->len=htons(pack->alloc_len+data->alloc_len);
	}

	/* Find enclosing IP header and do the checksum */
	/* TODO: Should only check one layer of enclosing header
		Could also find IPV6 headers? */
	for(i=num_hdrs;i>0;i--) {
		if(hdrs[i-1]=='i') {
			foundit=1; break;
		}
	}
	if(foundit) {
		i--;
		if(!(headers[i]->modified&IP_MOD_PROTOCOL)) {
			((ip_header *)(headers[i]->data))->protocol=IPPROTO_UDP;
			headers[i]->modified |= IP_MOD_PROTOCOL;
		}
		if(!(pack->modified&UDP_MOD_CHECK)) {
			udpcsum(headers[i],pack,data);
		}
	} else {
		if(!(pack->modified&UDP_MOD_CHECK)) {
			usage_error("UDP checksum not defined when UDP is not embedded in IP\n");
			return FALSE;
		}
	}

	return TRUE;
}

int num_opts() {
	return sizeof(udp_opts)/sizeof(sendip_option); 
}
sendip_option *get_opts() {
	return udp_opts;
}
char get_optchar() {
	return opt_char;
}

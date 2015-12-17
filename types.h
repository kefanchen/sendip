/* types.h - tpyes needed in sendip and not defined everywhere
 * Author: Mike Ricketts <mike@earth.li>
 * ChangeLog since 2.1 release:
 */
#ifndef _SENDIP_TYPES_H
#define _SENDIP_TYPES_H

/* Make sure we have bool */
typedef int bool;
#ifndef FALSE
#define TRUE  (0==0)
#define FALSE (!TRUE)
#endif

/* Solaris doesn't define these */
#ifdef __sun__
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint8_t  u_int8_t;

/* disable ipv6 on solaris */
#define gethostbyname2(x,y) gethostbyname(x)

#endif /* __sun__ */

/* for things that *really* don't know about ipv6, ... */
#ifndef AF_INET6
#define PF_INET6 10
#define AF_INET6 PF_INET6
struct in6_addr {
	union {
		u_int8_t  u6_addr8[16];
		u_int16_t u6_addr16[8];
		u_int32_t u6_addr32[4];
	} in6_u;
#define s6_addr  in6_u.u6_addr8
#define s6_add16 in6_u.u6_addr16
#define s6_add32 in6_u.u6_addr32
};

struct sockaddr_in6 {
	u_int16_t sin6_family;
	u_int16_t sin6_port;
	u_int32_t sin6_flowinfo;
	struct in6_addr sin6_addr;
	u_int32_t sin6_scope_id;
};

#endif /* !AF_INET 6 */

/* Convert _BIG_ENDIAN/_LITTLE_ENDIAN to __BYTE_ORDER */
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 4321
#endif

#ifndef __BYTE_ORDER
#ifdef _BIG_ENDIAN
#define __BYTE_ORDER __BIG_ENDIAN
#else   /* not _BIG_ENDIAN */
#ifdef _LITTLE_ENDIAN
#define __BYTE_ORDER __LITTLE_ENDIAN
#else   /* not _LITTLE_ENDIAN */
#error Could not guess your byte order
#endif  /* not _LITTLE_ENDIAN */
#endif  /* not _BIG_ENDIAN */
#endif  /* _BYTE_ORDER */

#endif  /* _SENDIP_TYPES_H */

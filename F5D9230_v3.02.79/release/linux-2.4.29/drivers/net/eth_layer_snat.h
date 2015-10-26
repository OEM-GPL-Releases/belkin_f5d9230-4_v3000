#ifndef _ETH_LAYER_SNAT_H
#define _ETH_LAYER_SNAT_H

#define ubyte_t u_int8_t
#define ushort_t u_int16_t
#define ulong_t u_int32_t
typedef ulong_t ipaddr_t;

#define HASH_KEY_LEN 9
#define FASTNAT_ENTRY_NUM (1 << HASH_KEY_LEN)
#define FASTNAT_TCP_CONN 1
#define FASTNAT_UDP_CONN 0

#define TCP_FASTNAT_TABLE_NUMBER      1024 
#define UDP_FASTNAT_TABLE_NUMBER      1024

#define         TCP_PORT_START          0x1001
#define         TCP_PORT_END            0x5000

#define         UDP_PORT_START          0x5001
#define         UDP_PORT_END            0x9000

#define MORE_FRAGMENT_BIT             0x0020

#define __IPHash(netaddr)   (netaddr[0] ^ netaddr[1] ^ netaddr[2] ^ netaddr[3] )
#define __IP_hash(netaddr)  (ubyte_t)__IPHash( ((ubyte_t *)&(netaddr)) )
#define __PORTHash(port)   ( port[0] ^ port[1] )
#define __Port_hash(port)  (ubyte_t)__PORTHash( ((ubyte_t *)&(port)) )

#define __IPHash3(netaddr)   (netaddr[2] ^ netaddr[3])
#define __IP_hash3(netaddr,port)  (ubyte_t)__IPHash3( ((ubyte_t *)&(netaddr)) ) ^  (ubyte_t)__PORTHash( ((ubyte_t *)&(port)) )
#define __Port_hash3(port,netaddr)  (ubyte_t)__PORTHash( ((ubyte_t *)&(port)) ) ^ (ubyte_t)__IPHash3( ((ubyte_t *)&(netaddr)) )

#define BE_USED         0x01
#define BE_RUNNING      0x02
#define FIN_LAN2WAN     0x04 //TCP Receive FIN from Lan to Wan
#define FIN_WAN2LAN     0x08 //TCP Receive FIN from Wan to Lan
#define BE_RST          0x10 //TCP Receive RST


typedef struct udp_connection udp_map_entry_t;
struct  udp_connection
{
    udp_map_entry_t *ip_flink;      // foreward link with net address
    udp_map_entry_t *ip_blink;      // backward link with net address
    udp_map_entry_t *port_ulink;    // foreward link with port
    udp_map_entry_t *port_dlink;    // backward link with port
    ubyte_t flag;             // refer to definitions behind 'tcp_map_entry_t.flag'
    ushort_t timer;              // session idle timer starts from 0.
//  ubyte_t mac_addr_client[6];    /* physical address */
    ipaddr_t ip_client;
    ushort_t port_client;
    ushort_t port_device;       // mapped port on device
    ipaddr_t ip_remote;
    ushort_t port_remote;
    ipaddr_t ip_outside;
    struct dst_entry *lan2wan_dst;
	  struct dst_entry *wan2lan_dst;
	  struct ip_conntrack *conn;
	  //int masq_index;
};

typedef struct tcp_connetcion tcp_map_entry_t;
struct  tcp_connetcion
{
    tcp_map_entry_t *ip_flink;      // foreward link with net address
    tcp_map_entry_t *ip_blink;      // backward link with net address
    tcp_map_entry_t *port_ulink;    // foreward link with port
    tcp_map_entry_t *port_dlink;    // backward link with port
    ubyte_t flag;             // refer to definitions behind 'tcp_map_entry_t.flag'
    ushort_t timer;              // session idle timer starts from 0.
    ipaddr_t ip_client;
    ushort_t port_client;
    ushort_t port_device;       // mapped port on device
    ipaddr_t ip_remote;
    ushort_t port_remote;
    ipaddr_t ip_outside;
// used for testing if the session is idle
    tcp_map_entry_t *ftp_link;      // interactive pointer of ftp command session
                              // and data session.
//    ulong_t current_seq;        // hi-lo seq no. of the recent received frame
//    ulong_t current_ack;        // hi-lo ack no. of the recent received frame

    ulong_t tcp_seq;            // the lo-hi seq no of the recent 'PORT' cmd
    ulong_t tcp_ack;
    ushort_t accum_offset;       // accumulated offset for every 'PORT' cmd
                                // except the recent one.
    ushort_t seq_ack_offset;     // the offset caused by the recent 'PORT' cmd
    struct dst_entry *lan2wan_dst;
	  struct dst_entry *wan2lan_dst;
	  struct ip_conntrack *conn;
	  //int masq_index;
};

#endif



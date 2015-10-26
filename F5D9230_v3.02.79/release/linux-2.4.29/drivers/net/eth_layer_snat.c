
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/brlock.h>
#include <net/checksum.h>
#include <linux/stddef.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/jhash.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
/* For ERR_PTR().  Yeah, I know... --RR */
#include <linux/fs.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>


#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ip_conntrack_protocol.h>
#include <linux/netfilter_ipv4/ip_conntrack_helper.h>
#include <linux/netfilter_ipv4/ip_conntrack_core.h>
#include <linux/netfilter_ipv4/listhelp.h>
#include <linux/timer.h>
#include "eth_layer_snat.h"


extern int ip_finish_output2(struct sk_buff *);


void fastnat_add_newentry(u_int32_t protonum,u_int32_t newsrc,struct ip_conntrack *ct);

tcp_map_entry_t *tcp_find_entry_out(ipaddr_t,ushort_t, ipaddr_t,ushort_t);
udp_map_entry_t *udp_find_entry_out(ipaddr_t,ushort_t,ipaddr_t,ushort_t);
tcp_map_entry_t *tcp_find_entry_in(ushort_t, ipaddr_t, ushort_t);
udp_map_entry_t *udp_find_entry_in(ushort_t, ipaddr_t, ushort_t);

static int snat_initial=0;
void software_nat_init(struct net_device *dev);

u_int32_t FastNAT_Hash_Key(u_int32_t sp,u_int32_t tu,u_int32_t sip,u_int32_t key_len);
static int tcp_fast_past_packet(struct sk_buff *);
static int udp_fast_past_packet(struct sk_buff *);
void ConvertCharToDec(u_int8_t *,u_int32_t *);

tcp_map_entry_t *tcp_hash_ptr_for_out[256];
tcp_map_entry_t *tcp_hash_ptr_for_in[256];
u_int16_t tcp_connection_live;
u_int16_t tcp_port_new_alloc;            // TCP port index allocated
tcp_map_entry_t *tcp_map_entry_ptr;
tcp_map_entry_t tcp_fastnat_table[TCP_FASTNAT_TABLE_NUMBER];

udp_map_entry_t *udp_hash_ptr_for_out[256];
udp_map_entry_t *udp_hash_ptr_for_in[256];
u_int16_t udp_connection_live;
u_int16_t udp_port_new_alloc;            // UDP port index allocated
udp_map_entry_t *udp_map_entry_ptr;
udp_map_entry_t udp_fastnat_table[UDP_FASTNAT_TABLE_NUMBER];

static u_int32_t shnat_pause = 0;
static u_int32_t packet_gate_cnt = 100;

extern unsigned long ip_ct_tcp_timeout_established;
extern unsigned long ip_ct_udp_timeout_stream;
extern unsigned long ip_ct_udp_timeout;

#define HOURSE_KEEPING_PERIOD	(jiffies + HZ * 30)  // 30 seconds
static struct timer_list snat_refresh_timer;
#define TCP_TIME_OUT 10 // 10*30 seconds = 300 seconds
#define UDP_TIME_OUT 1 // 6*30 seconds = 180 seconds


#if 1
#define DO_PRINT(args...)   
#else
#define DO_PRINT(args...) printk(args)
#endif


void clean_field( char *buffer, u_int32_t num )
{
    while( num-- )  *buffer++ = '\0';
}

void del_tcp_fastnat_entry(tcp_map_entry_t *rep)
{
  struct ip_conntrack *ct = rep->conn;
  struct ip_nat_info *info = &ct->nat.info;
  
  DO_PRINT("<del_tcp_fastnat_entry:%x,%x,%x,%x,%x,%x,%x>\n",ct, 
                                                   (&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->src.u.tcp.port,
                                                   rep->port_client,
                                                   ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.ip, 
                                                   rep->ip_remote,
                                                   (&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->dst.u.tcp.port,
                                                   rep->port_remote
                 );
	
  if (  (info->initialized) &&
        ((&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->src.u.tcp.port == rep->port_client) &&
        ( ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.ip == rep->ip_remote) &&
        ((&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->dst.u.tcp.port == rep->port_remote)
     )
	{
    DO_PRINT("<tcp_del_conntrack:%x>\n",ct);
    del_timer((unsigned long)&ct->timeout);
    death_by_timeout(ct);
   }
  
  //clean_field((char *)rep, sizeof(tcp_map_entry_t) );
  rep->flag &= 0;
	    tcp_connection_live--;
	DO_PRINT("<tcp_del_entry:%d>\n",tcp_connection_live);
	    return;
    }  
	
void del_udp_fastnat_entry(udp_map_entry_t *rep1)
	{
  struct ip_conntrack *ct = rep1->conn;
  struct ip_nat_info *info = &ct->nat.info;
  
  if (  (info->initialized) &&
        ((&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->src.u.udp.port == rep1->port_client) &&
        ( ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.ip == rep1->ip_remote) &&
        ((&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->dst.u.udp.port == rep1-> port_remote)
     )
    {
    DO_PRINT("<udp_del_conntrack:%x>\n",ct,
                                       (&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->src.u.udp.port,
                                       rep1->port_client,
                                       ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.ip,
                                       rep1->ip_remote,
                                       (&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->dst.u.udp.port,
                                       rep1-> port_remote
                                       );
    del_timer((unsigned long)&ct->timeout);
    death_by_timeout(ct);
  }
  
  //clean_field((char *)rep1, sizeof(udp_map_entry_t) );
  rep1->flag &= 0;
      udp_connection_live--;
	DO_PRINT("<udp_del_entry:%d>\n",udp_connection_live);
	    return;
    }	                                    

void shnat_external_cmd(char *cmd)
{
  return;
}

ushort_t AllocTCPNewPort(ipaddr_t ip_remote,ushort_t port_remote,ushort_t port)
{
  tcp_map_entry_t *mp;
  ushort_t port_an;

  mp = tcp_find_entry_in(port, ip_remote,port_remote);
  if (mp)
    {//Check to see if allocate another new port or not
    if ( tcp_port_new_alloc == TCP_PORT_END )
       tcp_port_new_alloc = TCP_PORT_START;
       
    port_an = ntohs(tcp_port_new_alloc);
    tcp_port_new_alloc++;
    
    return port_an;
    }
  else
    return port;  //If not found in the fast NAT table, just use orginal port is OK !!
}

ushort_t AllocUDPNewPort(ipaddr_t ip_remote,ushort_t port_remote,ushort_t port)
{
  udp_map_entry_t *mp1;
  ushort_t port_an;

  mp1 = udp_find_entry_in(port, ip_remote,port_remote);
  if (mp1)
    {//Check to see if allocate another new port or not
    if ( udp_port_new_alloc == UDP_PORT_END )
       udp_port_new_alloc = UDP_PORT_START;
       
    port_an = ntohs(udp_port_new_alloc);
    udp_port_new_alloc++;
    
    return port_an;
    }
  else
    return port; //If not found in the fast NAT table, just use orginal port is OK !!
}


tcp_map_entry_t  *tcp_map_table_add(ipaddr_t ip_remote, ushort_t port_remote, ipaddr_t netaddr, ushort_t port, ipaddr_t out_ip)
{
    tcp_map_entry_t  *rep,  *repbase,  *mapbase;
    tcp_map_entry_t  *father_ip,  *father_port;
    ushort_t port_an;
    ushort_t max_session;
 
 //DO_PRINT("<ip_remote:%x, port_remote:%x, netaddr:%x, port:%x, out_ip:%x>\n",ip_remote, port_remote,netaddr, port,out_ip );
 
    //Get a new TCP port
    port_an = AllocTCPNewPort(ip_remote,port_remote,port);
    
    father_ip = (tcp_map_entry_t *) &tcp_hash_ptr_for_out[ __IP_hash3( netaddr,port ) ];
    father_port = (tcp_map_entry_t *) ((char *)&tcp_hash_ptr_for_in[ __Port_hash3( port_an,ip_remote) ]- 3*sizeof(tcp_map_entry_t *));
    rep = repbase = tcp_map_entry_ptr;
    mapbase = tcp_fastnat_table;
    max_session = TCP_FASTNAT_TABLE_NUMBER;
  
    while(1)    /* find an available route entry to add */
    {
        ++rep;
        //wrap round
        //printk("1");
        if( rep == (tcp_map_entry_t *)&mapbase[ max_session ] )
            rep = (tcp_map_entry_t *)&mapbase[0];
            
        if ( (rep->flag & BE_USED) == 0 )
            break;
            
        if( rep == repbase )
        {
            return NULL;         /* !! sap table full !! */
        }
    }
    
    rep->flag = BE_USED;
    rep->ip_client = netaddr;
    rep->port_client = port;
    rep->port_device = port_an;
    rep->accum_offset = 0;
    rep->seq_ack_offset = 0;
    rep->tcp_seq = rep->tcp_ack = 0;
    rep->timer = 0;
    rep->ip_remote = ip_remote;
    rep->port_remote = port_remote;
    
    rep->port_ulink = father_port;
    rep->port_dlink = father_port->port_dlink;
    
    if ( father_port->port_dlink != NULL)
       rep->port_dlink->port_ulink = rep;
       
    father_port->port_dlink = rep;

    rep->ip_blink = father_ip;
    rep->ip_flink = father_ip->ip_flink;
    if (rep->ip_flink != NULL)
       rep->ip_flink->ip_blink = rep;
    father_ip->ip_flink = rep;

    rep->ftp_link = NULL;
   
    
    tcp_connection_live++;
    tcp_map_entry_ptr =rep;
      
    rep->ip_outside = out_ip;
   
    return rep;
}


udp_map_entry_t  *udp_map_table_add(ipaddr_t ip_remote, ushort_t port_remote, ipaddr_t netaddr, ushort_t port, ipaddr_t out_ip)
{
    udp_map_entry_t  *rep, *repbase, *mapbase;
    udp_map_entry_t  *father_ip, *father_port;
    ushort_t port_an;
    ushort_t max_session;
   

    port_an = AllocUDPNewPort(ip_remote,port_remote,port);

    father_ip = (udp_map_entry_t *) &udp_hash_ptr_for_out[ __IP_hash3( netaddr, port) ];
    father_port = (udp_map_entry_t *) ((char *)&udp_hash_ptr_for_in[ __Port_hash3( port_an,ip_remote) ]- 3*sizeof(udp_map_entry_t *));
    rep = repbase = udp_map_entry_ptr;
    mapbase = udp_fastnat_table;
    max_session = UDP_FASTNAT_TABLE_NUMBER;
  
    while(1)    /* find an available route entry to add */
    {
        ++rep;
        //printk("2");

        if( rep == (udp_map_entry_t *)&mapbase[ max_session ] )
            rep = (udp_map_entry_t *)&mapbase[0];
            
        if ( (rep->flag & BE_USED) == 0 )
            break;
            
        if( rep == repbase )
        {
            return NULL; //NAT Table full !!
        }
    }
    
    rep->flag = BE_USED;
    rep->ip_client = netaddr;
    rep->port_client = port;
    rep->port_device = port_an;

    rep->timer = 0;
    rep->ip_remote = ip_remote;
    rep->port_remote = port_remote;

    rep->port_ulink = father_port;
    rep->port_dlink = father_port->port_dlink;
    if ( father_port->port_dlink != NULL)
       rep->port_dlink->port_ulink = rep;
    father_port->port_dlink = rep;

    rep->ip_blink = father_ip;
    rep->ip_flink = father_ip->ip_flink;
    if (rep->ip_flink != NULL)
       rep->ip_flink->ip_blink = rep;
    father_ip->ip_flink = rep;
    
    udp_map_entry_ptr =rep;
    udp_connection_live++;
      
    rep->ip_outside = out_ip;
 
    return rep;
}

void fastnat_add_tcp(ipaddr_t ip_remote, ushort_t port_remote, ipaddr_t netaddr, ushort_t port, ipaddr_t out_ip , struct ip_conntrack *ct)
{
	tcp_map_entry_t  *mp;
	
  mp = tcp_map_table_add ( ip_remote,port_remote,netaddr , port , out_ip );
  if( mp )
  	mp->conn = ct;			                           	   
}

void fastnat_add_udp(ipaddr_t ip_remote, ushort_t port_remote, ipaddr_t netaddr, ushort_t port, ipaddr_t out_ip , struct ip_conntrack *ct)
{
	udp_map_entry_t  *mp;
	
  mp = udp_map_table_add ( ip_remote,port_remote,netaddr , port , out_ip );
  if( mp )
  	mp->conn = ct;			                           	   
}

void fastnat_add_newentry(u_int32_t protonum,u_int32_t newsrc,struct ip_conntrack *ct)
{
  
  tcp_map_entry_t  *mp;
  udp_map_entry_t  *mp1;
  
	if(shnat_pause) //shnat is disable
		return;	
  if( !ct->allow_cache )
       return 0;
	
	//printk("fastnat_add_newentry:fast nat added \n");
	
  switch(protonum)
		{
			case IPPROTO_TCP:
			  if ( mp = tcp_map_table_add ( ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.ip,
			                           (&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->dst.u.tcp.port,
			                           ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.ip,
			                           (&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->src.u.tcp.port,
			                           newsrc ) )
			  { 
			    mp->conn = ct;
			    //mp->masq_index = ct->nat.masq_index;
			    DO_PRINT("<New TCP entry:%x,%d,%x,sport:%d,%x,dport:%d>\n",(ulong_t *)ct,tcp_connection_live,
	                        ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.ip,
	                        ntohs((&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->src.u.tcp.port),
	                        ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.ip,
	                        ntohs((&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->dst.u.tcp.port));
			  }
				break;
				
			case IPPROTO_UDP:
			  if ( mp1 = udp_map_table_add ( ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.ip,
			                           (&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->dst.u.udp.port,
			                           ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.ip,
			                           (&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->src.u.udp.port,
			                           newsrc) )
			  {
			    mp1->conn = ct;
			    //mp1->masq_index = ct->nat.masq_index;
			    DO_PRINT("<New UDPP entry:%x,%d,%x,sport:%d,%x,dport:%d>\n",(ulong_t *)ct,udp_connection_live,
	                        ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.ip,
	                        ntohs((&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->src.u.udp.port),
	                        ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.ip,
	                        ntohs((&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)->dst.u.udp.port) );
			  }
				break;
			
			default:
				break;
		}
}


tcp_map_entry_t  *tcp_find_entry_out(ipaddr_t IPclient,ushort_t PORTclient, ipaddr_t IPremote,ushort_t PORTremote)
{
    tcp_map_entry_t *rep, *father;
    int i=0;

    father = (tcp_map_entry_t *)&tcp_hash_ptr_for_out[ __IP_hash3( IPclient,PORTclient ) ];

    while( rep = father->ip_flink )
    {
        //printk("3" );
    	
        if( rep->port_client == PORTclient && rep->port_remote == PORTremote &&
            rep->ip_remote == IPremote && rep->ip_client == IPclient )
           break;
        father = rep;
        i++ ;
        if( i > 255 )
        	return NULL;
    }
    
    if( rep )
        rep->timer = 0;
 
    return rep;
}


tcp_map_entry_t *tcp_find_entry_in(ushort_t vport, ipaddr_t IPremote, ushort_t PORTremote)
{
    tcp_map_entry_t *rep, *father;
    int i=0;

    father = (tcp_map_entry_t *) ((char *)&tcp_hash_ptr_for_in[ __Port_hash3( vport,IPremote ) ]- 3*sizeof(tcp_map_entry_t *)); //ip_flink,ip_blink,port_ulink

    rep = father->port_dlink;
    
    while( rep )
    {
        //printk("4");
    	
        if( rep->port_device == vport &&
            rep->port_remote == PORTremote && rep->ip_remote == IPremote )
           break;
        rep = rep->port_dlink;
        i++;
        if( i > 255 )
        	return NULL;
    }
    
    if( rep )
        rep->timer = 0;
        
    return rep;

}


static int tcp_fast_past_packet(struct sk_buff *skb)
{
  tcp_map_entry_t *mp;
	int  tcp_len;
	
	skb->h.raw = skb->nh.raw + (skb->nh.iph->ihl * 4);//Pointer to TCP header
	
/******************************************************/
//LAN -> WAN check & process Start
	if ( mp = tcp_find_entry_out(skb->nh.iph->saddr, skb->h.th->source, skb->nh.iph->daddr, skb->h.th->dest) )
	{
	  if (mp->lan2wan_dst == 0)
    {
      //DO_PRINT("\n TCP LAN -> WAN dst not found \n");
      return 0;
    }
    
    if (skb->nh.iph->frag_off & MORE_FRAGMENT_BIT)
    {
      //DO_PRINT("\n Fragment Packet \n");
      return 0;
    }
    //DO_PRINT("t");
    // Replace the new data
    skb->dst = mp->lan2wan_dst;
    skb->nh.iph->saddr = mp->ip_outside;
    skb->h.th->source = mp->port_device ;
    // Caculate the checksum
    skb->nh.iph->check = 0;
		skb->nh.iph->check = ip_fast_csum((unsigned char *)skb->nh.iph,skb->nh.iph->ihl);
		skb->h.th->check = 0;
		tcp_len = htons(skb->nh.iph->tot_len) -(skb->nh.iph->ihl * 4);
		mp->flag |= BE_RUNNING;
		
		if (skb->h.th->fin)
		  mp->flag |= FIN_LAN2WAN;
		if (skb->h.th->rst)
		  mp->flag |= BE_RST;
			
		skb->h.th->check = tcp_v4_check(skb->h.th,tcp_len ,
				   skb->nh.iph->saddr,
				   skb->nh.iph->daddr,
				   csum_partial((char *)skb->h.th,
						tcp_len, 0));
    
    skb->dev = skb->dst->dev;      //Added by Keilven
		ip_finish_output2(skb);
		return 1;
	}
//LAN -> WAN check & process End
/******************************************************/

/******************************************************/
//WAN -> LAN check & process Start
  if( mp = tcp_find_entry_in( skb->h.th->dest, skb->nh.iph->saddr, skb->h.th->source))
  {
    if (mp->wan2lan_dst == 0)
    {
//      DO_PRINT("\n TCP WAN -> LAN dst not found \n");
      return 0;
    }
    
    if (skb->nh.iph->frag_off & MORE_FRAGMENT_BIT)
    {
//      DO_PRINT("\n Fragment Packet \n");
      return 0;
    }
    // Replace the new data
    skb->dst = mp->wan2lan_dst;
    skb->nh.iph->daddr = mp->ip_client;
    skb->h.th->dest = mp->port_client;
    //Caculate the checksum
    skb->nh.iph->check = 0;
		skb->nh.iph->check = ip_fast_csum((unsigned char *)skb->nh.iph,skb->nh.iph->ihl);

		skb->h.th->check = 0;		
		tcp_len = htons(skb->nh.iph->tot_len) -(skb->nh.iph->ihl * 4);
		mp->flag |= BE_RUNNING;
		
		if (skb->h.th->fin)
		  mp->flag |= FIN_WAN2LAN;
		if (skb->h.th->rst)
		  mp->flag |= BE_RST;
		
		
		skb->h.th->check = tcp_v4_check(skb->h.th, tcp_len,
				   skb->nh.iph->saddr,
				   skb->nh.iph->daddr,
				   csum_partial((char *)skb->h.th,
						tcp_len, 0));
						
    skb->dev = skb->dst->dev;      //Added by Keilven
		ip_finish_output2(skb);

		return 1;		
  }

//WAN -> LAN check & process End
/******************************************************/
//Not found
	return 0;
}


udp_map_entry_t *udp_find_entry_out(ipaddr_t IPclient,ushort_t PORTclient,ipaddr_t IPremote,ushort_t PORTremote)
{
    udp_map_entry_t *rep, *father;
    int i;
    
    father = (udp_map_entry_t *) &udp_hash_ptr_for_out[ __IP_hash3( IPclient, PORTclient) ];

    while( rep = father->ip_flink )
    {
        //printk("5");
    	
        if( rep->port_client == PORTclient && rep->port_remote == PORTremote &&
            rep->ip_remote == IPremote && rep->ip_client == IPclient )
           break;
           
        father = rep;
        i++ ;
        if( i > 255 )
        	return NULL;
    }
    
    if( rep )
        rep->timer = 0;

    return rep;
}


udp_map_entry_t  *udp_find_entry_in(ushort_t vport,ipaddr_t IPremote,ushort_t PORTremote )
{
  udp_map_entry_t  *rep,*father;
  int i;

  father = (udp_map_entry_t *) ((char *)&udp_hash_ptr_for_in[ __Port_hash3( vport,IPremote ) ]- 3*sizeof(udp_map_entry_t *));

    rep = father->port_dlink;
    
    while( rep )
    {
        //printk("6");
    	
        if( rep->port_device == vport &&
            rep->port_remote == PORTremote && rep->ip_remote == IPremote )
          break;
          
        rep = rep->port_dlink;
        i++ ;
        if( i > 255 )
        	return NULL;
    }
    
    if( rep )
        rep->timer = 0;
        
    return rep;
}


static int udp_fast_past_packet(struct sk_buff *skb)
{
  udp_map_entry_t *mp1;
	int  udp_len;

	skb->h.raw = skb->nh.raw + (skb->nh.iph->ihl * 4);//Pointer to UDP header
	
/******************************************************/
//LAN -> WAN check & process Start
  if (mp1 = udp_find_entry_out(skb->nh.iph->saddr, skb->h.uh->source, skb->nh.iph->daddr, skb->h.uh->dest))
	{
	  if (mp1->lan2wan_dst == 0)
    {
      //DO_PRINT("\n UDP LAN -> WAN dst not found \n");
      return 0;
    }
    
    if (skb->nh.iph->frag_off & MORE_FRAGMENT_BIT)
    {
      //DO_PRINT("\n Fragment Packet \n");
      return 0;
    }
    
    // Replace the new data
    skb->dst = mp1->lan2wan_dst;
    skb->nh.iph->saddr = mp1->ip_outside;
    skb->h.uh->source = mp1->port_device;   
    // Caculate the checksum
    skb->nh.iph->check = 0;
		skb->nh.iph->check = ip_fast_csum((unsigned char *)skb->nh.iph,skb->nh.iph->ihl);
		skb->h.uh->check = 0;
		udp_len = htons(skb->nh.iph->tot_len) -(skb->nh.iph->ihl * 4);
		mp1->flag |= BE_RUNNING;
			
		skb->h.uh->check =csum_tcpudp_magic(skb->nh.iph->saddr, skb->nh.iph->daddr,
							udp_len, IPPROTO_UDP,
							csum_partial(skb->h.raw, udp_len, 0));
    
    skb->dev = skb->dst->dev;      //Added by Keilven
		ip_finish_output2(skb);
		return 1;
	}
//LAN -> WAN check & process End
/******************************************************/
	
/******************************************************/
//WAN -> LAN check & process Start
  if( mp1 = udp_find_entry_in( skb->h.uh->dest,  skb->nh.iph->saddr, skb->h.uh->source))
  {
    if (mp1->wan2lan_dst == 0)
    {
      DO_PRINT("\n UDP WAN -> LAN dst not found \n");
      return 0;
    }
  
    if (skb->nh.iph->frag_off & MORE_FRAGMENT_BIT)
    {
      DO_PRINT("\n Fragment Packet \n");
      return 0;
    }
    
    // Replace the new data
    skb->dst = mp1->wan2lan_dst;
    skb->nh.iph->daddr = mp1->ip_client;
    skb->h.uh->dest = mp1->port_client;
    //Caculate the checksum
    skb->nh.iph->check = 0;
		skb->nh.iph->check = ip_fast_csum((unsigned char *)skb->nh.iph,skb->nh.iph->ihl);

		skb->h.uh->check = 0;		
		udp_len = htons(skb->nh.iph->tot_len) -(skb->nh.iph->ihl * 4);
		mp1->flag |= BE_RUNNING;
		
		skb->h.uh->check =csum_tcpudp_magic(skb->nh.iph->saddr, skb->nh.iph->daddr,
							udp_len, IPPROTO_UDP,
							csum_partial(skb->h.raw, udp_len, 0));
						
    skb->dev = skb->dst->dev;      //Added by Keilven
		ip_finish_output2(skb);

		return 1;		
  }

//WAN -> LAN check & process End
/******************************************************/	
//Not found
	return 0;
}

int process_software_fastnat(struct sk_buff *skb)
{
	if(shnat_pause) //shnat is disable
		return 0;

	skb->nh.raw = skb->data;  //Modify by Keilven, 08/16/2006
	
  switch(skb->nh.iph->protocol)
		{
			case IPPROTO_TCP:

				if(tcp_fast_past_packet(skb))
				{
					//Hnat software simulation is trigger
					return 1;
				}		
			  break;
			
			case IPPROTO_UDP:
				if(udp_fast_past_packet(skb))
				{
					return 1;
				}
				break;
				
			default:
				//printk("\n Exception packet !! \n");
				break;
		}
		
	return 0;
}        

int tcp_connection_find_record_dst(struct sk_buff *skb)
{
  tcp_map_entry_t *mp;
	
	skb->h.raw = skb->nh.raw + (skb->nh.iph->ihl * 4);//Pointer to TCP header
	
/******************************************************/
//LAN -> WAN check & process Start
	if ( mp = tcp_find_entry_out(skb->nh.iph->saddr, skb->h.th->source, skb->nh.iph->daddr, skb->h.th->dest) )
	{
    // Record the new data
    mp->lan2wan_dst = skb->dst;
		return 1;
	}
//LAN -> WAN check & process End
/******************************************************/

/******************************************************/
//WAN -> LAN check & process Start
  if( mp = tcp_find_entry_in( skb->h.th->dest,  skb->nh.iph->saddr, skb->h.th->source))
  {
    // Replace the new data
    mp->wan2lan_dst = skb->dst;
		return 1;		
  }

//WAN -> LAN check & process End
/******************************************************/
//Not found
	return 0;
}

static int udp_connection_find_record_dst(struct sk_buff *skb)
{
  udp_map_entry_t *mp1;

	skb->h.raw = skb->nh.raw + (skb->nh.iph->ihl * 4);//Pointer to UDP header
	
	
/******************************************************/
//LAN -> WAN check & process Start
  if (mp1 = udp_find_entry_out(skb->nh.iph->saddr, skb->h.uh->source, skb->nh.iph->daddr, skb->h.uh->dest))
	{
    // Record the dst interface
    mp1->lan2wan_dst = skb->dst;
		return 1;
	}
//LAN -> WAN check & process End
/******************************************************/
	
/******************************************************/
//WAN -> LAN check & process Start
  if( mp1 = udp_find_entry_in( skb->h.uh->dest,skb->nh.iph->saddr, skb->h.uh->source))
  {
    // Record the dst interface
    mp1->wan2lan_dst = skb->dst;
		return 1;		
  }

//WAN -> LAN check & process End
/******************************************************/	
//Not found
	return 0;
}

int record_dst_interface(struct sk_buff *skb)
{
	
	if(shnat_pause) //shnat is disable
		return 0;

	skb->nh.raw = skb->data;  //Modify by Keilven, 08/16/2006
	
  switch(skb->nh.iph->protocol)
		{
			case IPPROTO_TCP:
				if(tcp_connection_find_record_dst(skb))
				{
					//Hnat software simulation is trigger
					return 1;
				}		
			break;
			
			case IPPROTO_UDP:
				if(udp_connection_find_record_dst(skb))
				{
					return 1;
				}
				break;
				
			default:
				break;
		}
		
	return 0;
}

void TCPSession_HouseKeeping(tcp_map_entry_t *start,tcp_map_entry_t *End)
{
  tcp_map_entry_t *rep;
  ulong_t idle_timeout;

  rep = start;
  while( ++rep < End ) // Examine all entries
  {
    if ( ( rep->flag & BE_USED ) == 0 )          // If NOT in use
            continue;
              
    //Session is running, reset timer
    if( rep->flag & BE_RUNNING )
          rep->timer = 0;
          
    //Clean session running
    rep->flag &= ~BE_RUNNING;
    
    //If TCP Receive FIN, delete session directly now.
    if( rep->flag & FIN_LAN2WAN )
    {
      if( rep->flag & FIN_WAN2LAN)
      {
        del_tcp_fastnat_entry( rep );
        continue;
      }
    }
    
    if( rep->flag & BE_RST )
    {
      del_tcp_fastnat_entry( rep ); 
      return;
    }
    //If Connection is Telnet, idle time set to 10 hours
    //if ( rep->aptype == TELNET_SESSION)
    //  idle_timeout = TELNET_CONNECTION_IDLE ;
    //else
      idle_timeout = TCP_TIME_OUT;
      
    //Check Idle now !!
    if ( ++rep->timer >= idle_timeout)
        del_tcp_fastnat_entry( rep );        // remove idle entry
  }//while( ++rep < End )
}

void UDPSession_HouseKeeping(udp_map_entry_t *start,udp_map_entry_t *End)
{
  udp_map_entry_t *rep1;
  ulong_t idle_timeout;

  rep1 = start;
  while( ++rep1 < End ) // Examine all entries
  {
    if ( ( rep1->flag & BE_USED ) == 0 )          // If NOT in use
      continue;
      
    if( rep1->flag & BE_RUNNING )
      {
      rep1->timer = 0;
      }
      
    rep1->flag &= ~BE_RUNNING;
    
    idle_timeout = UDP_TIME_OUT;
    
    //Check Idle now !!
    if ( ++rep1->timer > idle_timeout )
    {
      del_udp_fastnat_entry( rep1 ); // remove idle entry
    } //if ( ++rep1->timer > idle_timeout )
  }//while( ++rep1 < End ) // Examine all entries
}

static void snat_house_keeping(unsigned long data)
{ 
 	//DO_PRINT("<snat_house_keeping>");

 	/* Timer active again */
 	TCPSession_HouseKeeping(&tcp_fastnat_table[-1],&tcp_fastnat_table[TCP_FASTNAT_TABLE_NUMBER]);
  UDPSession_HouseKeeping(&udp_fastnat_table[-1],&udp_fastnat_table[UDP_FASTNAT_TABLE_NUMBER]);
 	snat_refresh_timer.expires = HOURSE_KEEPING_PERIOD;
 	add_timer(&snat_refresh_timer);
}

/******************************************************************************
 *
 * Software NAT initial function
 *
 ******************************************************************************/

void software_nat_init(struct net_device *dev)
{
	  u_int32_t len;

	  
	if (!snat_initial)
	{
	  init_timer(&snat_refresh_timer);
	  snat_refresh_timer.expires = HOURSE_KEEPING_PERIOD;
	  //snat_refresh_timer.data = 0;
	  snat_refresh_timer.function = snat_house_keeping;
	  add_timer(&snat_refresh_timer); 

		len = sizeof(tcp_map_entry_t*) * 256;
    clean_field((char *)tcp_hash_ptr_for_in, len);
    clean_field((char *)tcp_hash_ptr_for_out, len);
    len = sizeof(udp_map_entry_t *) * 256;
    clean_field((char *)udp_hash_ptr_for_in, len );
    clean_field((char *)udp_hash_ptr_for_out, len );
    
    len = sizeof(tcp_map_entry_t) * TCP_FASTNAT_TABLE_NUMBER;
    clean_field((char *)tcp_fastnat_table, len );
    len = sizeof(udp_map_entry_t) * UDP_FASTNAT_TABLE_NUMBER;
    clean_field((char *)udp_fastnat_table, len );
		
		tcp_connection_live = 0;
    udp_connection_live = 0;	
    	
    tcp_port_new_alloc = TCP_PORT_START;
    udp_port_new_alloc = UDP_PORT_START;
		
		tcp_map_entry_ptr = (tcp_map_entry_t  *)&tcp_fastnat_table[-1];
    udp_map_entry_ptr = (udp_map_entry_t  *)&udp_fastnat_table[-1];
}
  snat_initial ++;
}


EXPORT_SYMBOL(process_software_fastnat);
EXPORT_SYMBOL(software_nat_init);
EXPORT_SYMBOL(shnat_external_cmd);
EXPORT_SYMBOL(record_dst_interface);

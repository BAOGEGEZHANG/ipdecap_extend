/*
  Copyright (c) 2012-2013 Loïc Pefferkorn <loic-ipdecap@loicp.eu>
  ipdecap [http://www.loicp.eu/ipdecap]

  This file is part of ipdecap.

  Ipdecap is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  Ipdecap is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with ipdecap.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <pcap/vlan.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <openssl/evp.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include <stdbool.h>
#include <inttypes.h>

#include "config.h"
#include "ipdecap.h"
#include "gre.h"
#include "esp.h"

// Command line parameters
static const char *args_str = "vi:o:c:f:Vl";

struct global_args_t
{
  char *input_file;       // --input option
  char *output_file;      // --output option
  char *esp_config_file;  // --config option
  char *bpf_filter;       // --filter option
  bool verbose;           // --verbose option
  bool list_algo;         // --list option
} global_args;

static const struct option args_long[] =
{
  { "input",      required_argument,  NULL, 'i'},
  { "output",     required_argument,  NULL, 'o'},
  { "esp_config", required_argument,  NULL, 'c'},
  { "filter",     required_argument,  NULL, 'f'},
  { "list",       no_argument,        NULL, 'l'},
  { "verbose",    no_argument,        NULL, 'v'},
  { "version",    no_argument,        NULL, 'V'},
  { NULL,         0,                  NULL, 0}

};

// Global variables
pcap_dumper_t *pcap_dumper;
int ignore_esp;

void usage(void)
{
  printf("Ipdecap %s, decapsulate ESP, GRE, IPIP packets - Loic Pefferkorn\n", PACKAGE_VERSION);
  printf(
    "Usage\n"
    "    ipdecap [-v] [-l] [-V] -i input.cap -o output.cap [-c esp.conf] [-f <bpf filter>] \n"
    "Options:\n"
    "  -c, --conf     configuration file for ESP parameters (IP addresses, algorithms, ... (see man ipdecap)\n"
    "  -h, --help     this help message\n"
    "  -i, --input    pcap file to process\n"
    "  -o, --output   pcap file with decapsulated data\n"
    "  -f, --filter   only process packets matching the bpf filter\n"
    "  -l, --list     list availables ESP encryption and authentication algorithms\n"
    "  -V, --version  print version\n"
    "  -v, --verbose  verbose\n"
    "\n");
}


//define by myself

#define IP_FLAG_DF      0x4000
#define IP_FLAG_MF      0x2000
#define IP_FLAG_Flag    0xe000
#define IP_FLAG_OFFSET  0x1fff

#define IP_FLAG_MF_START    0X01
#define IP_FLAG_MF_MID      0X02
#define IP_FLAG_MF_END      0X03

#define GRE_PPP_ZIP         0X00
#define GRE_PPP_NO_ZIP      0X01
#define GRE_PPP_FRAGMENT    0X02
#define GRE_PPP_SLIP        0X03
#define GRE_PPP_NCP         0X04
#define GRE_PPP_NO_IP       0X05
#define GRE_PPP_INVAILD     0X05

#define GRE_PPP_MIN_SIZE    0X01
#define GRE_PPP_ZIP_HEADERSIZE 0X02
#define GRE_PPP_NO_ZIP_HEADERSIZE 0X05
#define GRE_PPP_PACKET_MAXNUM_PPP  64

#define DGB_FORMAT_LINE_LEN     16
#define IP_PAYLOAD_MIN_SIZE     20


#define GetBit(dat,i) ((dat&(0x0001<<i))?1:0)
#define SetBit(dat,i) ((dat)|=(0x0001<<(i)))
#define ClearBit(dat,i) ((dat)&=(~(0x0001<<(i))))



typedef struct _note Note;
typedef struct _node Node;
typedef struct _Point Point;
typedef struct _PPP_RET PPP_RET;
typedef struct _gre_flag GRE_FLAG;


struct _gre_flag
{
  uint32_t key;
  uint32_t seqnum;
};

struct _note
{
  uint32_t flag;
  uint32_t id;
  uint32_t offset;
  uint32_t inter_ip_src;
  uint32_t inter_ip_dst;
  GRE_FLAG gre_flag;
};

struct _node
{
  struct list_head pos;
  int age_time;
  uint32_t hash_id;
  Note ip;
};

struct _Point
{
  int start;
  int end;
};

struct _PPP_RET
{
  const u_char *org_bkt;
  int ppp_num;
  Point ppp_pos[GRE_PPP_PACKET_MAXNUM_PPP] ;
};

Node *list;
static int packet_num = 0;




//Debug Function
void Print_Debug(unsigned char*pos, int len)
{
#ifndef _QDEBUG
    return ;
#endif
  if (NULL == pos){
    QDebug_Error("Print_Debug parameter:pos is invalid");
    return ;
  }
  int i;
  for (i = 0; i < len; i++)
  {
    printf ("%02x ", pos[i]);
    if ((i+1)%DGB_FORMAT_LINE_LEN == 0) printf ("\n");
  }
  printf ("\n");
}

//IP.Flag Function
int Is_IP_Fragment(struct ip ip_hdr)
{
  if (ntohs(ip_hdr.ip_off) & IP_FLAG_DF)
    return 0;
  return 1;
}

int Get_IP_Fragment_statue(const struct ip ip_hdr)
{
  if (Is_IP_Fragment(ip_hdr))
  {
    if (ntohs(ip_hdr.ip_off) & IP_FLAG_MF)
    {
      if (ntohs(ip_hdr.ip_off) & IP_FLAG_OFFSET)
      {
        return IP_FLAG_MF_MID;
      }
      else
      {
        return IP_FLAG_MF_START;
      }
    }
    else /*not more fragment*/
    {
      if (!(ntohs(ip_hdr.ip_off) & IP_FLAG_OFFSET))
      {
        return IP_FLAG_MF_START;
      }
      else
      {
        return IP_FLAG_MF_END;
      }
    }
  }
  else
  {
    QDebug_string("[%s]Not Fragment");
  }
}

uint16_t Get_IP_FLAG_Offset(struct ip ip_hdr)
{
  return (IP_FLAG_OFFSET & ntohs(ip_hdr.ip_off));
}


uint32_t Get_hashid(uint32_t add1, uint32_t add2, uint16_t id)
{
  return add1 + add2 + id;
}

uint8_t Set_IP_FLAG_DF (struct ip *ip_hdr, uint8_t flag)
{
  if (flag == 1)
    ip_hdr->ip_off = htons(ntohs(ip_hdr->ip_off) | IP_FLAG_DF);
  else
    ip_hdr->ip_off = htons(ntohs(ip_hdr->ip_off) & (~IP_FLAG_DF));
  return ntohs(ip_hdr->ip_off) & IP_FLAG_DF;
}

uint8_t Set_IP_FLAG_MF (struct ip *ip_hdr, uint8_t flag)
{
  if (flag == 1)
    ip_hdr->ip_off = htons(ntohs(ip_hdr->ip_off) | IP_FLAG_MF);
  else
    ip_hdr->ip_off = htons(ntohs(ip_hdr->ip_off) & (~IP_FLAG_MF));
  return ntohs(ip_hdr->ip_off) & IP_FLAG_MF;
}


uint16_t Set_IP_FLAG_Offset (struct ip *ip_hdr, uint16_t offset)
{
  ip_hdr->ip_off = htons((ntohs(ip_hdr->ip_off) & IP_FLAG_Flag) | offset );
  return (ip_hdr->ip_off);
}


uint16_t ip_checksum(uint16_t *ip_payload, int ip_payload_length)
{
  if ((NULL == ip_payload) || (ip_payload_length < IP_PAYLOAD_MIN_SIZE)){
    QDebug_Errorval2("ip_checksum is failed,parameter is invalid;ip_payload, ip_payload_length;", ip_payload, ip_payload_length);
    return 0;
  }
  uint32_t cksum = 0;
  while(ip_payload_length> 1)
  {
    cksum += *ip_payload ++;
    ip_payload_length-= sizeof(uint16_t);
  }
  if (ip_payload_length)
  {
    cksum += *(uint8_t*)ip_payload;
  }
  cksum = (cksum >> 16) + (cksum & 0xffff);
  cksum += (cksum >> 16);
  return (uint16_t)(~cksum);
}

//#########################################################
//  LIST Function
//#########################################################

/*
* name: Add_List
* parameter :
  list : header of list;
  hash_id : key of list
  ip: save data
* ret : success 0; failed 1;
* description: save data into list
*/
int Add_List(Node *list, uint32_t hash_id,Note ip)
{
  QDebug_string("Add_List into");
  Node *cur = (Node *)malloc(sizeof(struct _node));
  if (NULL == cur)
  {
    QDebug_string("[Add_List]malloc node space failed");
    return 1;
  }
  list_add (&(cur->pos), &(list->pos));
  cur->hash_id = hash_id;
  cur->age_time = 10;
  cur->ip = ip;
  QDebug_strval1("cur->hash_id:", cur->hash_id);
  return 0;
}
/*
* name: Destory_Node
* parameter :
  pos : node of list wated to delete
* ret : success 0; failed 1;
* description: delete node
*/
int Destory_Node(Node *pos)
{
  QDebug_string("[Delete Node]");
  list_del((struct list_head *)pos);
  free(pos);
  return 0;
}
/*
* name: Find_List
* parameter :
  list : header of list
  hash_id : key wanted to match
* ret : return Node if found ; else return NULL;
* description: find node by hash_id
*/
Node  *Find_List(Node *list, uint32_t hash_id)
{
  struct list_head *pos, *n;
  list_for_each_safe(pos, n, &(list->pos))
  {
    QDebug_strval1("pos->hash_id", ((Node*)pos)->hash_id);
    if (((Node *)pos)->hash_id == hash_id)
    {
      QDebug_string("[Find_List]found hash_id");
      return (Node *)pos;
    }
    //destory_node when age_time timeout
    if ( 0 >= ((Node *)pos)->age_time --)
    {
      Destory_Node((Node *)pos);
    }
  }
  return NULL;
}

//GRE packet parser & process function
/*
* name: gre_get_items
* parameter :
      gre_hdr : struct gre_hdr segment
      result  : output result after analyse
* ret : gre segment length
* description: Get gre segment and return key & seqnum
*/
int gre_get_items(struct grehdr *gre_hdr, GRE_FLAG *result)
{
  if ((NULL == gre_hdr) || (NULL == result)){
    QDebug_Errorval2("gre_get_items is failed, parameter is invalid, gre_hdr, result;", gre_hdr, result);
    return -1;
  }
  uint16_t flag;
  int length = 0;
  u_char *pos = (u_char *)gre_hdr;
  if (ntohs(gre_hdr->next_protocol) == 0x8881)
  {
    length = sizeof(struct grehdr);
    pos += length;
    flag = ntohs(gre_hdr->flags);
    if (flag & GRE_CHECKSUM || flag & GRE_ROUTING)
    {
      length += 4;
      pos += 4;
    }
    if (flag & GRE_KEY)
    {
      result->key = ntohl(*(int *)pos);
      length+= 4;
      pos += 4;
    }
    if (flag & GRE_SEQ)
    {
      result->seqnum = ntohl (*(int *)pos);
      length += 4;
      pos += 4;
    }
  }
  return length;
}

/*
* name: gre_get_ppp_type
* parameter :
  headerbytes : first 4bytes of ppp header
* ret : ppp type
* description: Get ppp header type
*/
int gre_get_ppp_type(int headerbytes)
{
  uint8_t *pos = (uint8_t *)(&headerbytes);

  if ((pos[0] == 0x7e) && (pos[1] == 0x21))
  {
    return GRE_PPP_ZIP;
  }else if ((pos[0] == 0x7e) && (pos[1] == 0xff) && (pos[2] == 0x03) && (pos[3] == 0x00)){
    return GRE_PPP_NO_ZIP;
  }else if ((pos[0] == 0x7e) && (pos[1] == 0xff) && (pos[2] == 0x03) && (pos[3] == 0xc0)){
    return GRE_PPP_SLIP;
  }else if ((pos[0] == 0x7e) && (pos[1] == 0xff) && (pos[2] == 0x03) && (pos[3] == 0x80)){
    return GRE_PPP_NCP;
  }else{
    return GRE_PPP_FRAGMENT;
  }
}

/*
* name: gre_ppp_parser
* parameter :
    ppp_payload : pos of start ppp segment payload
    ppp_payload_length : length of ppp segment
    ppp_ret : output result of anlynise ppp_payload
* return : success 0; failed : -1;
*   description : parset ppp segment ;
*/
int  gre_ppp_parser( const u_char *ppp_payload, const int ppp_payload_length, PPP_RET *ppp_ret)
{
  if ((NULL == ppp_payload) || (ppp_payload_length< GRE_PPP_MIN_SIZE) || (NULL == ppp_ret)){
    QDebug_Error("gre_ppp_parser failed;parameter is invalid");
    return -1;
  }

  memset(ppp_ret, 0x00,sizeof(PPP_RET));
  
  int pos = 0, ppp_num;
  ppp_num = 1;
	
  ppp_ret->ppp_pos[ppp_num].start = 0;
  
  if (ppp_payload[pos] == 0x7e)
	  pos ++;

  while(pos < ppp_payload_length){
	while( (pos < ppp_payload_length) && (ppp_payload[pos]!= 0x7e)) 
		pos++;

  if (pos >= ppp_payload_length){
	  QDebug_strval2("pos & payload", pos, ppp_payload_length);
		ppp_ret->ppp_pos[ppp_num].end = pos - 1;
  }else if ((ppp_payload[pos]== 0x7e)){
		if ((pos < ppp_payload_length - 1) && (ppp_payload[pos+1]== 0x7e)){
			ppp_ret->ppp_pos[ppp_num].end = pos;
			ppp_num ++;
			ppp_ret->ppp_pos[ppp_num].start = ++pos;
      ++pos;
      if (pos >= ppp_payload_length)
        ppp_num--;
		}else if ((pos < ppp_payload_length - 1) && (ppp_payload[pos+1]!= 0x7e)){
			ppp_ret->ppp_pos[ppp_num].end = pos - 1;
			ppp_num ++;
			ppp_ret->ppp_pos[ppp_num].start = pos++;
		}else {
			ppp_ret->ppp_pos[ppp_num].end = pos++;
		}
	}
  }
  ppp_ret->ppp_num = ppp_num;
  return 0;
}

/*
* name: format_ppp
* parameter :
        payload : pos of start ppp segment from 7e
        packet_size : modify total packet_size
* ret : success 0; failed -1;
* description : re_translatat ppp format;
*/
int format_ppp_packet (  u_char  *ppp_payload, int *ppp_payload_size)
{
  if ((NULL == ppp_payload) || (*ppp_payload_size < GRE_PPP_MIN_SIZE)){
    return -1;
  }
  int tmp_packet_size = *ppp_payload_size;
  int loop;
  for (loop = 0; loop < tmp_packet_size - 1 ; loop++)
  {
    if (ppp_payload[loop]== 0x7d )
    {
      ppp_payload[loop + 1] ^= 0x20;
      memcpy(ppp_payload + loop, ppp_payload + loop + 1, tmp_packet_size - loop - 1);
      tmp_packet_size --;
    }
  }
  *ppp_payload_size = tmp_packet_size;
  return 0;
}


/*
* name: gre_remove_PPP_header
* parameter :
  ppp_payload : pointer of payload_gre
  ppp_payload_length : total packet length
* ret : valid payload address of success , else invalid data;
*   description : remove ppp header ;
*/
u_char *gre_remove_PPP_header(u_char *ppp_payload, int *ppp_payload_length)
{
  QDebug_string("[gre_remove_PPP_header]comming into");
  if (NULL == ppp_payload){
    QDebug_Error("gre_remove_PPP_header is failed; parameter is invalid;");
    return GRE_PPP_INVAILD;
  }
  
  if(*ppp_payload_length < sizeof(int)){
    if (*(ppp_payload) != 0x7e){
      return GRE_PPP_FRAGMENT;
    }else{
      return GRE_PPP_INVAILD;
    } 
  }
  int gre_ppp_type ;
  gre_ppp_type = gre_get_ppp_type(*(int *)ppp_payload);
  QDebug_strval1("Get gre_ppp_type", gre_ppp_type);
  switch (gre_ppp_type)
  {
  case GRE_PPP_ZIP:
    if (*ppp_payload_length < GRE_PPP_ZIP_HEADERSIZE){
      QDebug_Errorval1( "PACKET_SIZE < GRE_PPP_ZIP_HEADERSIZE",   *ppp_payload_length);
      return GRE_PPP_INVAILD;
    }
    *ppp_payload_length -= 2;
    ppp_payload += 2;
    break;
  case GRE_PPP_NO_ZIP:
    if (*ppp_payload_length < GRE_PPP_NO_ZIP_HEADERSIZE){
      QDebug_Errorval1( "PACKET_SIZE < GRE_PPP_NO_ZIP_HEADERSIZE", *ppp_payload_length);
      return GRE_PPP_INVAILD;
    }
    *ppp_payload_length -= 5;
    ppp_payload  += 5;
    break;
  case GRE_PPP_NCP:
  case GRE_PPP_SLIP:
    return GRE_PPP_NO_IP;
  case GRE_PPP_FRAGMENT:
  default :
    QDebug_strval1("No stand gre_ppp_type is", gre_ppp_type);
    return (u_char *)GRE_PPP_FRAGMENT;
  }
  return ppp_payload;
}


/*
* name: gre_remove_PPP_tail
* parameter :
  ppp_payload : start of ppp segment ;
  ppp_payload_length : output parameter  and length of ppp_payload
* ret : 0 if success , else -1;
*   description : remove ppp header ;
*/
int gre_remove_PPP_tail(u_char *ppp_payload, int *ppp_payload_length)
{
  if ((NULL == ppp_payload) || (*ppp_payload_length < GRE_PPP_MIN_SIZE)){
    QDebug_Errorval1("gre_remove_PPP_tail is failed; parameter is invalid;ppp_payload_length will be", *ppp_payload_length);
    return -1;
  }
  if (ppp_payload[*ppp_payload_length - 1]== 0x7e)
  {
    QDebug_strval1("gre_remove_PPP_tail:[tail Bytes]:",ppp_payload[*ppp_payload_length - 1] );
    (*ppp_payload_length) --;
  }
  return 0;
}



/*
* name: gre_process_fragment_start
* parameter :
  payload: input payload of packet
  payload_len : packet_length
  new_packet_hdr : pcap header of packet
  new_packet_payload : payload of new packet
* result:
* description:
            cal hashid;  add outer_ip ip.flag ip.offset ; inter_ip ip.src ip.dst
            remove outer_ip segment and gre_headr , modify ip.fragment ip.offset ip.id ; cal ip.crc;

*/
void gre_process_fragment_start(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload)
{
  u_char *tmp_ppp_fragment_payload = NULL;
  u_char *ip_fragment = NULL; 
  //Deal MAC
  int packet_size = 0;
  const u_char *payload_src = NULL;
  u_char *payload_dst = NULL;
  
  struct ip ip_hdr ;
  payload_src = payload;
  payload_dst = new_packet_payload;

  memcpy( payload_dst, payload_src, sizeof(struct ether_header));
  payload_src += sizeof(struct ether_header);  
  payload_dst += sizeof(struct ether_header);
  packet_size = sizeof(struct ether_header);
  
  
  QDebug_strval1("Copy Eth header, packet_size:should be 14Bytes", packet_size);
  int protocol;

  //Cal Hash_id
  ip_hdr = *(struct ip*)payload_src;
  uint32_t outer_ip_src, outer_ip_dst;
  uint16_t outer_ip_id;
  uint32_t hash_id;
  uint32_t outer_offset;
  int outer_ip_size ;
  outer_ip_src  =   ntohl(ip_hdr.ip_src.s_addr);
  outer_ip_dst  =   ntohl(ip_hdr.ip_dst.s_addr);
  outer_ip_id   =   ntohs(ip_hdr.ip_id);
  protocol      =   ip_hdr.ip_p;
  outer_offset  =   Get_IP_FLAG_Offset(ip_hdr);
  hash_id       =   Get_hashid( outer_ip_dst, outer_ip_src, outer_ip_id);
  outer_ip_size = ip_hdr.ip_hl*4;
  
  packet_size += ntohs(ip_hdr.ip_len);
  
  ip_fragment = malloc(outer_ip_size);
  if (NULL == ip_fragment)
  {
    QDebug_string("[gre_process_fragment_start]malloc inter_ip_fragment_space failed");
    goto Failed;
  }
  memcpy(ip_fragment, payload_src, outer_ip_size);
  payload_src += ip_hdr.ip_hl*4;
  
  int fill_ip_dst, fill_ip_src;
  int total_byte;

  int gre_size = packet_size - sizeof (struct ether_header) - outer_ip_size;
  GRE_FLAG gre_flag;
  int grehdr_length = gre_get_items((struct grehdr*)payload_src, &gre_flag);
  QDebug_strval1("Get GRE length: should be 12Bytes", grehdr_length);
  payload_src += grehdr_length;
  int ppp_size = gre_size - grehdr_length;
  int key = gre_flag.key;
  int seqnum = gre_flag.seqnum;
  
  PPP_RET ppp_log;
  int ret ;
  ret = gre_ppp_parser( payload_src, ppp_size, &ppp_log);
  if (ret < 0){
    QDebug_string("gre_ppp_parser is failed in gre_process_fragment_start");
    goto Failed;
  }
  int ppp_index = 0;
  QDebug_strval1("total:ppp_num :", ppp_log.ppp_num);
  int ppp_num = ppp_log.ppp_num;
  int tmp_ppp_fragment_size;
  tmp_ppp_fragment_payload = malloc (65536);
  if (NULL == tmp_ppp_fragment_payload)
  {
    QDebug_string("[gre_process_fragment_start]malloc tmp_payload_fragment zone failed");
    return ;
  }
  memset(tmp_ppp_fragment_payload, 0x00, 65536);
  
  struct pcap_pkthdr out_pkthdr = {0x00};  
  //Deal frist packet
  ppp_index = ppp_num - ppp_log.ppp_num + 1;
  tmp_ppp_fragment_size = ppp_log.ppp_pos[ppp_index].end - ppp_log.ppp_pos[ppp_index].start + 1;
  memcpy(tmp_ppp_fragment_payload, payload_src + ppp_log.ppp_pos[ppp_index].start, tmp_ppp_fragment_size);

  ret = format_ppp_packet( tmp_ppp_fragment_payload, &tmp_ppp_fragment_size);
  if (ret < 0){
    QDebug_string("format_ppp_packet failed in frist packet deal of gre_process_fragment_start function");
    goto Failed;
  }
  u_char *new_ppp_fragment_payload = gre_remove_PPP_header( tmp_ppp_fragment_payload, &tmp_ppp_fragment_size);
  if (new_ppp_fragment_payload == GRE_PPP_NO_IP){
    goto Failed;
  }else {
    if (((uint64_t)new_ppp_fragment_payload != GRE_PPP_FRAGMENT)){
        gre_remove_PPP_tail( new_ppp_fragment_payload, &tmp_ppp_fragment_size);
    }else{
        gre_remove_PPP_tail( tmp_ppp_fragment_payload, &tmp_ppp_fragment_size);
    }
  }
  
  //PPP-Fragment
  if (((uint64_t)new_ppp_fragment_payload) == GRE_PPP_FRAGMENT)
  {
    Node* cur = Find_List( list, hash_id);
    if (cur != NULL)
    {
      if ( (cur->ip.gre_flag.key == gre_flag.key) && (cur->ip.gre_flag.seqnum == gre_flag.seqnum - 1))
      {
        fill_ip_dst = cur->ip.inter_ip_dst;
        fill_ip_src = cur->ip.inter_ip_src;
      }
    }
    else
    {
        fill_ip_dst = outer_ip_dst;
        fill_ip_src = outer_ip_src;
    }
        new_ppp_fragment_payload= tmp_ppp_fragment_payload;
  }
  else //not PPP-Fragment
  {
    QDebug_string("ppp_fragment is not fragment");
    struct ip* inter_ip_hdr = (struct ip*)new_ppp_fragment_payload;
    if (inter_ip_hdr->ip_hl*4 > tmp_ppp_fragment_size){
      goto Failed;
    }
    fill_ip_src = ntohl(inter_ip_hdr->ip_src.s_addr);
    fill_ip_dst = ntohl(inter_ip_hdr->ip_dst.s_addr);
    protocol    =  inter_ip_hdr->ip_p;
    
    new_ppp_fragment_payload += inter_ip_hdr->ip_hl*4;
    tmp_ppp_fragment_size -= inter_ip_hdr->ip_hl*4;
  }

  //Change something
  struct ip* tmp_ip_hdr = (struct ip*)ip_fragment;
  tmp_ip_hdr->ip_src.s_addr = htonl(fill_ip_src);
  tmp_ip_hdr->ip_dst.s_addr = htonl(fill_ip_dst);

  if (ppp_log.ppp_pos[ppp_index].end < ppp_size)
  {
    tmp_ip_hdr->ip_id  = htons(outer_ip_id);
    tmp_ip_hdr->ip_off  = 0;
    Set_IP_FLAG_DF( tmp_ip_hdr, 1);
    Set_IP_FLAG_MF( tmp_ip_hdr, 0);
  }
  else
  {
    tmp_ip_hdr->ip_id  = htons(outer_ip_id);
    tmp_ip_hdr->ip_off  = htons(outer_offset);
    Set_IP_FLAG_DF( tmp_ip_hdr, 0);
    Set_IP_FLAG_MF( tmp_ip_hdr, 1);
  }
  tmp_ip_hdr->ip_len = ntohs(tmp_ip_hdr->ip_hl*4+tmp_ppp_fragment_size);
  tmp_ip_hdr->ip_p = protocol;
  tmp_ip_hdr->ip_sum = 0x00;
  tmp_ip_hdr->ip_sum = htons(ip_checksum( (uint16_t *)ip_fragment, tmp_ip_hdr->ip_hl*4));
  memcpy(payload_dst, ip_fragment, tmp_ip_hdr->ip_hl*4);
  
  payload_dst += tmp_ip_hdr->ip_hl*4;
  memcpy(payload_dst, new_ppp_fragment_payload, tmp_ppp_fragment_size);
  QDebug_strval2("packet_num,ppp_index", packet_num, ppp_index);
  out_pkthdr.ts.tv_sec = packet_num;
  out_pkthdr.ts.tv_usec = ppp_index;
  out_pkthdr.caplen = tmp_ppp_fragment_size + sizeof(struct ether_header) + tmp_ip_hdr->ip_hl*4;
  out_pkthdr.len = out_pkthdr.caplen;
  pcap_dump((u_char *)pcap_dumper, &out_pkthdr, new_packet_payload);
  QDebug_strval1("Frist packet is deal, num:", ppp_index);

  ppp_log.ppp_num --;
  while(ppp_log.ppp_num)
  {
    ppp_index = ppp_num - ppp_log.ppp_num + 1;
   // printf("\033[31mPPP_Fragment:%d\033[0m\n", ppp_index);
    payload_dst = new_packet_payload + sizeof(struct ether_header);
    memset(tmp_ppp_fragment_payload, 0x00, 65536);
    tmp_ppp_fragment_size = ppp_log.ppp_pos[ppp_index].end - ppp_log.ppp_pos[ppp_index].start + 1;
    memcpy(tmp_ppp_fragment_payload, payload_src + ppp_log.ppp_pos[ppp_index].start, tmp_ppp_fragment_size);
    ret = format_ppp_packet( tmp_ppp_fragment_payload, &tmp_ppp_fragment_size);
    if (ret < 0){
      QDebug_strval2("format_ppp_packet is failed,packet: fragment:", packet_num + 1, ppp_index);
      goto NEXT;
    }
    new_ppp_fragment_payload = gre_remove_PPP_header( tmp_ppp_fragment_payload, &tmp_ppp_fragment_size);
    if (new_ppp_fragment_payload == GRE_PPP_NO_IP){
      QDebug_string("new_ppp_fragment_payload is GRE_PPP_NO_IP");
      goto NEXT;
    }
    if (new_ppp_fragment_payload == GRE_PPP_FRAGMENT){
      QDebug_string("new_ppp_fragment_payload is GRE_PPP_FRAGMENT");
      goto NEXT;
    }
    
    gre_remove_PPP_tail( new_ppp_fragment_payload, &tmp_ppp_fragment_size);
    //Change something
    struct ip* inter_ip_hdr = (struct ip*)new_ppp_fragment_payload;
    if (tmp_ppp_fragment_size < inter_ip_hdr->ip_hl*4){
        goto NEXT;
    }else {
        fill_ip_src = ntohl(inter_ip_hdr->ip_src.s_addr);
        fill_ip_dst = ntohl(inter_ip_hdr->ip_dst.s_addr);
        protocol = inter_ip_hdr->ip_p;
        new_ppp_fragment_payload+= inter_ip_hdr->ip_hl*4;
        tmp_ppp_fragment_size -= inter_ip_hdr->ip_hl*4;
    }
      
    tmp_ip_hdr = (struct ip*)ip_fragment;
    if (ppp_log.ppp_pos[ppp_index].end < ppp_size)
    {
      tmp_ip_hdr->ip_id  = htons(outer_ip_id + ppp_index);
      tmp_ip_hdr->ip_off  = 0;
      Set_IP_FLAG_DF( tmp_ip_hdr, 1);
      Set_IP_FLAG_MF( tmp_ip_hdr, 0);
    }
    else
    {
      tmp_ip_hdr->ip_id  = htons(outer_ip_id);
      tmp_ip_hdr->ip_off  = htons(outer_offset);
      Set_IP_FLAG_DF( tmp_ip_hdr, 0);
      Set_IP_FLAG_MF( tmp_ip_hdr, 1);
    }
    tmp_ip_hdr->ip_src.s_addr = htonl(fill_ip_src);
    tmp_ip_hdr->ip_dst.s_addr = htonl(fill_ip_dst);
    tmp_ip_hdr->ip_len = ntohs(tmp_ip_hdr->ip_hl*4 + tmp_ppp_fragment_size);
    tmp_ip_hdr->ip_p = protocol;
    tmp_ip_hdr->ip_sum = 0x00;
    tmp_ip_hdr->ip_sum = htons(ip_checksum( (uint16_t *)ip_fragment, tmp_ip_hdr->ip_hl*4));
    
    memcpy(payload_dst, ip_fragment, tmp_ip_hdr->ip_hl*4);
    payload_dst += tmp_ip_hdr->ip_hl*4;
    memcpy(payload_dst, new_ppp_fragment_payload, tmp_ppp_fragment_size);

    out_pkthdr.ts.tv_sec = packet_num;
    out_pkthdr.ts.tv_usec = ppp_index;
    out_pkthdr.caplen = tmp_ppp_fragment_size + sizeof(struct ether_header) + tmp_ip_hdr->ip_hl*4;
    out_pkthdr.len = out_pkthdr.caplen;
    pcap_dump((u_char *)pcap_dumper, &out_pkthdr, new_packet_payload);
    NEXT:
    ppp_log.ppp_num --;
  }
  Note cur;
  cur.flag = 1;
  cur.id = hash_id;
  cur.inter_ip_dst = fill_ip_dst;
  cur.inter_ip_src = fill_ip_src;
  cur.offset = outer_offset;
  cur.gre_flag.key = gre_flag.key;
  cur.gre_flag.seqnum = gre_flag.seqnum;
  Add_List( list, cur.id, cur);
Failed:
  if (NULL != ip_fragment)
    free(ip_fragment);
  if (NULL != tmp_ppp_fragment_payload)
    free(tmp_ppp_fragment_payload);
}
/*
* name: gre_process_fragment_other
* parameter :
  payload: input payload of packet
  payload_len : packet_length
  new_packet_hdr : pcap header of packet
  new_packet_payload : payload of new packet
* result:
* description:
            cal hashid;
*/
void gre_process_fragment_other(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload)
{
  QDebug_string("[gre_process_fragment_other]comming into");
  u_char *tmp_payload_fragment = NULL;
  u_char *ip_fragment = NULL;
  //Deal MAC
  int packet_size = 0;
  const u_char *payload_src = NULL;
  u_char *payload_dst = NULL;
  struct ip ip_hdr ;
  
  payload_src = payload;
  payload_dst = new_packet_payload;
  memcpy(payload_dst, payload_src, sizeof(struct ether_header));
  payload_src += sizeof(struct ether_header);
  payload_dst += sizeof(struct ether_header);
  
  packet_size = sizeof(struct ether_header);
  QDebug_strval1("Copy Eth header, packet_size:should be 14Bytes", packet_size);
  //Cal Hash_id
  ip_hdr = *(struct ip*)payload_src;
  uint32_t outer_ip_src, outer_ip_dst;
  uint16_t outer_ip_id;
  uint32_t hash_id;
  uint32_t outer_offset;
  int protocol;
  outer_ip_src  =   ntohl(ip_hdr.ip_src.s_addr);
  outer_ip_dst  =   ntohl(ip_hdr.ip_dst.s_addr);
  outer_ip_id   =   ntohs(ip_hdr.ip_id);
  protocol      =   ip_hdr.ip_p;
  outer_offset  =   Get_IP_FLAG_Offset(ip_hdr);
  hash_id       =   Get_hashid( outer_ip_dst, outer_ip_src, outer_ip_id);
  QDebug_strval1("Cal hashid", hash_id);
  
  int ip_fragment_size = ip_hdr.ip_hl * 4;
  ip_fragment = malloc (ip_fragment_size);
  if (NULL == ip_fragment)
  {
    QDebug_string("[gre_process_fragment_other]malloc ip_fragment failed");
    return ;
  }
  memcpy(ip_fragment, payload_src, ip_hdr.ip_hl*4);
  
  QDebug_strval1("Copy outer_ip into ip_fragment, size:should be 20Bytes", ip_hdr.ip_hl*4);
  int fill_ip_dst, fill_ip_src;
  
  //Remove gre header
  Node *cur = Find_List( list, hash_id);
  if (NULL == cur)
  {
    QDebug_string("[gre_process_fragment_other]found not hash_id, will use outer_ip");
    fill_ip_dst = outer_ip_dst;
    fill_ip_src = outer_ip_src;
    //  return ;
  }
  else 
  {
    fill_ip_dst = cur->ip.inter_ip_dst;
    fill_ip_src = cur->ip.inter_ip_src;
  }
  
  packet_size += ntohs(ip_hdr.ip_len);
  payload_src += ip_hdr.ip_hl*4;
  
  int ppp_size = packet_size - sizeof (struct ether_header) - ip_hdr.ip_hl*4;
  PPP_RET ppp_log;
  int ret ;
  ret = gre_ppp_parser( payload_src, ppp_size, &ppp_log);
  if (ret < 0){
    QDebug_string("gre_ppp_parser is failed in gre_process_fragment_other");
    goto Failed;
  }
  QDebug_strval1("total:ppp_num :", ppp_log.ppp_num);
  int ppp_num = ppp_log.ppp_num;
  int ppp_index ;
  u_char *new_ppp_fragment_payload = NULL;
  tmp_payload_fragment = malloc (65536);
  if (NULL == tmp_payload_fragment)
  {
    QDebug_string("[gre_process_fragment_start]malloc tmp_payload_fragment zone failed");
    goto Failed;
  }

  int tmp_ppp_fragment_size;
  struct pcap_pkthdr out_pkthdr;
  struct ip* tmp_ip_hdr ;
  
  while(ppp_log.ppp_num)
  {
    ppp_index = ppp_num - ppp_log.ppp_num + 1;
    QDebug_strval1("analyse ppp_fragment, num:", ppp_index);
    payload_dst = new_packet_payload + sizeof(struct ether_header);
    memset(tmp_payload_fragment, 0x00, 65536);
    QDebug_strval1("tmp_payload_fragment ", tmp_payload_fragment);
    tmp_ppp_fragment_size = ppp_log.ppp_pos[ppp_index].end - ppp_log.ppp_pos[ppp_index].start + 1;
    if (tmp_ppp_fragment_size < GRE_PPP_MIN_SIZE){
      QDebug_strval1("tmp_ppp_fragment_size is invalid,", tmp_ppp_fragment_size);
      goto NEXT;
    }
    memcpy(tmp_payload_fragment, payload_src + ppp_log.ppp_pos[ppp_index].start, tmp_ppp_fragment_size);
    ret = format_ppp_packet( tmp_payload_fragment, &tmp_ppp_fragment_size);
    if (ret < 0){
      QDebug_strval2("format_ppp_packet is failed,packet: fragment:", packet_num + 1, ppp_index);
      goto NEXT;
    }
    new_ppp_fragment_payload = gre_remove_PPP_header( tmp_payload_fragment, &tmp_ppp_fragment_size);
    if (new_ppp_fragment_payload == GRE_PPP_NO_IP){
      goto NEXT;
    }else{
      if ((uint64_t)new_ppp_fragment_payload != GRE_PPP_FRAGMENT){
        ret = format_ppp_packet( new_ppp_fragment_payload, &tmp_ppp_fragment_size);
        if (ret < 0){
          QDebug_strval2("format_ppp_packet is failed,packet: fragment:", packet_num + 1, ppp_index);
          goto NEXT;
        }
      }else{
        gre_remove_PPP_tail( tmp_payload_fragment, &tmp_ppp_fragment_size);
        QDebug_strval1("tmp_payload_fragment", tmp_payload_fragment);
      }
    }
    
  //PPP-Fragment
  if (((uint64_t)new_ppp_fragment_payload) == GRE_PPP_FRAGMENT)
  {
      QDebug_strval1("tmp_payload_fragment", tmp_payload_fragment);
    Node* cur = Find_List( list, hash_id);
    if (cur != NULL)
    {
        fill_ip_dst = cur->ip.inter_ip_dst;
        fill_ip_src = cur->ip.inter_ip_src;
    }
    else
    {
        fill_ip_dst = outer_ip_dst;
        fill_ip_src = outer_ip_src;
    }
    new_ppp_fragment_payload= tmp_payload_fragment;
  }
  else //not PPP-Fragment
  {
    QDebug_string("ppp_fragment is not fragment");
    struct ip* inter_ip_hdr = (struct ip*)new_ppp_fragment_payload;
    if (inter_ip_hdr->ip_hl*4 < tmp_ppp_fragment_size){
      goto Failed;
    }
    fill_ip_src = ntohl(inter_ip_hdr->ip_src.s_addr);
    fill_ip_dst = ntohl(inter_ip_hdr->ip_dst.s_addr);
    protocol    =  inter_ip_hdr->ip_p;
    
    new_ppp_fragment_payload += inter_ip_hdr->ip_hl*4;
    tmp_ppp_fragment_size -= inter_ip_hdr->ip_hl*4;
  }
    
    tmp_ip_hdr = (struct ip*)ip_fragment;
    tmp_ip_hdr->ip_sum = 0x00;
    tmp_ip_hdr->ip_src.s_addr = htonl(fill_ip_src);
    tmp_ip_hdr->ip_dst.s_addr = htonl(fill_ip_dst);
    tmp_ip_hdr->ip_p = protocol;
    if (ppp_log.ppp_pos[ppp_index].end < ppp_size)
    {
      tmp_ip_hdr->ip_id  = htons(outer_ip_id + ppp_index);
      tmp_ip_hdr->ip_off  = 0;
      Set_IP_FLAG_DF( tmp_ip_hdr, 1);
      Set_IP_FLAG_MF( tmp_ip_hdr, 0);
    }
    else
    {
      tmp_ip_hdr->ip_id  = htons(outer_ip_id);
      tmp_ip_hdr->ip_off  = htons(outer_offset);
      Set_IP_FLAG_DF( tmp_ip_hdr, 0);
      Set_IP_FLAG_MF( tmp_ip_hdr, 1);
    }
    tmp_ip_hdr->ip_sum = ip_checksum((uint16_t *)tmp_ip_hdr, tmp_ip_hdr->ip_hl*4);
    memcpy(payload_dst, ip_fragment, tmp_ip_hdr->ip_hl*4);
    
    payload_dst += tmp_ip_hdr->ip_hl*4;
    QDebug_strval1("tmp_ppp_fragment_size", tmp_ppp_fragment_size);
    memcpy(payload_dst, new_ppp_fragment_payload, tmp_ppp_fragment_size );
    out_pkthdr.ts.tv_sec = packet_num;
    out_pkthdr.ts.tv_usec = ppp_index;
    out_pkthdr.caplen = tmp_ppp_fragment_size + sizeof(struct ether_header) + tmp_ip_hdr->ip_hl*4;
    out_pkthdr.len = out_pkthdr.caplen;

    pcap_dump((u_char *)pcap_dumper, &out_pkthdr, new_packet_payload);
  NEXT:
    ppp_log.ppp_num --;
  }
Failed:
  if (ip_fragment != NULL)
    free(ip_fragment);
  if (NULL != tmp_payload_fragment)
    free(tmp_payload_fragment);
}






void print_version()
{
  printf("Ipdecap %s\n", PACKAGE_VERSION);
}

void verbose(const char *format, ...)
{
  if (global_args.verbose == true)
  {
    va_list argp;
    va_start (argp, format);
    vfprintf(stdout, format, argp);
    va_end(argp);
  }
}
/*
 * Parse commande line arguments
 *
 */
void parse_options(int argc, char **argv)
{
  int opt = 0;
  int opt_index = 0;
  // Init parameters to default values
  global_args.esp_config_file = NULL;
  global_args.input_file = NULL;
  global_args.output_file = NULL;
  global_args.bpf_filter = NULL;
  global_args.verbose = false;
  global_args.list_algo = false;
  opt = getopt_long(argc, argv, args_str, args_long, &opt_index);
  while(opt != -1)
  {
    switch(opt)
    {
    case 'i':
      global_args.input_file = optarg;
      break;
    case 'o':
      global_args.output_file = optarg;
      break;
    case 'c':
      global_args.esp_config_file = optarg;
      break;
    case 'f':
      global_args.bpf_filter = optarg;
      break;
    case 'l':
      global_args.list_algo = true;
      break;
    case 'v':
      global_args.verbose = true;
      break;
    case 'V':
      print_version();
      exit(EXIT_SUCCESS);
    case 'h':
    case '?':
      usage();
      exit(EXIT_FAILURE);
      break;
    case 0:
      if (strcmp("verbose", args_long[opt_index].name) == 0)
      {
        global_args.verbose = true;
      }
      break;
    default:
      break;
    }
    opt = getopt_long(argc, argv, args_str, args_long, &opt_index);
  }
}

void print_algorithms()
{
  printf("Supported ESP algorithms:\n"
         "\n"
         "\tEncryption:\n"
         "\n"
         "\t\tdes-cbc                            (rfc2405)\n"
         "\t\t3des-cbc                           (rfc2451)\n"
         "\t\taes128-cbc aes192-cbc aes256-cbc   (rfc3602)\n"
         "\t\taes128-ctr                         (rfc3686)\n"
         "\t\tnull_enc                           (rfc2410)\n"
         "\n"
         "\tAuthentication (not yet checked):\n"
         "\n"
         "\t\thmac_md5-96                        (rfc2403)\n"
         "\t\thmac_sha1-96                       (rfc2404)\n"
         "\t\taes_xcbc_mac-96                    (rfc3566)\n"
         "\t\tnull_auth                          (rfc2410)\n"
         "\t\tany96 any128 any160 any192 any256 any384 any512\n"
         "\n"
        );
}
/*
 * Friendly printed MAC address
 *
 */
void print_mac(const unsigned char *mac_ptr)
{
  int i;
  for(i=0; i<ETHER_ADDR_LEN; i++)
    i != ETHER_ADDR_LEN ? printf("%02x:",  *(mac_ptr+i)) : printf("%02x",  *(mac_ptr+i));
  printf("\n");
}

void dumpmem(char *prefix, const unsigned char *ptr, int size, int space)
{
  int i;
  printf("%s:: ", prefix);
  for(i=0; i<size; i++)
    space == 0
    ? printf("%02x", *(ptr+i))
    : printf("%02x ", *(ptr+i));
  printf("\n");
}

void *str2dec(const char *in, int maxsize)
{
  int i, len;
  unsigned char c;
  unsigned char *out = NULL;
  MALLOC(out, maxsize, unsigned char);
  len = strlen(in);
  if (len > maxsize*2)
  {
    printf("str too long\n");
    free(out);
    return NULL;
  }
  for(i=0; i<len; i++)
  {
    c = in[i];
    if ((c >= '0') && (c <= '9'))
      c -= '0';
    else if ((c >= 'A') && (c <= 'F'))
      c = c-'A'+10;
    else if ((c >= 'a') && (c <= 'f'))
      c = c-'a'+10;
    else
    {
      printf("non hex digit: %c\n", c);
      free(out);
      return NULL;
    }
    if (i % 2 == 0)
      out[i/2] = (c<<4);
    else
      out[i/2] = out[i/2] | c;
  }
  return out;
}

// Cleanup allocated flow during configuration file parsing (makes valgrind happy)
void flows_cleanup()
{
  llflow_t *f, *tmp;
  f = flow_head;
  while (f != NULL)
  {
    tmp = f;
    f = f->next;
    free(tmp->crypt_name);
    free(tmp->auth_name);
    free(tmp->key);
    free(tmp);
  }
}

/*
 * Add to the linked list flow_head this ESP flow, read from configuration file by parse_esp_conf
 *
 */
int add_flow(char *ip_src, char *ip_dst, char *crypt_name, char *auth_name, char *key, char *spi)
{
  unsigned char *dec_key = NULL;
  unsigned char *dec_spi = NULL;
  llflow_t *flow = NULL;
  llflow_t *ptr = NULL;
  crypt_method_t *cm = NULL;
  auth_method_t *am = NULL;
  char *endptr = NULL;  // for strtol
  MALLOC(flow, 1, llflow_t);
  flow->next = NULL;
  debug_print("\tadd_flow() src:%s dst:%s crypt:%s auth:%s spi:%s\n",
              ip_src, ip_dst, crypt_name, auth_name, spi);
  if ((cm = find_crypt_method(crypt_name)) == NULL)
    err(1, "%s: Cannot find encryption method: %s, please check supported algorithms\n",
        global_args.esp_config_file, crypt_name);
  else
    flow->crypt_method = cm;
  if ((am = find_auth_method(auth_name)) == NULL)
    err(1, "%s: Cannot find authentification method: %s, please check supported algorithms\n",
        global_args.esp_config_file, auth_name);
  else
    flow->auth_method = am;
  // If non NULL encryption, check key
  if (cm->openssl_cipher != NULL)
  {
    // Check for hex format header
    if (key[0] != '0' || (key[1] != 'x' && key[1] != 'X' ) )
    {
      error("%s: Only hex keys are supported and must begin with 0x\n", global_args.esp_config_file);
    }
    else
      key += 2; // shift over 0x
    // Check key length
    if (strlen(key) > MY_MAX_KEY_LENGTH)
    {
      error("%s: Key is too long : %lu > %i -  %s\n",
            global_args.esp_config_file,
            strlen(key),
            MY_MAX_KEY_LENGTH,
            key
           );
    }
    // Convert key to decimal format
    if ((dec_key = str2dec(key, MY_MAX_KEY_LENGTH)) == NULL)
      err(1, "Cannot convert key to decimal format: %s\n", key);
  }
  else
  {
    dec_key = NULL;
  }
  if (spi[0] != '0' || (spi[1] != 'x' && spi[1] != 'X' ) )
  {
    error("%s: Only hex SPIs are supported and must begin with 0x\n", global_args.esp_config_file);
  }
  else
    spi += 2; // shift over 0x
  if ((dec_spi = str2dec(spi, ESP_SPI_LEN)) == NULL)
    err(1, "%s: Cannot convert spi to decimal format\n", global_args.esp_config_file);
  if (inet_pton(AF_INET, ip_src, &(flow->addr_src)) != 1
      || inet_pton(AF_INET, ip_dst, &(flow->addr_dst)) != 1)
  {
    error("%s: Cannot convert ip address\n", global_args.esp_config_file);
  }
  errno = 0;
  flow->spi = strtol(spi, &endptr, 16);
  // Check for conversion errors
  if (errno == ERANGE)
  {
    error("%s: Cannot convert spi (strtol: %s)\n",
          global_args.esp_config_file,
          strerror(errno));
  }
  if (endptr == spi)
  {
    error("%s: Cannot convert spi (strtol: %s)\n",
          global_args.esp_config_file,
          strerror(errno));
  }
  flow->crypt_name = strdup(crypt_name);
  flow->auth_name = strdup(auth_name);
  flow->key = dec_key;
  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);
  flow->ctx = ctx;
  // Adding to linked list
  if (flow_head == NULL)
  {
    flow_head = flow;
    flow_head->next = NULL;
  }
  else
  {
    ptr = flow_head;
    while(ptr->next != NULL)
      ptr = ptr->next;
    ptr->next = flow;
  }
  free(dec_spi);
  return 0;
}

/*
 * Parse the ipdecap ESP configuration file
 *
 */
int parse_esp_conf(char *filename)
{
  const char delimiters[] = " \t";
  char buffer[CONF_BUFFER_SIZE];
  char *copy = NULL;
  char *src = NULL;
  char *dst = NULL;
  char *crypt = NULL;
  char *auth = NULL;
  char *spi = NULL;
  char *key = NULL;
  int line = 0;
  FILE *conf;
  conf = fopen(filename, "r");
  if (conf == NULL )
    return -1;
  while (fgets(buffer, CONF_BUFFER_SIZE, conf) != NULL)
  {
    line++;
    copy = strdup(buffer);
    // Empty line
    if (strlen(copy) == 1)
      continue;
    // Commented line
    if (copy[0] == '#')
      continue;
    // Remove new line character
    copy[strcspn(copy, "\n")] = '\0';
    if ((src = strtok(copy, delimiters)) == NULL)
      error("Cannot parse line %i in %s, missing column ?\n\t--> %s\n", line, filename, buffer);
    if ((dst = strtok(NULL, delimiters)) == NULL)
      error("Cannot parse line %i in %s, missing column ?\n\t--> %s\n", line, filename, buffer);
    if ((crypt = strtok(NULL, delimiters)) == NULL)
      error("Cannot parse line %i in %s, missing column ?\n\t--> %s\n", line, filename, buffer);
    if ((auth = strtok(NULL, delimiters)) == NULL)
      error("Cannot parse line %i in %s, missing column ?\n\t--> %s\n", line, filename, buffer);
    if ((key = strtok(NULL, delimiters)) == NULL)
      error("Cannot parse line %i in %s, missing column ?\n\t--> %s\n", line, filename, buffer);
    if ((spi = strtok(NULL, delimiters)) == NULL)
      error("Cannot parse line %i in %s, missing column ?\n\t--> %s\n", line, filename, buffer);
    debug_print("parse_esp_conf() src:%s dst:%s crypt:%s auth:%s key:%s spi:%s\n",
                src, dst, crypt, auth, key, spi);
    add_flow(src, dst, crypt, auth, key, spi);
    free(copy);
  }
  fclose(conf);
  return 0;
}

/*
 * Find the corresponding crypt_method_t from its name
 *
 */
struct crypt_method_t * find_crypt_method(char *crypt_name)
{

  int rc;
  struct crypt_method_t *cm = NULL;

  cm = crypt_method_list;

  while(cm != NULL)
  {
    rc = strcmp(crypt_name, cm->name);
    if (rc == 0)
    {
      return cm;
    }
    cm = cm->next;
  }
  return NULL;
}

/*
 * Find the corresponding auth_method_t from its name
 *
 */
struct auth_method_t * find_auth_method(char *auth_name)
{

  int rc;
  struct auth_method_t *am = NULL;

  am = auth_method_list;

  while(am != NULL)
  {
    rc = strcmp(auth_name, am->name);
    if (rc == 0)
    {
      return am;
    }
    am = am->next;
  }
  return NULL;
}

/*
 * Try to find an ESP configuration to decrypt the flow between ip_src and ip_dst
 *
 */
struct llflow_t * find_flow(char *ip_src, char *ip_dst, u_int32_t spi)
{

  const char *rc;
  struct llflow_t *f = NULL;
  char src_txt[INET_ADDRSTRLEN];
  char dst_txt[INET_ADDRSTRLEN];

  debug_print("find_flow() need:: ip_src:%s ip_dst:%s spi:%02x\n", ip_src, ip_dst, spi);

  f = flow_head;

  while(f != NULL)
  {
    rc = inet_ntop(AF_INET, &(f->addr_src), src_txt, INET_ADDRSTRLEN);
    if (rc == NULL)
      error("Cannot convert source IP adddress - inet_ntop() err");
    inet_ntop(AF_INET, &(f->addr_dst), dst_txt, INET_ADDRSTRLEN);
    if (rc == NULL)
      error("inet_ntop() err");
    if (strcmp(ip_src, src_txt) == 0)
    {
      if (strcmp(ip_dst, dst_txt) == 0)
      {
        if (f->spi == ntohl(spi))
        {
          debug_print("find_flow() found match:: src:%s dst:%s spi:%x\n", src_txt, dst_txt, ntohl(f->spi));
          return f;
        }
      }
    }
    f = f->next;
  }
  return NULL;
}

/*
 * Print known ESP flows, read from the ESP confguration file
 *
 */
void dump_flows()
{
  char src[INET_ADDRSTRLEN];
  char dst[INET_ADDRSTRLEN];
  struct llflow_t *e = NULL;
  e = flow_head;
  while(e != NULL)
  {
    if (inet_ntop(AF_INET, &(e->addr_src), src, INET_ADDRSTRLEN) == NULL
        || inet_ntop(AF_INET, &(e->addr_dst), dst, INET_ADDRSTRLEN) == NULL)
    {
      free(e);
      error("Cannot convert ip");
    }
    printf("dump_flows: src:%s dst:%s crypt:%s auth:%s spi:%lx\n",
           src, dst, e->crypt_name, e->auth_name, (long unsigned int) e->spi);
    dumpmem("key", e->key, EVP_CIPHER_CTX_key_length(&e->ctx), 0);
    printf("\n");
    e = e->next;
  }
}

/*
 * Remove IEEE 802.1Q header (virtual lan)
 *
 */
void remove_ieee8021q_header(const u_char *in_payload, const int in_payload_len, pcap_hdr *out_pkthdr, u_char *out_payload)
{
  u_char *payload_dst = NULL;
  u_char *payload_src = NULL;
  // Pointer used to shift through source packet bytes
  payload_src = (u_char *) in_payload;
  payload_dst = out_payload;
  // Copy ethernet src and dst
  memcpy(payload_dst, payload_src, 2*sizeof(struct ether_addr));
  payload_src += 2*sizeof(struct ether_addr);
  payload_dst += 2*sizeof(struct ether_addr);
  // Skip ieee 802.1q bytes
  payload_src += VLAN_TAG_LEN;
  memcpy(payload_dst, payload_src, in_payload_len
         - 2*sizeof(struct ether_addr)
         - VLAN_TAG_LEN);
  // Should I check for minimum frame size, even if most drivers don't supply FCS (4 bytes) ?
  out_pkthdr->len = in_payload_len - VLAN_TAG_LEN;
  out_pkthdr->caplen = in_payload_len - VLAN_TAG_LEN;
}

/*
 * Simply copy non-IP packet
 *
 */
void process_nonip_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload)
{
  // Copy full packet
  memcpy(new_packet_payload, payload, payload_len);
  new_packet_hdr->len = payload_len;
}

/* Decapsulate an IPIP packet
 *
 */
void process_ipip_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload)
{
  int packet_size = 0;
  const u_char *payload_src = NULL;
  u_char *payload_dst = NULL;
  const struct ip *ip_hdr = NULL;
  payload_src = payload;
  payload_dst = new_packet_payload;
  // Copy ethernet header
  memcpy(payload_dst, payload_src, sizeof(struct ether_header));
  payload_src += sizeof(struct ether_header);
  payload_dst += sizeof(struct ether_header);
  packet_size = sizeof(struct ether_header);
  // Read encapsulating IP header to find offset to encapsulted IP packet
  ip_hdr = (const struct ip *) payload_src;
  debug_print("\tIPIP: outer IP - hlen:%i iplen:%02i protocol:%02x\n",
              (ip_hdr->ip_hl *4), ntohs(ip_hdr->ip_len), ip_hdr->ip_p);
  // Shift to encapsulated IP header, read total length
  payload_src += ip_hdr->ip_hl *4;
  ip_hdr = (const struct ip *) payload_src;
  debug_print("\tIPIP: inner IP - hlen:%i iplen:%02i protocol:%02x\n",
              (ip_hdr->ip_hl *4), ntohs(ip_hdr->ip_len), ip_hdr->ip_p);
  memcpy(payload_dst, payload_src, ntohs(ip_hdr->ip_len));
  packet_size += ntohs(ip_hdr->ip_len);
  new_packet_hdr->len = packet_size;
}

/* Decapsulate an IPv6 packet
 *
 */
void process_ipv6_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload)
{
  int packet_size = 0;
  const u_char *payload_src = NULL;
  u_char *payload_dst = NULL;
  const struct ip *ip_hdr = NULL;
  uint16_t ethertype;
  payload_src = payload;
  payload_dst = new_packet_payload;
  // Copy src and dst ether addr
  memcpy(payload_dst, payload_src, 2*sizeof(struct ether_addr));
  payload_src += 2*sizeof(struct ether_addr);
  payload_dst += 2*sizeof(struct ether_addr);
  // Set ethernet type to IPv6
  ethertype = htons(ETHERTYPE_IPV6);
  memcpy(payload_dst, &ethertype, member_size(struct ether_header, ether_type));
  payload_src += member_size(struct ether_header, ether_type);
  payload_dst += member_size(struct ether_header, ether_type);
  // Read encapsulating IPv4 header to find header lenght and offset to encapsulated IPv6 packet
  ip_hdr = (const struct ip *) payload_src;
  packet_size = payload_len - (ip_hdr->ip_hl *4);
  debug_print("\tIPv6: outer IP - hlen:%i iplen:%02i protocol:%02x\n",
              (ip_hdr->ip_hl *4), ntohs(ip_hdr->ip_len), ip_hdr->ip_p);
  // Shift to encapsulated IPv6 packet, then copy
  payload_src += ip_hdr->ip_hl *4;
  memcpy(payload_dst, payload_src, packet_size);
  new_packet_hdr->len = packet_size;
}

/*
 * Decapsulate a GRE packet
 *
 */
void process_gre_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload)
{
  QDebug_string("go into process_gre_packet");
  //TODO: check si version == 0 1 non support car pptp)
  int packet_size = 0;
  u_int16_t flags;
  const u_char *payload_src = NULL;
  u_char *payload_dst = NULL;
  const struct ip *ip_hdr = NULL;
  const struct grehdr *gre_hdr = NULL;
  payload_src = payload ;
  payload_dst = new_packet_payload;
  // Copy ethernet header
  memcpy(payload_dst, payload_src, sizeof(struct ether_header));
  payload_src += sizeof(struct ether_header) ;
  payload_dst += sizeof(struct ether_header) ;
  packet_size = sizeof(struct ether_header) ;
  // Read encapsulating IP header to find offset to GRE header
  ip_hdr = (const struct ip *) payload_src;
  packet_size += ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl*4;
  payload_src += (ip_hdr->ip_hl *4);
  debug_print("\tGRE: outer IP - hlen:%i iplen:%02i protocol:%02x\n",
              (ip_hdr->ip_hl *4), ntohs(ip_hdr->ip_len), ip_hdr->ip_p);
  // Skip ip - fragment packet framer:26
  // Read GRE header to find offset to encapsulated IP packet
  gre_hdr = (const struct grehdr *) payload_src;
  debug_print("\tGRE - GRE header: flags:%u protocol:%x\n", gre_hdr->flags, ntohs(gre_hdr->next_protocol));
  packet_size -= sizeof(struct grehdr) ;
  payload_src += sizeof(struct grehdr) ;
  flags = ntohs(gre_hdr->flags);
  if (flags & GRE_CHECKSUM || flags & GRE_ROUTING)
  {
    payload_src += 4; // Both checksum and offset fields are present
    packet_size -= 4;
  }
  if (flags & GRE_KEY)
  {
    payload_src += 4;
    packet_size -= 4;
  }
  if (flags & GRE_SEQ)
  {
    payload_src += 4;
    packet_size -= 4;
  }
  PPP_RET ppp_log;
  int ret ;
  int ppp_size = packet_size - sizeof(struct ether_header) ;
  ret = gre_ppp_parser( payload_src, ppp_size, &ppp_log);
  int ppp_num = ppp_log.ppp_num;
  u_char *tmp_payload_fragment = NULL;
  u_char *new_ppp_fragment_payload = NULL;
  tmp_payload_fragment = malloc (65536);
  if (NULL == tmp_payload_fragment)
  {
    QDebug_string("[gre_process_fragment_start]malloc tmp_payload_fragment zone failed");
    return ;
  }
  int tmp_fragment_size;
  struct pcap_pkthdr out_pkthdr;
  while(ppp_log.ppp_num)
  {
    payload_dst = new_packet_payload + sizeof(struct ether_header);
    
    memset(tmp_payload_fragment, 0x00, 65536 );
    tmp_fragment_size = ppp_log.ppp_pos[ppp_log.ppp_num].end - ppp_log.ppp_pos[ppp_log.ppp_num].start + 1;
    memcpy(tmp_payload_fragment, payload_src + ppp_log.ppp_pos[ppp_log.ppp_num].start, tmp_fragment_size);
    new_ppp_fragment_payload= gre_remove_PPP_header( tmp_payload_fragment, &tmp_fragment_size);
    gre_remove_PPP_tail( new_ppp_fragment_payload, &tmp_fragment_size);
    format_ppp_packet( new_ppp_fragment_payload, &tmp_fragment_size);
    memcpy(payload_dst, tmp_payload_fragment,tmp_fragment_size );
    out_pkthdr.ts.tv_sec = packet_num;
    out_pkthdr.ts.tv_usec = ppp_num - ppp_log.ppp_num;
    out_pkthdr.caplen = tmp_fragment_size + sizeof(struct ether_header);
    pcap_dump((u_char *)pcap_dumper, &out_pkthdr, new_packet_payload);
    ppp_log.ppp_num --;
  }
END:
  memcpy(payload_dst, payload_src , packet_size);
  new_packet_hdr->len = packet_size;
  free(tmp_payload_fragment);
}

/*
 * Decapsulate an ESP packet:
 * -try to find an ESP configuration entry (ip, spi, algorithms)
 * -decrypt packet with the configuration found
 *
 */
void process_esp_packet(u_char const *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload)
{
  const u_char *payload_src = NULL;
  u_char *payload_dst = NULL;
  const struct ip *ip_hdr = NULL;
  esp_packet_t esp_packet;
  char ip_src[INET_ADDRSTRLEN+1];
  char ip_dst[INET_ADDRSTRLEN+1];
  llflow_t *flow = NULL;
  EVP_CIPHER_CTX ctx;
  const EVP_CIPHER *cipher = NULL;
  int packet_size, rc, len, remaining;
  int ivlen;
  // TODO: memset sur new_packet_payload
  payload_src = payload;
  payload_dst = new_packet_payload;
  // Copy ethernet header
  memcpy(payload_dst, payload_src, sizeof(struct ether_header));
  payload_src += sizeof(struct ether_header);
  payload_dst += sizeof(struct ether_header);
  packet_size = sizeof(struct ether_header);
  // Read encapsulating IP header to find offset to ESP header
  ip_hdr = (const struct ip *) payload_src;
  payload_src += (ip_hdr->ip_hl *4);
  // Read ESP fields
  memcpy(&esp_packet.spi, payload_src, member_size(esp_packet_t, spi));
  payload_src += member_size(esp_packet_t, spi);
  memcpy(&esp_packet.seq, payload_src, member_size(esp_packet_t, seq));
  payload_src += member_size(esp_packet_t, seq);
  // Extract dst/src IP
  inet_ntop(AF_INET, &(ip_hdr->ip_src), ip_src, INET_ADDRSTRLEN);
  if (ip_src == NULL)
    error("Cannot convert source ip address for ESP packet\n");
  inet_ntop(AF_INET, &(ip_hdr->ip_dst), ip_dst, INET_ADDRSTRLEN);
  if (ip_dst == NULL)
    error("Cannot convert destination ip address for ESP packet\n");
  // Find encryption configuration used
  flow = find_flow(ip_src, ip_dst, esp_packet.spi);
  if (flow == NULL)
  {
    verbose("No suitable flow configuration found for src:%s dst:%s spi: %lx copying raw packet\n",
            ip_src, ip_dst, esp_packet.spi);
    process_nonip_packet(payload, payload_len, new_packet_hdr, new_packet_payload);
    return;
  }
  else
  {
    debug_print("Found flow configuration src:%s dst:%s crypt:%s auth:%s spi: %lx\n",
                ip_src, ip_dst, flow->crypt_name, flow->auth_name, (long unsigned) flow->spi);
  }
  // Differences between (null) encryption algorithms and others algorithms start here
  if (flow->crypt_method->openssl_cipher == NULL)
  {
    remaining = ntohs(ip_hdr->ip_len)
                - ip_hdr->ip_hl*4
                - member_size(esp_packet_t, spi)
                - member_size(esp_packet_t, seq);
    // If non null authentication, discard authentication data
    if (flow->auth_method->openssl_auth == NULL)
    {
      remaining -= flow->auth_method->len;
    }
    u_char *pad_len = ((u_char *)payload_src + remaining -2);
    remaining = remaining
                - member_size(esp_packet_t, pad_len)
                - member_size(esp_packet_t, next_header)
                - *pad_len;
    packet_size += remaining;
    memcpy(payload_dst, payload_src, remaining);
    new_packet_hdr->len = packet_size;
  }
  else
  {
    if ((cipher = EVP_get_cipherbyname(flow->crypt_method->openssl_cipher)) == NULL)
      error("Cannot find cipher %s - EVP_get_cipherbyname() err", flow->crypt_method->openssl_cipher);
    EVP_CIPHER_CTX_init(&ctx);
    // Copy initialization vector
    ivlen = EVP_CIPHER_iv_length(cipher);
    memset(&esp_packet.iv, 0, EVP_MAX_IV_LENGTH);
    memcpy(&esp_packet.iv, payload_src, ivlen);
    payload_src += ivlen;
    rc = EVP_DecryptInit_ex(&ctx, cipher,NULL, flow->key, esp_packet.iv);
    if (rc != 1)
    {
      error("Error during the initialization of crypto system. Please report this bug with your .pcap file");
    }
    // ESP payload length to decrypt
    remaining =  ntohs(ip_hdr->ip_len)
                 - ip_hdr->ip_hl*4
                 - member_size(esp_packet_t, spi)
                 - member_size(esp_packet_t, seq)
                 - ivlen;
    // If non null authentication, discard authentication data
    if (flow->auth_method->openssl_auth == NULL)
    {
      remaining -= flow->auth_method->len;
    }
    // Do the decryption work
    rc = EVP_DecryptUpdate(&ctx, payload_dst, &len, payload_src, remaining);
    packet_size += len;
    if (rc != 1)
    {
      verbose("Warning: cannot decrypt packet with EVP_DecryptUpdate(). Corrupted ? Cipher is %s, copying raw packet...\n",
              flow->crypt_method->openssl_cipher);
      process_nonip_packet(payload, payload_len, new_packet_hdr, new_packet_payload);
      return;
    }
    EVP_DecryptFinal_ex(&ctx, payload_dst+len, &len);
    packet_size += len;
    // http://www.mail-archive.com/openssl-users@openssl.org/msg23434.html
    packet_size +=EVP_CIPHER_CTX_block_size(&ctx);
    u_char *pad_len = (new_packet_payload + packet_size -2);
    // Detect obviously badly decrypted packet
    if (*pad_len >=  EVP_CIPHER_CTX_block_size(&ctx))
    {
      verbose("Warning: invalid pad_len field, wrong encryption key ? copying raw packet...\n");
      process_nonip_packet(payload, payload_len, new_packet_hdr, new_packet_payload);
      return;
    }
    // Remove next protocol, pad len fields and padding
    packet_size = packet_size
                  - member_size(esp_packet_t, pad_len)
                  - member_size(esp_packet_t, next_header)
                  - *pad_len;
    new_packet_hdr->len = packet_size;
    EVP_CIPHER_CTX_cleanup(&ctx);
  } /*  flow->crypt_method->openssl_cipher == NULL */
}




/*
 * For each packet, identify its encapsulation protocol and give it to the corresponding process_xx_packet function
 *
 */
void handle_packets(u_char *bpf_filter, const struct pcap_pkthdr *pkthdr, const u_char *bytes)
{
  const struct ether_header *eth_hdr = NULL;
  const struct ip *ip_hdr = NULL;
  struct bpf_program *bpf = NULL;
  struct pcap_pkthdr *in_pkthdr = NULL;
  struct pcap_pkthdr *out_pkthdr = NULL;
  u_char *in_payload = NULL;
  u_char *out_payload = NULL;
  verbose("Processing packet %i\n", packet_num);
  // Check if packet match bpf filter, if given
  if (bpf_filter != NULL)
  {
    bpf = (struct bpf_program *) bpf_filter;
    if (pcap_offline_filter(bpf, pkthdr, bytes)  == 0)
    {
      verbose("Packet %i does not match bpf filter\n", packet_num);
      goto exit;
    }
  }
  MALLOC(out_pkthdr, 1, struct pcap_pkthdr);
  MALLOC(out_payload, 65535, u_char);
  memset(out_pkthdr, 0, sizeof(struct pcap_pkthdr));
  memset(out_payload, 0, 65535);
  // Pointer used to shift through source packet bytes
  // updated when vlan header is removed
  in_pkthdr = (struct pcap_pkthdr *) pkthdr;
  in_payload = (u_char *) bytes;
  // Copy source pcap metadata
  out_pkthdr->ts.tv_sec = in_pkthdr->ts.tv_sec;
  out_pkthdr->ts.tv_usec = in_pkthdr->ts.tv_usec;
  out_pkthdr->caplen = in_pkthdr->caplen;
  eth_hdr = (const struct ether_header *) in_payload;
  // If IEEE 802.1Q header, remove it before further processing
  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_VLAN)
  {
    debug_print("%s\n", "\tIEEE 801.1Q header\n");
    remove_ieee8021q_header(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
    // Update source packet with the new one without 802.1q header
    memcpy(in_payload, out_payload, out_pkthdr->caplen);
    in_pkthdr->caplen = out_pkthdr->caplen;
    in_pkthdr->len = out_pkthdr->len;
    // Re-read new ethernet type
    eth_hdr = (const struct ether_header *) in_payload;
  }
  // ethertype = *(pkt_in_ptr + 12) << 8 | *(pkt_in_ptr+13);
  if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
  {
    // Non IP packet ? Just copy
    process_nonip_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
    pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
  }
  else //IP Protocol
  {
    // Find encapsulation type
    ip_hdr = (const struct ip *) (in_payload + sizeof(struct ether_header));
    struct ip outer_ip_hdr = *ip_hdr;
    //is_ip_fragment
    if (Is_IP_Fragment(outer_ip_hdr))
    {
      //Is gre packet
      if (outer_ip_hdr.ip_p == IPPROTO_GRE)
      {
        int packet_type =  Get_IP_Fragment_statue(outer_ip_hdr);
        switch (packet_type)
        {
        case IP_FLAG_MF_START:
          //cal hashid;  add outer_ip ip.flag ip.offset ; inter_ip ip.src ip.dst
          //remove outer_ip segment and gre_headr , modify ip.fragment ip.offset ip.id ; cal ip.crc;
          gre_process_fragment_start( in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
          goto END;
        case IP_FLAG_MF_MID:
        case IP_FLAG_MF_END:
          //cal hashid; find same_hashid into list
          //modify inter_ip segment, ip.offset; re-cal ip.crc;
          gre_process_fragment_other( in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
          goto END;
        }
      }
      else
      {
        goto NOFRAGMENT;
      }
    }
    else
    {
      goto NOFRAGMENT;
    }
NOFRAGMENT:
    switch (ip_hdr->ip_p)
    {
    case IPPROTO_IPIP:
      debug_print("%s\n", "\tIPPROTO_IPIP");
      process_ipip_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
      out_pkthdr->ts.tv_sec = packet_num;
      pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
      break;
    case IPPROTO_IPV6:
      debug_print("%s\n", "\tIPPROTO_IPV6");
      process_ipv6_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
      out_pkthdr->ts.tv_sec = packet_num;
      pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
      break;
    case IPPROTO_GRE:
      debug_print("%s\n", "\tIPPROTO_GRE\n");
      process_gre_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
      out_pkthdr->ts.tv_sec = packet_num;
      pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
      break;
    case IPPROTO_ESP:
      debug_print("%s\n", "\tIPPROTO_ESP\n");
      if (ignore_esp == 1)
      {
        verbose("Ignoring ESP packet %i\n", packet_num);
        free(out_pkthdr);
        free(out_payload);
        return;
      }
      process_esp_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
      out_pkthdr->ts.tv_sec = packet_num;
      pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
      break;
    default:
      // Copy not encapsulated/unknown encpsulation protocol packets, like non_ip packets
      process_nonip_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
      out_pkthdr->ts.tv_sec = packet_num;
      pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
      verbose("Copying packet %i: not encapsulated/unknown encapsulation protocol\n", packet_num);
    } // if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
  }
END:
  free(out_pkthdr);
  free(out_payload);
exit: // Avoid several 'return' in middle of code
  packet_num++;
  QDebug_strval1("packet_num", packet_num);
}


int main(int argc, char **argv)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_reader = NULL;
  pcap_dumper = NULL;
  pcap_t *p = NULL;
  struct bpf_program *bpf = NULL;
  ignore_esp = 0;
  int rc;
  parse_options(argc, argv);
  if (global_args.list_algo == true)
  {
    print_algorithms();
    exit(0);
  }
  verbose("Input file :\t%s\nOutput file:\t%s\nConfig file:\t%s\nBpf filter:\t%s\n",
          global_args.input_file,
          global_args.output_file,
          global_args.esp_config_file,
          global_args.bpf_filter);
  if (global_args.input_file == NULL || global_args.output_file == NULL)
  {
    usage();
    error("Input and outfile file parameters are mandatory\n");
  }
  pcap_reader = pcap_open_offline(global_args.input_file, errbuf);
  if (pcap_reader == NULL)
    error("Cannot open input file %s: %s", global_args.input_file, errbuf);
  debug_print("snaplen:%i\n", pcap_snapshot(pcap_reader));
  p = pcap_open_dead(DLT_EN10MB, MAXIMUM_SNAPLEN);
  // try to compile bpf filter for input packets
  if (global_args.bpf_filter != NULL)
  {
    MALLOC(bpf, 1, struct bpf_program);
    verbose("Using bpf filter:%s\n", global_args.bpf_filter);
    if (pcap_compile(p, bpf, global_args.bpf_filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
      error("pcap_compile() %s\n", pcap_geterr(p));
    }
  }
  pcap_dumper = pcap_dump_open(p, global_args.output_file);
  if (pcap_dumper == NULL)
    error("Cannot open output file %s : %s\n", global_args.output_file, errbuf);
  // Try to read ESP configuration file
  if (global_args.esp_config_file != NULL)
  {
    rc = parse_esp_conf(global_args.esp_config_file);
    switch(rc)
    {
    case -1:
      warnx("ESP config file: cannot open %s - ignoring ESP packets\n",
            global_args.esp_config_file);
      ignore_esp = 1;
      break;
    case -2:
      warnx("ESP config file: %s is not parsable (missing column ?) - ignoring ESP packets\n",
            global_args.esp_config_file);
      ignore_esp = 1;
      break;
    case 0: // Processing of ESP configuraton file is OK
      break;
    }
  }
#ifdef DEBUG
  dump_flows();
#endif
  OpenSSL_add_all_algorithms();
  //Init hashlist
  list = malloc (sizeof(Node));
  INIT_LIST_HEAD(&(list->pos));
  // Dispatch to handle_packet function each packet read from the pcap file
  pcap_dispatch(pcap_reader, 0, handle_packets, (u_char *) bpf);
  pcap_close(pcap_reader);
  pcap_close(p);
  pcap_dump_close(pcap_dumper);
  EVP_cleanup();
  flows_cleanup();
  return 0;
}

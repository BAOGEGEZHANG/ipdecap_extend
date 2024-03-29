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


#define GRE_PPP_ZIP         0X00
#define GRE_PPP_NO_ZIP      0X01
#define GRE_PPP_FRAGMENT    0X02
#define GRE_PPP_SLIP        0X03
#define GRE_PPP_NCP         0X04
#define GRE_PPP_NO_IP       0X05
#define GRE_PPP_INVAILD     0X05

#define GRE_PPP_MIN_SIZE        0X02
#define GRE_PPP_ZIP_HEADERSIZE  0X02
#define GRE_PPP_NO_ZIP_HEADERSIZE 0X05
#define GRE_PPP_PACKET_MAXNUM_PPP  64

#define PPP_PKT_OK        0X00
#define PPP_PKT_START_OK  0X01
#define PPP_PKT_END_OK    0X02
#define PPP_PKT_BRK       0X03
#define PPP_PKT_NUM       0x03

#define IP_MIN_HEADER       20
#define AGE_TIME_INIT       100
#define DGB_FORMAT_LINE_LEN     16
#define TMP_BUF_PAYLOAD_SIZE    65536

#define GetBit(dat,i) ((dat&(0x0001<<i))?1:0)
#define SetBit(dat,i) ((dat)|=(0x0001<<(i)))
#define ClearBit(dat,i) ((dat)&=(~(0x0001<<(i))))



typedef struct _Node      LIST_NODE;
typedef struct _ip_node   IP_NODE;
typedef struct _gre_node  GRE_NODE;

typedef struct _Point       Point;
typedef struct _PPP_RET     PPP_RET;
typedef struct _IP_INFO     IP_INFO;
typedef struct _Statistic_Log Statistic_LOG;



struct _gre_node
{
  uint8_t enable;
  uint32_t key;
  uint32_t seqnum;
};

struct _ip_node
{
  uint8_t enable;
  uint8_t fragment;
  uint8_t p;
  uint8_t tos;
  uint16_t outer_id;
  uint16_t inter_id;
  uint32_t src;
  uint32_t dst;
  uint16_t nextoff, curoff;
  uint8_t *buffer;
  uint32_t buffer_length;
};

struct _Node
{
  struct list_head pos;
  int age_time;
  uint32_t hash_id;
  GRE_NODE gre_node;
  IP_NODE ip_node;
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

struct _IP_INFO
{
  uint8_t   hl;
  uint8_t   version;
  uint8_t   tos;
  uint16_t  total_len;
  uint16_t  id;
  uint16_t  offset;
  uint8_t   df:1;
  uint8_t   mf:1;
  uint8_t   ttl;
  uint8_t   protocol;
  uint16_t  checksum;
  uint32_t  ip_src, ip_dst;
};

struct _Statistic_Log
{
  uint64_t not_gre_pacekt_cnt;
  uint64_t gre_df_packet_cnt ;
  uint64_t gre_mf_packet_cnt ;
  uint64_t gre_mf_last_packet_cnt;
  uint64_t gre_mf_tony_last_packet_cnt;
  uint64_t ip_find_cnt;
  uint64_t ip_not_find_cnt;
  uint64_t gre_find_cnt;
  uint64_t gre_not_find_cnt;
  uint64_t gre_ppp_invalid_pro;
  uint64_t drop_gre_cnt;
  uint64_t drop_ip_cnt;
  uint64_t dump_cnt;
  uint64_t reserv_cnt;
};

LIST_NODE *list_header;
Statistic_LOG statistic_log;
uint64_t packet_num = 1;

//Debug Function
void Print_Debug(unsigned char*pos, int len)
{
#ifndef _QDEBUG
  return ;
#endif
  if (NULL == pos)
  {
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

void Print_Statistic_cnt()
{
  printf ("==========================================================\n");
  printf ("statistic_log.not_gre_pacekt_cnt:%lu\n",statistic_log.not_gre_pacekt_cnt);
  printf ("statistic_log.gre_df_packet_cnt:%lu\n",statistic_log.gre_df_packet_cnt);
  printf ("statistic_log.gre_mf_packet_cnt:%lu\n",statistic_log.gre_mf_packet_cnt);
  printf ("statistic_log.gre_mf_tony_last_packet_cnt:%lu\n",statistic_log.gre_mf_tony_last_packet_cnt);
  printf ("statistic_log.gre_mf_last_packet_cnt:%lu\n",statistic_log.gre_mf_last_packet_cnt);
  printf ("statistic_log.ip_not_find_cnt:%lu\n", statistic_log.ip_not_find_cnt);
  printf ("statistic_log.ip_find_cnt:%lu\n", statistic_log.ip_find_cnt);
  printf ("statistic_log.gre_find_cnt:%lu\n",statistic_log.gre_find_cnt);
  printf ("statistic_log.gre_not_find_cnt:%lu\n", statistic_log.gre_not_find_cnt);
  printf ("statistic_log.gre_ppp_invalid_pro:%lu\n",statistic_log.gre_ppp_invalid_pro);
  printf ("statistic_log.dump_cnt:%lu\n",statistic_log.dump_cnt + statistic_log.not_gre_pacekt_cnt);
  printf ("statistic_log.drop_gre_cnt:%lu\n",statistic_log.drop_gre_cnt);
  printf ("statistic_log.drop_ip_cnt:%lu\n", statistic_log.drop_ip_cnt);
  printf ("statistic_log.reserv_cnt:%lu\n", statistic_log.reserv_cnt);
}

int ip_get_df(const struct ip *ip_hdr)
{
  if (ntohs(ip_hdr->ip_off) & IP_DF)
    return 1;
  return 0;
}


int ip_get_mf (const struct ip*ip_hdr)
{
  if (ntohs(ip_hdr->ip_off) & IP_MF)
    return 1;
  return 0;
}

uint32_t ip_cal_hashid(uint32_t ip_src, uint32_t ip_dst, uint16_t id)
{
  return ((ip_src * ip_dst)*(ip_src * ip_dst));
}

uint16_t ip_checksum(uint16_t *ip_payload, int ip_payload_length)
{
  if ((NULL == ip_payload) || (ip_payload_length < IP_MIN_HEADER))
  {
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


uint16_t ip_off_info(struct ip *ip_hdr)
{
  return (IP_OFFMASK & ntohs(ip_hdr->ip_off));
}

int ip_all_info(const struct ip* ip_hdr, IP_INFO *ip_info)
{
  if ((NULL == ip_hdr) || (NULL == ip_info))
  {
    QDebug_Error("ip_all_info is failed;parameter is invalid;");
    return -1;
  }
  memset(ip_info, 0x00, sizeof(IP_INFO));
  
  ip_info->tos = ip_hdr->ip_tos;
  ip_info->ttl = ip_hdr->ip_ttl;
  ip_info->hl = ip_hdr->ip_hl * 4;
  ip_info->version = ip_hdr->ip_v;
  ip_info->id = ntohs(ip_hdr->ip_id);
  ip_info->checksum = ntohs(ip_hdr->ip_sum);
  ip_info->total_len = ntohs(ip_hdr->ip_len);
  ip_info->ip_src  = ntohl(ip_hdr->ip_src.s_addr);
  ip_info->ip_dst  = ntohl(ip_hdr->ip_dst.s_addr);
  ip_info->df = (ntohs(ip_hdr->ip_off) & IP_DF)?1:0;
  ip_info->mf = (ntohs(ip_hdr->ip_off) & IP_MF)?1:0;
  ip_info->offset = (ntohs(ip_hdr->ip_off) & IP_OFFMASK) * 8;
  return 0;
}


int Set_IP_FLAG_DF (struct ip *ip_hdr, uint8_t flag)
{
  if ((NULL == ip_hdr) || (flag > 1)){
    QDebug_Error("Set_IP_Flag_df is failed,the parameter is invalid");
    return -1;
  }
  if (flag == 1)
    ip_hdr->ip_off = htons(ntohs(ip_hdr->ip_off) | IP_DF);
  else
    ip_hdr->ip_off = htons(ntohs(ip_hdr->ip_off) & (~IP_DF));
  return 0;
}

int Set_IP_FLAG_MF (struct ip *ip_hdr, uint8_t flag)
{
  if ((NULL == ip_hdr) || (flag > 1)){
    QDebug_Error("Set_IP_Flag_MF is failed, parameter is invalid");
    return -1;
  }
  if (flag == 1)
    ip_hdr->ip_off = htons(ntohs(ip_hdr->ip_off) | IP_MF);
  else
    ip_hdr->ip_off = htons(ntohs(ip_hdr->ip_off) & (~IP_MF));
  return 0;
}


int Set_IP_FLAG_Offset (struct ip *ip_hdr, uint16_t offset)
{
  if ((NULL == ip_hdr)){
    QDebug_Error("Set_IP_flag_Offset is failed, parameter is invalid");
    return -1;
  }
  ip_hdr->ip_off = htons((ntohs(ip_hdr->ip_off) & (~IP_OFFMASK)) | offset );
  return 0;
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
int ppp_list_add(LIST_NODE *list, LIST_NODE *node)
{
  QDebug_string("[list_ip_add node into list]");
  LIST_NODE *cur = (LIST_NODE *)malloc(sizeof(LIST_NODE));
  if (NULL == cur)
  {
    QDebug_string("[Add_List]malloc node space failed");
    return 1;
  }
  list_add (&(cur->pos), &(list->pos));
  cur->hash_id = node->hash_id;
  cur->age_time = AGE_TIME_INIT;
  cur->gre_node = node->gre_node;
  cur->ip_node = node->ip_node;
  return 0;
}
/*
* name: Destory_Node
* parameter :
  pos : node of list wated to delete
* ret : success 0; failed 1;
* description: delete node
*/
int ppp_list_del(LIST_NODE *pos)
{
  QDebug_string("[Delete Node]");
  list_del((struct list_head *)pos);
  free(pos->ip_node.buffer);
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
LIST_NODE * ppp_list_find(LIST_NODE *list, uint32_t hash_id)
{
  struct list_head *pos, *n;
  list_for_each_safe(pos, n, &(list->pos))
  {
    if (((LIST_NODE *)pos)->hash_id == hash_id)
    {
      statistic_log.ip_find_cnt++;
      //  statistic_log.gre_ppp_invalid_pro = packet_num;
      QDebug_Error("find same hash_id in ip list");
      return (LIST_NODE*)pos;
    }
    if ( 0 >= ((LIST_NODE *)pos)->age_time --)
    {
      statistic_log.drop_ip_cnt++;
      ppp_list_del((LIST_NODE *)pos);
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
int gre_get_items(struct grehdr *gre_hdr, GRE_NODE *result)
{
  if ((NULL == gre_hdr) || (NULL == result))
  {
    QDebug_Errorval2("gre_get_items is failed, parameter is invalid, gre_hdr, result;", gre_hdr, result);
    return -1;
  }
  int length = 0;
  uint16_t flag = ntohs(gre_hdr->flags);;
  u_char *pos = (u_char *)gre_hdr;
  if (flag & GRE_RESER){
    QDebug_Error("gre header is not valied");
    return length;
  }
  if ((ntohs(gre_hdr->next_protocol)) == 0x8881)
  {
    length = sizeof(struct grehdr);
    pos += length;
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
    if (flag & GRE_ROUTING){
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
  }
  else if ((pos[0] == 0x7e) && (pos[1] == 0xff) && (pos[2] == 0x03) && (pos[3] == 0x00))
  {
    return GRE_PPP_NO_ZIP;
  }
  else if ((pos[0] == 0x7e) && (pos[1] == 0xff) && (pos[2] == 0x03) && (pos[3] == 0xc0))
  {
    return GRE_PPP_SLIP;
  }
  else if ((pos[0] == 0x7e) && (pos[1] == 0xff) && (pos[2] == 0x03) && (pos[3] == 0x80))
  {
    return GRE_PPP_NCP;
  }
  else if (pos[0] != 0x7e)
  {
    return GRE_PPP_FRAGMENT;
  }
  else
  {
    return GRE_PPP_INVAILD;
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
  if ((NULL == ppp_payload) || (ppp_payload_length< GRE_PPP_MIN_SIZE) || (NULL == ppp_ret))
  {
    QDebug_Error("gre_ppp_parser failed;parameter is invalid");
    return -1;
  }
  memset(ppp_ret, 0x00,sizeof(PPP_RET));
  int pos = 0, ppp_num;
  ppp_num = 1;
  ppp_ret->ppp_pos[ppp_num].start = 0;
  if (ppp_payload[pos] == 0x7e)
    pos ++;
  while(pos < ppp_payload_length)
  {
    while( (pos < ppp_payload_length) && (ppp_payload[pos]!= 0x7e))
      pos++;
    if (pos >= ppp_payload_length)
    {
      QDebug_strval2("pos & payload", pos, ppp_payload_length);
      ppp_ret->ppp_pos[ppp_num].end = pos - 1;
    }
    else if ((ppp_payload[pos]== 0x7e))
    {
      if ((pos < ppp_payload_length - 1) && (ppp_payload[pos+1]== 0x7e))
      {
        ppp_ret->ppp_pos[ppp_num].end = pos;
        ppp_num ++;
        ppp_ret->ppp_pos[ppp_num].start = ++pos;
        ++pos;
        if (pos >= ppp_payload_length)
          ppp_num--;
      }
      else if ((pos < ppp_payload_length - 1) && (ppp_payload[pos+1]!= 0x7e))
      {
        ppp_ret->ppp_pos[ppp_num].end = pos - 1;
        ppp_num ++;
        ppp_ret->ppp_pos[ppp_num].start = pos++;
      }
      else
      {
        ppp_ret->ppp_pos[ppp_num].end = pos++;
      }
    }
  }
  ppp_ret->ppp_num = ppp_num;
  return 0;
}

/*
* name: ppp_format_payload
* parameter :
        payload : pos of start ppp segment from 7e
        packet_size : modify total packet_size
* ret : success 0; failed -1;
* description : re_translatat ppp format;
*/
int ppp_translat_payload (  u_char  *ppp_payload, int *ppp_payload_size)
{
  if ((NULL == ppp_payload) || (*ppp_payload_size < GRE_PPP_MIN_SIZE))
  {
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
* name: ppp_remove_header
* parameter :
  ppp_payload : pointer of payload_gre
  ppp_payload_length : total packet length
  output_payload : the pointer point is valid address ;
* result :
    success : PPP_TYPE;
    false : < 0;
    invalid : > GRE_PPP_INVAILD;
*   description : remove ppp header ;
*/
int ppp_remove_header(u_char *ppp_payload, int *ppp_payload_length, uint8_t **output_payload)
{
  QDebug_string("[gre_remove_PPP_header]comming into");
  if (NULL == ppp_payload)
  {
    QDebug_Error("gre_remove_PPP_header is failed; parameter is invalid;");
    return -1;
  }
  *output_payload = ppp_payload;
  if(*ppp_payload_length < sizeof(int))
  {
    if (*(ppp_payload) != 0x7e)
    {
      return GRE_PPP_FRAGMENT;
    }
    else
    {
      return GRE_PPP_INVAILD;
    }
  }
  int gre_ppp_type ;
  gre_ppp_type = gre_get_ppp_type(*(int *)ppp_payload);
  QDebug_strval1("Get gre_ppp_type", gre_ppp_type);
  switch (gre_ppp_type)
  {
  case GRE_PPP_ZIP:
    if (*ppp_payload_length < GRE_PPP_ZIP_HEADERSIZE)
    {
      QDebug_Errorval1( "PACKET_SIZE < GRE_PPP_ZIP_HEADERSIZE",   *ppp_payload_length);
      return GRE_PPP_INVAILD;
    }
    *ppp_payload_length -= 2;
    ppp_payload += 2;
    break;
  case GRE_PPP_NO_ZIP:
    if (*ppp_payload_length < GRE_PPP_NO_ZIP_HEADERSIZE)
    {
      QDebug_Errorval1( "PACKET_SIZE < GRE_PPP_NO_ZIP_HEADERSIZE", *ppp_payload_length);
      return GRE_PPP_INVAILD;
    }
    *ppp_payload_length -= 5;
    ppp_payload  += 5;
    break;
  case GRE_PPP_NCP:
  case GRE_PPP_SLIP:
  case GRE_PPP_INVAILD:
    return GRE_PPP_NO_IP;
  case GRE_PPP_FRAGMENT:
  default :
    return GRE_PPP_FRAGMENT;
  }
  *output_payload = ppp_payload;
  return gre_ppp_type;
}


/*
* name: ppp_remove_tail
* parameter :
  ppp_payload : start of ppp segment ;
  ppp_payload_length : output parameter  and length of ppp_payload
* ret : 0 if success , else -1;
*   description : remove ppp header ;
*/
int ppp_remove_tail(u_char *ppp_payload, int *ppp_payload_length)
{
  if ((NULL == ppp_payload) || (*ppp_payload_length < GRE_PPP_MIN_SIZE))
  {
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
  name: ppp_autoformat_payload
  parameter:
    ppp_one_packet_payload  : start of ppp packet ;
    ppp_one_packet_length   : address of ppp_one_packet length
    output_ppp_one_packet_payload : output parameter ; the pointer to ready to pcapdump
    ppp_type : the pointer point to ppp type
  result:
    false: < 0;
    invalid : > 0
    success : 0
  description :
    process_ppp_payload  aim to org info data
*/

int ppp_autoformat_payload(uint8_t *ppp_one_packet_payload, int *ppp_one_packet_length, uint8_t **output_ppp_one_packet_payload, int* ppp_type)
{
  if ((NULL == ppp_one_packet_payload) || (NULL == ppp_one_packet_length))
  {
    QDebug_Error("ppp_process_payload is failed; parameter is invalid;");
    return -1;
  }
  int ret = 0;
  ret = ppp_translat_payload( ppp_one_packet_payload, ppp_one_packet_length);
  if (ret < 0)
  {
    QDebug_Error("ppp_format_payload is failed; parameter is invalid;");
    return -1;
  }
  uint8_t *new_ppp_fragment_payload = NULL;
  ret =   ppp_remove_header( ppp_one_packet_payload, ppp_one_packet_length, &new_ppp_fragment_payload);
  if (ret < 0)
  {
    QDebug_Error("ppp_remove_header is failed; parameter is invalid;");
    return -1;
  }
  else if ((ret == GRE_PPP_FRAGMENT) || (ret == GRE_PPP_ZIP) || (ret == GRE_PPP_NO_ZIP))
  {
    *ppp_type = ret ;
    ret = ppp_remove_tail( new_ppp_fragment_payload, ppp_one_packet_length);
    if (ret < 0)
    {
      QDebug_Error("ppp_remove_tail is failed; parameter is invalid;");
      return -1;
    }
  }
  else
  {
    *ppp_type = ret;
    statistic_log.gre_ppp_invalid_pro++;
    QDebug_string("ppp payload is not support protocol");
    return 1;
  }
  *output_ppp_one_packet_payload = new_ppp_fragment_payload;
  return 0;
}
/*
  name : ppp_process_packet_normal_dump
  parameter :
    output_payload : ready to write packet
    output_payload_size : size of packet
  return :
    success 0, failed -1;
  description :
    write packet into file by pcap_dump
*/
int ppp_process_packet_normal_dump(uint8_t *output_payload, int output_payload_size)
{
  if ((NULL == output_payload) || (output_payload_size < sizeof(struct ether_header)) )
  {
    QDebug_Error("ppp_process_packet_normal_dump is failed");
    return -1;
  }
  statistic_log.dump_cnt++;
  struct pcap_pkthdr out_pkthdr = {0x00};
  out_pkthdr.ts.tv_sec = packet_num;
  out_pkthdr.ts.tv_usec = 0;
  out_pkthdr.caplen = output_payload_size;
  out_pkthdr.len = out_pkthdr.caplen;
  pcap_dump((u_char *)pcap_dumper, &out_pkthdr, output_payload);
  return 0;
}


/*
  name : ppp_process_packet_normal
  parameter :
    ppp_payload : the pointer point to ppp segment
    ppp_payload_length : length of ppp segment
  return :
    successs 0, failed -1;
  description :
    process ppp payload normal
*/
int ppp_process_packet_normal(uint8_t *eth_payload, int *eth_payload_length)
{
  if ((NULL == eth_payload) || (NULL == eth_payload_length) || (*eth_payload_length <= sizeof(struct ether_header)))
  {
    QDebug_Error("ppp_process_packet_normal is failed, parameter is invalid");
    return -1;
  }
  uint8_t *output_payload = NULL;
  uint8_t *mac_payload = NULL;
  mac_payload = malloc (sizeof(struct ether_header));
  if (NULL == mac_payload)
  {
    QDebug_Error("mac_payload malloc buffer is failed");
    goto failed;
  }
  memcpy(mac_payload, eth_payload, sizeof(struct ether_header));
  eth_payload += sizeof(struct ether_header);
  int ip_hl = ((struct ip*)eth_payload)->ip_hl*4;
  int ip_len = *eth_payload_length - sizeof(struct ether_header);
  int ppp_size = ip_len - ip_hl;
  //QDebug_Error("payload come into function");
  //Print_Debug( eth_payload, ppp_size);
  int ppp_type, ret = 0;
  uint8_t *new_ppp_payload = NULL;
  ret = ppp_autoformat_payload( eth_payload, &ppp_size, &new_ppp_payload, &ppp_type);
  if (ret < 0)
  {
    QDebug_Error("ppp_autoformat_payload is failed or not support");
    goto failed;
  }
  else if (ret > 0)
  {
    QDebug_string("ppp_autoformat_payload is failed or not support");
    goto END;
  }
  output_payload = malloc (TMP_BUF_PAYLOAD_SIZE);
  if (NULL == output_payload)
  {
    QDebug_Error("output_payload malloc is failed");
    goto failed;
  }
  //QDebug_Error("after in format ppp_payload ,from ppp_payload");
  //Print_Debug(new_ppp_payload, ppp_size);
  memcpy(output_payload, mac_payload, sizeof(struct ether_header));
  memcpy(output_payload + sizeof(struct ether_header), new_ppp_payload, ppp_size);
  ip_len = ntohs(((struct ip*)new_ppp_payload)->ip_len);
  ret = ppp_process_packet_normal_dump( output_payload, ip_len + sizeof(struct ether_header));
  if (ret < 0)
  {
    QDebug_Error("ppp_process_packet_normal_dump is failed");
    goto failed;
  }
END:
  if (NULL != mac_payload)
    free(mac_payload);
  if (NULL != output_payload)
    free(output_payload);
  return 0;
failed :
  if (NULL != mac_payload)
    free(mac_payload);
  if (NULL != output_payload)
    free(output_payload);
  return -1;
}



/*
  name : ppp_packet_status
  parameter :
    ppp_payload : the pointer point tto ppp_payload
    ppp_payload_length : size of ppp_payload
   return :
    complete : 0;
    start : 1
    end : 2
    other : 3
  description:
    get ppp_packet_status
*/
int ppp_packet_status(uint8_t *ppp_payload, int ppp_payload_length, int packet_position)
{
  if ((NULL == ppp_payload) || (ppp_payload_length < GRE_PPP_MIN_SIZE))
  {
    QDebug_Error("ppp_packet_complete is failed, parameter is invalid");
    return -1;
  }
  if ((ppp_payload[0] == 0x7e) && ((ppp_payload[ppp_payload_length - 1] == 0x7e) || packet_position))
  {
    return PPP_PKT_OK;
  }
  else if (ppp_payload[0] == 0x7e)
  {
    return PPP_PKT_START_OK;
  }
  else if (ppp_payload[ppp_payload_length - 1] == 0x7e)
  {
    return PPP_PKT_END_OK;
  }
  else
  {
    return PPP_PKT_BRK;
  }
}
/*
  name : ppp_process_packet
  parameter:
    eth_payload : the pointer point to payload of packet
    eth_payload_length : size of packet
    packet_position : midile 1, end 0
  return :
    success 0, failed -1; invalid >0
  description:
    process one packet;
*/

int ppp_process_packet(uint8_t *eth_payload, int eth_payload_length, int packet_position, GRE_NODE *gre_node)
{
  if ((NULL == eth_payload) || (eth_payload_length < ETHER_HDR_LEN) || (NULL == gre_node))
  {
    QDebug_Error("eth_payload is failed, parameter is invalid");
    return -1;
  }
  uint8_t *src_payload = eth_payload;
  uint8_t *output_payload = NULL;
  output_payload = malloc (TMP_BUF_PAYLOAD_SIZE);
  if (NULL == output_payload){
    QDebug_Error("malloc is failed in ppp_process_packet");
    return -1;
  }
  src_payload += ETHER_HDR_LEN;
  int packet_size = ETHER_HDR_LEN;
  
  struct ip* ip_hdr = (struct ip*)src_payload;
  int ip_hl   =   ip_hdr->ip_hl * 4;
  int ip_src  =   ntohl(ip_hdr->ip_src.s_addr);
  int ip_dst  =   ntohl(ip_hdr->ip_dst.s_addr);
  uint16_t ip_outer_id = ntohs(ip_hdr->ip_id);
  int ip_len = eth_payload_length - ETHER_HDR_LEN;
  uint8_t ip_frag = (ntohs(ip_hdr->ip_off) & IP_MF)?1:0;
  
  uint8_t *ip_payload = NULL;
  ip_payload = malloc (ip_hl);
  if (NULL == ip_payload)
  {
    QDebug_Error("ip_payload malloc is failed");
    return -1;
  }
  memcpy(ip_payload, src_payload, ip_hl);
  
  uint32_t hash_id = 0;
  hash_id = ip_cal_hashid( ip_src,  ip_dst,  0);
  
  src_payload += ip_hl;
  int packet_status = 0;
  int ppp_payload_length = ip_len - ip_hl;
  packet_status = ppp_packet_status( src_payload, ppp_payload_length, packet_position);
  if (packet_status < 0)
  {
    QDebug_Error("ppp_packet_status is failed");
    return 1;
  }
  
  LIST_NODE list_node = {0x00};
  list_node.age_time = AGE_TIME_INIT;
  list_node.hash_id = hash_id;
  
  int ppp_type,ret = 0;
  uint8_t *new_output_payload = NULL;
  ret = ppp_autoformat_payload( src_payload, &ppp_payload_length, &new_output_payload, &ppp_type);
  if (ret < 0)
  {
    QDebug_Error("ppp_autoformat_payload  is failed");
    return -1;
  }
  else if (ret > 0)
  {
    QDebug_string("ppp_autoformat_payload not support protocol");
    return 1;
  }
  else
  {
    QDebug_string("ppp_autoformat_payload process payload is ok");
  }
  
  if (packet_status == PPP_PKT_OK)
  {
    struct ip*ip_hdr = (struct ip*)new_output_payload;
    ip_len = ntohs(ip_hdr->ip_len);
    packet_size += ip_len;
    memcpy(output_payload, eth_payload, ETHER_HDR_LEN);
    memcpy(output_payload + ETHER_HDR_LEN, new_output_payload, ip_len);
    
    ret = ppp_process_packet_normal_dump( output_payload, packet_size);
    if (ret < 0){
      QDebug_Error("ppp_process_packet_normal_dump is failed");
      return -1;
    }
  }
  else if (packet_status == PPP_PKT_START_OK)
  {
    if (ppp_payload_length < IP_MIN_HEADER)
    {
      QDebug_string("ip segment is lost&ready put it into buffer");
      list_node.ip_node.enable = 0;
      list_node.gre_node = *gre_node;
      list_node.ip_node.buffer = malloc(ppp_payload_length);
      if (NULL == list_node.ip_node.buffer)
      {
        QDebug_Error("malloc is failed");
        return -1;
      }
      memcpy(list_node.ip_node.buffer, new_output_payload, ppp_payload_length);
      list_node.ip_node.buffer_length = ppp_payload_length;
      ret = ppp_list_add( list_header, &list_node);
      if (ret < 0)
      {
        QDebug_Error("ppp_list_add failed");
        return -1;
      }
    }
    else //have full ip segment ,so ready to dump packet_segment
    {
      struct ip* ip_hdr = (struct ip*)new_output_payload;
      int ip_hl = (ip_hdr->ip_hl)*4;
      int ip_len = ntohs(ip_hdr->ip_len);
      int ip_src = ntohl(ip_hdr->ip_src.s_addr);
      int ip_dst = ntohl(ip_hdr->ip_dst.s_addr);
      int ip_p  = ip_hdr->ip_p;
      uint8_t ip_tos = ip_hdr->ip_tos;
      uint16_t ip_inter_id = ntohs(ip_hdr->ip_id);

      uint8_t *data_payload = new_output_payload + ip_hl;
      int data_payload_length = ppp_payload_length - ip_hl;
      int bytes = data_payload_length / 8 * 8;
      int last = data_payload_length % 8;

      memcpy(output_payload, eth_payload, ETHER_HDR_LEN);
      // if the packet is full, so don't be care the next packet, the next packet must be checksum
      if (ppp_payload_length >= ip_len){
        Set_IP_FLAG_DF( ip_hdr, 1);
        Set_IP_FLAG_MF(ip_hdr, 0);
        Set_IP_FLAG_Offset( ip_hdr, 0);        
        memcpy(output_payload + ETHER_HDR_LEN, new_output_payload, ip_len);
        packet_size = ETHER_HDR_LEN + ip_len;
        last = 0;
      }else {
        Set_IP_FLAG_DF( ip_hdr, 0);
        Set_IP_FLAG_MF(ip_hdr, 1);
        Set_IP_FLAG_Offset( ip_hdr, 0);
        ip_hdr->ip_len = htons(ip_hl + bytes);
        memcpy(output_payload + ETHER_HDR_LEN, new_output_payload, ip_hl);
        memcpy(output_payload + ETHER_HDR_LEN + ip_hl, new_output_payload + ip_hl, bytes);
        packet_size = ETHER_HDR_LEN + ip_hl + bytes;
      }
            
      ret = ppp_process_packet_normal_dump( output_payload, packet_size);
      if (ret < 0)
      {
        QDebug_Error("ppp_process_packet_normal_dump failed");
        return -1;
      }
      if (0 != last)
      {
        list_node.ip_node.buffer = malloc(last);
        if (NULL == list_node.ip_node.buffer)
        {
          QDebug_Error("malloc is failed");
          return -1;
        }
        memcpy(list_node.ip_node.buffer, new_output_payload + ip_hl + bytes, last);
        list_node.ip_node.buffer_length = last;
        list_node.gre_node = *gre_node;
        list_node.ip_node.src = ip_src;
        list_node.ip_node.dst = ip_dst;
        list_node.ip_node.p = ip_p;
        list_node.ip_node.tos = ip_tos;
        list_node.ip_node.outer_id = ip_outer_id;
        list_node.ip_node.inter_id = ip_inter_id;
        list_node.ip_node.fragment = ip_frag;
        list_node.ip_node.nextoff = bytes/8;
        list_node.ip_node.curoff = 0;
        list_node.ip_node.enable = 1;
        ppp_list_add( list_header, &list_node);
      }
    }
  }
  else if (packet_status == PPP_PKT_END_OK)
  {
    LIST_NODE *find_ret = NULL;
    find_ret = ppp_list_find( list_header, hash_id);
    if (NULL == find_ret)
    {
      statistic_log.gre_not_find_cnt++;
      QDebug_string("list_gre_find not found key");
      return 1;
    }
    if ((gre_node->enable != 1) ||  (find_ret->gre_node.enable != 1))
    {
      statistic_log.gre_not_find_cnt++;
      QDebug_string("gre_flag.seqnum is error");
      return 1;
    }
    if (!((find_ret->gre_node.seqnum == gre_node->seqnum - 1) || (find_ret->gre_node.seqnum == gre_node->seqnum)))
    {
      statistic_log.gre_not_find_cnt++;
      QDebug_string("gre_flag.seqnum is error");
      return 1;
    }
    
    if (find_ret->ip_node.fragment){
      if (find_ret->ip_node.outer_id != ip_outer_id){
        return 1;
      }
    }
    
    find_ret->ip_node.buffer = realloc(find_ret->ip_node.buffer, find_ret->ip_node.buffer_length + ppp_payload_length);
    if (NULL == find_ret->ip_node.buffer)
    {
      QDebug_Error("realloc is failed");
      return -1;
    }
    memcpy(find_ret->ip_node.buffer + find_ret->ip_node.buffer_length, new_output_payload, ppp_payload_length);
    find_ret->ip_node.buffer_length += ppp_payload_length;
    memcpy(output_payload, eth_payload, ETHER_HDR_LEN);

    struct ip* ip_hdr = NULL;
    int ip_src , ip_dst, ip_p;
    int ip_hl, ip_len;
    uint8_t ip_tos;
    uint16_t ip_inter_id, ip_outer_id;
    uint16_t ip_off = 0;
    if (find_ret->ip_node.enable != 1)
    {
      ip_hdr = (struct ip*)(find_ret->ip_node.buffer);
      ip_len = ntohs(ip_hdr->ip_len);
      ip_inter_id = ntohs(ip_hdr->ip_id);
      memcpy(output_payload + ETHER_HDR_LEN, find_ret->ip_node.buffer, ip_len);
      packet_size += ip_len;
    }else {
      ip_src =  find_ret->ip_node.src;
      ip_dst =  find_ret->ip_node.dst;
      ip_p =    find_ret->ip_node.p;
      ip_off =  find_ret->ip_node.nextoff;
      ip_inter_id = find_ret->ip_node.inter_id;
      ip_tos = find_ret->ip_node.tos;
      
      //re-modify ip-segmnet info node rf: 0 df:0 mf:0
      ip_hdr = (struct ip*)ip_payload;
      ip_hl = ip_hdr->ip_hl*4;
      ip_hdr->ip_src.s_addr = htonl(ip_src);
      ip_hdr->ip_dst.s_addr = htonl(ip_dst);
      ip_hdr->ip_p = ip_p;
      ip_hdr->ip_id = htons(ip_inter_id);
      ip_hdr->ip_tos = ip_tos;
      ip_hdr->ip_len = htons(ip_hl + find_ret->ip_node.buffer_length);
      Set_IP_FLAG_DF( ip_hdr, 0);
      Set_IP_FLAG_MF( ip_hdr, 0);
      Set_IP_FLAG_Offset( ip_hdr, ip_off);
      memcpy(output_payload + ETHER_HDR_LEN, ip_payload, ip_hl);
      memcpy(output_payload + ETHER_HDR_LEN + ip_hl, find_ret->ip_node.buffer, find_ret->ip_node.buffer_length);
      packet_size += ip_hl + find_ret->ip_node.buffer_length;
    }
    //Print_Debug( output_payload, packet_size);
    ret = ppp_process_packet_normal_dump( output_payload, packet_size);
    if (ret < 0)
    {
    QDebug_Error("ppp_process_packet_normal_dump failed");
      return -1;
    }
    ppp_list_del( find_ret);
  }
  else if (packet_status == PPP_PKT_BRK)
  {
    LIST_NODE *find_ret = NULL;
    find_ret = ppp_list_find( list_header, hash_id);
    if (NULL == find_ret)
    {
      statistic_log.gre_not_find_cnt++;
      QDebug_string("list_gre_find not found key");
      return 1;
    }
    if ((find_ret->gre_node.enable != 1) || (gre_node->enable != 1))
    {
      QDebug_string("gre_flag.seqnum is error");
      return 1;
    }
    if (!((find_ret->gre_node.seqnum == gre_node->seqnum - 1) || (find_ret->gre_node.seqnum == gre_node->seqnum)))
    {
      statistic_log.gre_not_find_cnt++;
      QDebug_string("gre_flag.seqnum is error");
      return 1;
    }

    if (find_ret->ip_node.fragment){
      if (find_ret->ip_node.outer_id != ip_outer_id){
        return 1;
      }
    }
    
    find_ret->ip_node.buffer = realloc(find_ret->ip_node.buffer, find_ret->ip_node.buffer_length+ ppp_payload_length);
    if (NULL == find_ret->ip_node.buffer)
    {
      QDebug_Error("realloc is failed");
      goto failed;
    }
    memcpy(find_ret->ip_node.buffer + find_ret->ip_node.buffer_length, new_output_payload, ppp_payload_length);
    find_ret->ip_node.buffer_length += ppp_payload_length;

    struct ip* ip_hdr = NULL;
    int ip_src , ip_dst, ip_p;
    int ip_hl, ip_len;
    uint16_t ip_inter_id, ip_off;
    uint8_t ip_tos;
    int bytes, last;
    if (find_ret->ip_node.enable != 1)
    {
      ip_hdr = (struct ip*)(find_ret->ip_node.buffer);
      ip_len = ntohs(ip_hdr->ip_len);
      ip_hl = ip_hdr->ip_hl * 4;
      ip_src = ntohl(ip_hdr->ip_src.s_addr);
      ip_dst = ntohl(ip_hdr->ip_dst.s_addr);
      ip_p = ip_hdr->ip_p;
      ip_inter_id = ntohs(ip_hdr->ip_id);
      ip_tos = ip_hdr->ip_tos;

      bytes = (find_ret->ip_node.buffer_length - ip_hl) / 8 * 8;
      last =  (find_ret->ip_node.buffer_length - ip_hl) % 8;


      if (ppp_payload_length >= ip_len){
        Set_IP_FLAG_DF( ip_hdr, 1);
        Set_IP_FLAG_MF(ip_hdr, 0);
        Set_IP_FLAG_Offset( ip_hdr, 0);
        memcpy(output_payload + ETHER_HDR_LEN, new_output_payload, ip_len);
        packet_size = ETHER_HDR_LEN + ip_len;
        last = 0;
      }else {
        Set_IP_FLAG_DF( ip_hdr, 0);
        Set_IP_FLAG_MF(ip_hdr, 1);
        Set_IP_FLAG_Offset( ip_hdr, 0);
        ip_hdr->ip_len = htons(ip_hl + bytes);
        memcpy(output_payload + ETHER_HDR_LEN, find_ret->ip_node.buffer, ip_hl);
        memcpy(output_payload + ETHER_HDR_LEN + ip_hl, find_ret->ip_node.buffer + ip_hl, bytes);
        packet_size = ETHER_HDR_LEN + ip_hl + bytes;
      }
    }else {
      ip_src = find_ret->ip_node.src;
      ip_dst = find_ret->ip_node.dst;
      ip_p = find_ret->ip_node.p;
      ip_inter_id = find_ret->ip_node.inter_id;
      ip_tos = find_ret->ip_node.tos;
      ip_off = find_ret->ip_node.nextoff;

      bytes = find_ret->ip_node.buffer_length / 8 * 8;
      last = find_ret->ip_node.buffer_length % 8;

      ip_hdr = (struct ip*)ip_payload;
      ip_hl = ip_hdr->ip_hl*4;
      ip_hdr->ip_src.s_addr = htonl(ip_src);
      ip_hdr->ip_dst.s_addr = htonl(ip_dst);
      ip_hdr->ip_p = ip_p;
      ip_hdr->ip_tos = ip_tos;
      ip_hdr->ip_id = htons(ip_inter_id);
      Set_IP_FLAG_DF( ip_hdr, 0);
      Set_IP_FLAG_MF(ip_hdr, 1);
      Set_IP_FLAG_Offset( ip_hdr, ip_off);
      ip_hdr->ip_len = htons(ip_hl + bytes);
      memcpy(output_payload + ETHER_HDR_LEN, ip_payload, ip_hl);
      memcpy(output_payload + ETHER_HDR_LEN + ip_hl, find_ret->ip_node.buffer, bytes);
      packet_size += ip_hl + bytes;
    }    
    ret = ppp_process_packet_normal_dump( output_payload, packet_size);
    if (ret < 0)
    {
    QDebug_Error("ppp_process_packet_normal_dump failed");
      return -1;
    }
    if (last != 0){
      list_node.age_time = AGE_TIME_INIT;
      list_node.gre_node = *gre_node;
      list_node.hash_id = hash_id;
      list_node.ip_node.buffer = malloc (last);
      if (NULL == list_node.ip_node.buffer)
      {
          QDebug_Error("malloc is failed");
          return -1;
      }
      memcpy(list_node.ip_node.buffer, find_ret->ip_node.buffer + bytes, last);
      ppp_list_del(find_ret);
      list_node.ip_node.buffer_length = last;
      list_node.ip_node.enable = 1;
      list_node.ip_node.dst = ip_dst;
      list_node.ip_node.src = ip_src;
      list_node.ip_node.p = ip_p;
      list_node.ip_node.fragment = ip_frag;
      list_node.ip_node.tos = ip_tos;
      list_node.ip_node.outer_id = ip_outer_id;
      list_node.ip_node.inter_id = ip_inter_id;
      list_node.ip_node.nextoff=bytes/8;
      ppp_list_add( list_header, &list_node);
    }
  }
  else
  {
    QDebug_Error("something will be wrong, please check ppp_packet_status function");
    goto failed;
  }
END:
  if (NULL != output_payload)
    free(output_payload);
  return 0;
failed:
  if (NULL != output_payload)
    free(output_payload);
  return -1;
}

/*
  name : ppp_process_packets
  parameter :
    eth_payload : start of orgpacket
    eth_payload_length : size of orgpacket
  return :
    success 0, fail <0 ;
  description:
    split packets in ppp payload and put it into deal function: ppp_process_packet
*/

int ppp_process_packets(uint8_t *eth_payload, int *eth_payload_length, GRE_NODE *gre_node)
{
  if ((NULL == eth_payload) || (NULL == eth_payload_length) || (*eth_payload_length < ETHER_HDR_LEN))
  {
    QDebug_Error("ppp_process_packets is failed, parameter is invalid");
    return -1;
  }
  
  uint8_t *struct_pacekt = NULL;
  uint8_t *src_payload = eth_payload;
  struct ip* ip_hdr = NULL;
  
  src_payload += ETHER_HDR_LEN;
  ip_hdr = (struct ip*)src_payload;
  int ip_len = *eth_payload_length - ETHER_HDR_LEN;
  int ip_hl = ip_hdr->ip_hl * 4;
  
  src_payload += ip_hl;
  int ppp_payload_length = ip_len - ip_hl;
  int ret = 0;
  PPP_RET ppp_ret = {0x00};
  ret = gre_ppp_parser( src_payload,  ppp_payload_length,  &ppp_ret);
  if (ret < 0)
  {
    QDebug_Error("gre_ppp_parser is faild");
    return -1;
  }
  struct_pacekt = malloc (TMP_BUF_PAYLOAD_SIZE);
  if (NULL == struct_pacekt)
  {
    QDebug_Error("struct_packet malloc is failed");
    statistic_log.drop_gre_cnt++;
    goto failed;
  }
  int ppp_num = ppp_ret.ppp_num;
  int ppp_index = 0, ppp_pos;
  int struct_pacekt_length = 0;
  const int ex_hl = ETHER_HDR_LEN + ip_hl;
  memcpy(struct_pacekt, eth_payload, ETHER_HDR_LEN + ip_hl);
  QDebug_strval2("how many packet:[] in framer:[]", ppp_num, packet_num);
  while(ppp_num--)
  {
    ppp_index = ppp_ret.ppp_num - ppp_num;
    ppp_payload_length = ppp_ret.ppp_pos[ppp_index].end - ppp_ret.ppp_pos[ppp_index].start + 1;
    struct_pacekt_length = ex_hl + ppp_payload_length;
    memcpy(struct_pacekt + ex_hl, src_payload + ppp_ret.ppp_pos[ppp_index].start, ppp_payload_length);
    ret = ppp_process_packet( struct_pacekt, struct_pacekt_length, (ppp_index < ppp_ret.ppp_num)? 1:0, gre_node);
    if (ret < 0)
    {
      QDebug_Error("ppp_process_packet is failed");
      goto failed;
    }
    else if (ret > 0)
    {
      QDebug_string("ppp_process_packet some abort");
      continue;
    }
  }
END:
  free(struct_pacekt);
  return 0;
failed:
  if (NULL != struct_pacekt)
    free(struct_pacekt);
  return -1;
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
  //TODO: check si version == 0 1 non support car pptp)
  int packet_size = 0;
  u_int16_t flags;
  const u_char *payload_src = NULL;
  u_char *payload_dst = NULL;
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
  uint8_t *new_payload = NULL;
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
    statistic_log.not_gre_pacekt_cnt++;
    // Non IP packet ? Just copy
    process_nonip_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
    pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
  }
  else //IP Protocol
  {
    ip_hdr = (const struct ip *) (in_payload + sizeof(struct ether_header));
    if (ip_hdr->ip_p == IPPROTO_GRE)
    {
      new_payload = (uint8_t*)malloc (TMP_BUF_PAYLOAD_SIZE);
      if (NULL == new_payload)
      {
        QDebug_Error("malloc is failed");
        goto END;
      }
      int ret = 0;
      IP_INFO ip_info = {0x00};
      ret = ip_all_info( ip_hdr, &ip_info);
      if (ret < 0){
        QDebug_Error("ip_all_info is failed");
        goto END;
      }
      //because the in_pkt->len is wrong, so i cal the length
      int packet_length = ip_info.total_len + ETHER_HDR_LEN;
      //get ip_info
      uint32_t hash_id;
      hash_id =   ip_cal_hashid( ip_info.ip_src,  ip_info.ip_dst, 0);
      
      uint8_t *src_payload = in_payload;
      const int ex_hl = ETHER_HDR_LEN + ip_info.hl;
      memcpy(new_payload, src_payload, ex_hl);
      src_payload += ex_hl;
      
      int gre_hl = 0;
      int ip_frag = (ip_info.offset)?1:0;
      GRE_NODE gre_node = {0x00};
      if (ip_frag){
          gre_hl = 0;
      }else {
          gre_hl = gre_get_items((struct grehdr *) src_payload, &gre_node);
      }
      
      LIST_NODE *list_node = NULL;
      if (0 == gre_hl){
        list_node = ppp_list_find( list_header, hash_id);
        if (NULL == list_node){
          QDebug_string("lost gre info node");
          gre_node.enable = 0;
        }else {
          gre_node = list_node->gre_node;
        }
      }else {
          gre_node.enable = 1;
      }
      
      src_payload += gre_hl;
      packet_length -= gre_hl;
      memcpy(new_payload + ex_hl, src_payload, packet_length - ex_hl);
      //struct packet, eth_ip_ppp_payload (gre_node info)->gre_node 
      ret = ppp_process_packets(new_payload, &packet_length, &gre_node);
      if (ret < 0)
      {
        QDebug_Error("i will drop the packet");
      }
      goto END;
    }
    else /*other protocol */
    {
      goto DEFAULT;
    }
DEFAULT:
    switch (ip_hdr->ip_p)
    {
    //case IPPROTO_IPIP:
    //  debug_print("%s\n", "\tIPPROTO_IPIP");
    // process_ipip_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
    //  out_pkthdr->ts.tv_sec = packet_num;
    //  pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
    //  break;
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
//    case IPPROTO_ESP:
//     debug_print("%s\n", "\tIPPROTO_ESP\n");
//      if (ignore_esp == 1)
//      {
//        verbose("Ignoring ESP packet %i\n", packet_num);
//        free(out_pkthdr);
//        free(out_payload);
//        return;
//      }
//      process_esp_packet(new_in_payload, packet_length, out_pkthdr, out_payload);
//      out_pkthdr->ts.tv_sec = packet_num;
//      pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
//      break;
    default:
      // Copy not encapsulated/unknown encpsulation protocol packets, like non_ip packets
      process_nonip_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
      out_pkthdr->ts.tv_sec = packet_num;
      pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
      verbose("Copying packet %i: not encapsulated/unknown encapsulation protocol\n", packet_num);
    } // if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
  }
END:
  if (NULL != new_payload)
    free(new_payload);
  free(out_pkthdr);
  free(out_payload);
exit: // Avoid several 'return' in middle of code
  QDebug_strval1("packet_num", packet_num);
  packet_num++;
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
  list_header = malloc (sizeof(LIST_NODE));
  if (NULL == list_header)
  {
    QDebug_Error("malloc is failed, in main");
    goto failed;
  }
  INIT_LIST_HEAD(&(list_header->pos));
  // Dispatch to handle_packet function each packet read from the pcap file
  pcap_dispatch(pcap_reader, 0, handle_packets, (u_char *) bpf);
failed:
  pcap_close(pcap_reader);
  pcap_close(p);
  pcap_dump_close(pcap_dumper);
  EVP_cleanup();
  flows_cleanup();
  Print_Statistic_cnt();
  return 0;
}

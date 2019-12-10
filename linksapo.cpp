#include <netlink/netlink.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <net/if.h>

#include <linux/wireless.h>
#include <linux/nl80211.h>

#include <sys/ioctl.h>

#include <iostream>
#include <thread>
#include <unistd.h>

#define GET_STA_MS_SLEEP 1000 //reading period for link going down. set in ms
#define IFINDEX 1 // Set the IFINDEX of the interface here
//#define MAC_ADDR "" // INSERT YOUR MAC HERE
#define MODE "avg" // "<last> or <avg> uses the last/average signal strengh for threshold of "link going down"
//#define SIGNAL_STRENGTH -65 // threshold for link going down
//#define GOINGDOWN_ACT false //(de)activate going down pooling method 
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

std::string MAC_ADDR = "";
bool GOINGDOWN_ACT = false;
bool isRunning = false;

int get_ifindex(struct nlattr* tb[], int *ifindex)
{
  if(tb[NL80211_ATTR_IFINDEX] == NULL) {
    return -1;
  }

  *ifindex = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);

  return 0;
}

int getSSID(int fd, const char* ifname, char* ssid)
{
  struct iwreq wrq;
  
  memset(ssid, 0, sizeof(ssid));
  wrq.u.essid.pointer = (caddr_t) ssid;
  wrq.u.essid.length  = IW_ESSID_MAX_SIZE + 1;
  wrq.u.essid.flags   = 0;
  strncpy(wrq.ifr_name, ifname, strlen(ifname));
  
  return ioctl(fd, SIOCGIWESSID, &wrq);
}

int nlCallbackSTAInfo(struct nl_msg* msg, void* arg)
{
  struct nlmsghdr* nl_hdr = nlmsg_hdr(msg);
  struct genlmsghdr* gnl_hdr = (genlmsghdr*) nlmsg_data(nl_hdr);
  struct nlattr* tb[NL80211_ATTR_MAX + 1];

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnl_hdr, 0), genlmsg_attrlen(gnl_hdr, 0), NULL);

  if(tb[NL80211_ATTR_STA_INFO] == NULL) {
    std::cout << "Unable to get attr sta info" << std::endl << std::flush;
    return -1;
  }
  
  struct nlattr* sta_info[NL80211_STA_INFO_MAX + 1];
  nla_parse_nested(sta_info, NL80211_STA_INFO_MAX, tb[NL80211_ATTR_STA_INFO], NULL);
  if(sta_info[NL80211_STA_INFO_SIGNAL] == NULL) {
    return -1;
  }
  
  int recv_signal;

  std::string mode = MODE;
  if(mode.compare("last") == 0) {
    recv_signal = (int)((int8_t) nla_get_u8(sta_info[NL80211_STA_INFO_SIGNAL]));
  } else if(mode.compare("avg") == 0) {
    recv_signal = (int)((int8_t) nla_get_u8(sta_info[NL80211_STA_INFO_SIGNAL_AVG]));
  } else {
    std::cout << "Error: Invalid Mode" << std::endl << std::flush;
  }
  
  if(recv_signal < SIGNAL_STRENGTH) {
    std::cout << "Crossed threshold "<< recv_signal << std::endl << std::flush;
  }
  
  return 0;
}

int nlCallbackEvents(struct nl_msg* msg, void* arg)
{
  int sk_fd = *((int*) arg);
  struct nlmsghdr* nl_hdr = nlmsg_hdr(msg);
  struct genlmsghdr* gnl_hdr = (genlmsghdr*) nlmsg_data(nl_hdr);
  struct nlattr* tb[NL80211_ATTR_MAX + 1];

  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnl_hdr, 0), genlmsg_attrlen(gnl_hdr, 0), NULL);

  switch(gnl_hdr->cmd) {
  
  // for STA
  case NL80211_CMD_CONNECT: {
    std::cout << "Received NL_CMD_CONNECT event" << std::endl << std::flush;
    
    int ifindex;
    get_ifindex(tb, &ifindex);
    char ifname[256];
    memset(ifname, 0, 256);
    if_indextoname(ifindex, ifname);
    std::cout << ifindex << ": " << ifname << std::endl << std::flush;
    
    // Get SSID
    char ssid[IW_ESSID_MAX_SIZE + 1];
    if(getSSID(sk_fd, ifname, ssid) < 0) {
      std::cout << "Error while discovering SSID" << std::endl << std::flush;
    }
    printf("%s\n", ssid);
  } break;
  
  // for STA
  case NL80211_CMD_DISCONNECT: {
    std::cout << "Received NL_CMD_DISCONNECT event" << std::endl << std::flush;
  } break;

  // for AP
  case NL80211_CMD_NEW_STATION:
    if (get_addr(tb, &addr) < 0)
      printf("New station: no MAC\n");
    else
      printf("New station: "MACSTR"\n", MAC2STR(addr));
    break;

  // for AP  
  case NL80211_CMD_DEL_STATION:
    if (get_addr(tb, &addr) < 0)
      printf("Del station: no MAC\n");
    else
      printf("Del station: "MACSTR"\n", MAC2STR(addr));
break;
  
  default:
    return NL_SKIP;
  }

  return 0;
}

int handleEvents()
{
  struct nl_sock *sk = NULL;

  sk = nl_socket_alloc();
  if(sk == NULL) {
    std::cout << "Unable to alloc nl socket" << std::endl << std::flush;
    nl_socket_free(sk);
    return -1;
  }
  
  int ret;
  ret = genl_connect(sk);
  if(ret < 0) {
    std::cout << "Cannot genl connect [" << ret << "]" << std::endl << std::flush;
    nl_socket_free(sk);
    return -1;
  }
  
  ret = genl_ctrl_resolve_grp(sk, "nl80211", NL80211_MULTICAST_GROUP_MLME);
  if(ret < 0) {
    std::cout << "MLME group not found [" << ret << "]" << std::endl << std::flush;
    nl_socket_free(sk);
    return -1;
  }

  ret = nl_socket_add_membership(sk, ret);
  if(ret < 0) {
    std::cout << "Unable to add membership [" << ret << "]" << std::endl << std::flush;
    nl_socket_free(sk);
    return -1;
  }

  nl_socket_disable_seq_check(sk);

  int fd = nl_socket_get_fd(sk);
  ret = nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, nlCallbackEvents, (int*) &fd);
  if(ret < 0) {
    std::cout << "Unable to modify callback [" << ret << "]" << std::endl << std::flush;
    nl_socket_free(sk);
    return -1;
  }

  while(isRunning) {
    ret = nl_recvmsgs_default(sk);
    if(ret < 0) {
      std::cout << "Error while receiving messages [" << ret << "]" << std::endl << std::flush;
    }
  }
  
  nl_socket_free(sk);
}

int handleSTAInfo()
{
  struct nl_msg* msg = NULL;
  struct nl_sock *sk = NULL;

  sk = nl_socket_alloc();
  if(sk == NULL) {
    std::cout << "Unable to alloc nl socket" << std::endl << std::flush;
    return -1;
  }
  
  int ret;
  ret = genl_connect(sk);
  if(ret < 0) {
    std::cout << "Cannot genl connect [" << ret << "]" << std::endl << std::flush;
    return -1;
  }

  int nl_id = genl_ctrl_resolve(sk, "nl80211");
  if(nl_id < 0) {
    std::cout << "Error 0 [" << "]" << std::endl << std::flush;
    return -1;
  }

  while(isRunning) { //pooling: checks each GET_STA_MS_SLEEP ms
    msg = nlmsg_alloc();
    if(msg == NULL) {
      std::cout << "Unable to alloc NL message" << std::endl << std::flush;
      nl_socket_free(sk);
      return -1;
    }

    if(!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl_id, 0, NLM_F_DUMP, NL80211_CMD_GET_STATION, 0)) {
      std::cout << "Unable to define command " << std::endl << std::flush;
      nlmsg_free(msg);
      nl_socket_free(sk);
      return -1;
    }

    if(nla_put_u32(msg, NL80211_ATTR_IFINDEX, IFINDEX)) {
      std::cout << "Unable to set attr ifindex " << std::endl << std::flush;
      nlmsg_free(msg);
      nl_socket_free(sk);
      return -1;
    }

    if(nla_put(msg, NL80211_ATTR_MAC, 6, MAC_ADDR)) {
      std::cout << "Unable to set attr mac " << std::endl << std::flush;
      nlmsg_free(msg);
      nl_socket_free(sk);
      return -1;
    }

    ret = nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, nlCallbackSTAInfo, NULL);
    if(ret < 0) {
      std::cout << "Unable to modify callback [" << ret << "]" << std::endl << std::flush;
      nlmsg_free(msg);
      nl_socket_free(sk);
      return -1;
    }

    ret = nl_send_sync(sk, msg);
    if(ret < 0) {
      std::cout << "Unable to send nl message [" << ret << "]" << std::endl << std::flush;
      nl_socket_free(sk);
      return -1;
    }

    usleep(GET_STA_MS_SLEEP * 1000);
  }

  nl_socket_free(sk);
}

int main(int argc, char** argv)
{
  //arg -> -mac <MACADDR> -gdown <THRESHOLD>
  if (argc > 2){
    std::cout << "Optional parameter (only for STA in <GoingDown> detection mode): -mac <MACADDR> -gdown <THRESHOLD>"
    return 0
  }
  for (int i = 1; i < argc; i++) {
    if (argv[i] == "-mac") {
      MAC_ADDR = argv[i + 1];

    }
    else if (argv[i] == "-gdown") {
      GOINGDOWN_ACT = true;
      isRunning = true;
      SIGNAL_STRENGTH = argv[i + 1];
    }
  }

  std::thread events(handleEvents); //link up and down
  if (GOINGDOWN_ACT)
    std::thread sta_info(handleSTAInfo); // going down
  
  events.join();
  sta_info.join();
  return 0;
}

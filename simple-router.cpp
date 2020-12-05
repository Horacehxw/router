/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
inline bool isBroadcastMac(const Buffer& mac) {
  Buffer broadcastMac(6, 0xff);
  if (mac == broadcastMac) return true;
  return false;
}

inline bool isRouterMac(const Buffer& mac, const Interface* inIface) {
  return mac == inIface->addr;
}

// IMPLEMENT THIS METHOD

//////////////////////////////////////////////////////////////////////////
void
SimpleRouter::handlePacket(const Buffer& packetBuffer, const std::string& inIfaceName)
{
  std::cerr << "Got packet of size " << packetBuffer.size() << " on interface " << inIfaceName << std::endl;

  /* sanity check the packet */
  // std::cerr << getRoutingTable() << std::endl;
  const Interface* inIface = findIfaceByName(inIfaceName);
  if (inIface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  // check packet size(preliminary judgment)
  if (packetBuffer.size() < sizeof(ethernet_hdr)) {
    std::cerr << "Received packet, but header is truncated, ignoring" << std::endl;
    return;
  }

  // check the ethernet header
  uint8_t* packet = (uint8_t*) packetBuffer.data();
  ethernet_hdr *ethernetHeader = (ethernet_hdr *) packet;
  Buffer inDestMac(ethernetHeader->ether_dhost, ethernetHeader->ether_dhost + ETHER_ADDR_LEN);
  if (!isBroadcastMac(inDestMac) && !isRouterMac(inDestMac, inIface)) {
    std::cerr << "Received packet, but target mac address in ethernet header is unknown, ignoring" << std::endl;
    return;
  }

  /* handle packet according to its type(arp or ipv4) */

  if (ntohs(ethernetHeader->ether_type) == ethertype_arp) {
    handleArpPacket(packetBuffer, inIface); 

  } else if (ntohs(ethernetHeader->ether_type) == ethertype_ip) { 
    handleIpPacket(packetBuffer, inIface);

  } else {
    std::cerr << "Received packet, but ether type is unknown, ignoring" << std::endl;
    return;
  }
}


void
SimpleRouter::handleArpPacket(const Buffer& packetBuffer, const Interface* inIface)
{
  uint8_t* packet = (uint8_t*) packetBuffer.data();
  ethernet_hdr* ethernetHeader = (ethernet_hdr*) packet;
  arp_hdr* arpHeader = (arp_hdr*) (packet + sizeof(ethernet_hdr)); 

  /* sanity check */

  // check if non-ethernet requests. 
  if (ntohs(arpHeader->arp_hrd) != arp_hrd_ethernet) {
    std::cerr << "Received arp packet, but hardware type is unknown, ignoring" << std::endl;
    return;
  }

  // check packet size
  if (packetBuffer.size() < sizeof(ethernet_hdr) + sizeof(arp_hdr)) {
    std::cerr << "Received arp packet, but size is less than arp minimum, ignoring" << std::endl;      
    return;
  }

  /* handle arp REQUEST or REPLY */

  if (ntohs(arpHeader->arp_op) == arp_op_request) { 

    // check: destination ip address must be targeted to router,
    // otherwise router doesn't have to make any response
    if (arpHeader->arp_tip != inIface->ip) {
      std::cerr << "Received arp packet, but it is not targeted to the router, ignoring" << std::endl;
      return;
    }

    uint32_t srcIp = inIface->ip;
    Buffer srcMac = inIface->addr;
    uint32_t destIp = arpHeader->arp_sip;
    Buffer destMac(ethernetHeader->ether_shost, ethernetHeader->ether_shost + ETHER_ADDR_LEN);
    sendArpPacket(srcIp, srcMac, destIp, destMac, arp_op_reply);
    return;

  } else if (ntohs(arpHeader->arp_op) == arp_op_reply) { 

    /* handle arp replies */

    // add request info to arp cache
      // ? maybe need to check entry existence before adding too ?
    uint32_t inSrcIp = arpHeader->arp_sip;
    Buffer inSrcMac(arpHeader->arp_sha, arpHeader->arp_sha + ETHER_ADDR_LEN);
    std::shared_ptr<ArpRequest> request = m_arp.insertArpEntry(inSrcMac, inSrcIp); 

    // forward all packets attached to the arp request
    for (auto& packet: request->packets) {
      // modify the packet before forwarding
      uint8_t* outPacket = (uint8_t*) packet.packet.data();
      ethernet_hdr *outEthernetHeader = (ethernet_hdr *) outPacket;
      ip_hdr* outIpHeader = (ip_hdr*) (outPacket + sizeof(ethernet_hdr));
      const Interface* outIface = findIfaceByName(packet.iface);

      memcpy(outEthernetHeader->ether_dhost, arpHeader->arp_sha, ETHER_ADDR_LEN);
      memcpy(outEthernetHeader->ether_shost, &(outIface->addr[0]), ETHER_ADDR_LEN);
      outIpHeader->ip_ttl--;
      outIpHeader->ip_sum = 0;
      outIpHeader->ip_sum = cksum(outIpHeader, sizeof(ip_hdr));

      sendPacket(packet.packet, packet.iface);
    }
      
    // remove the arp request from request queue maintained by m_arp
    // m_arp.removeRequest(request);
    return;

  } else { 
    // don't handle undocumented ARP packet types.
    std::cerr << "Received arp packet, but its arp operator code is unknown, ignoring" << std::endl;
    return; 
  }
}

void
SimpleRouter::handleIpPacket(const Buffer& packetBuffer, const Interface* inIface) 
{ 
  uint8_t* packet = (uint8_t*) packetBuffer.data();
  ethernet_hdr *ethernetHeader = (ethernet_hdr*) packet; 
  ip_hdr *ipHeader = (ip_hdr*) (packet + sizeof(ethernet_hdr));
  icmp_hdr *icmpHeader = (icmp_hdr*) (packet + sizeof(ethernet_hdr) + sizeof(ip_hdr));

  /* sanity check packet */

  // check packet size
  if (packetBuffer.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)) {
    std::cerr << "Received ip packet, but size is less than ip minimum, ignoring" << std::endl;
    return;
  }

  // check packet checksum 
  uint16_t ip_sum = ipHeader->ip_sum; 
  ipHeader->ip_sum = 0x0; 
  if (cksum(ipHeader, sizeof(ip_hdr)) != ip_sum) { 
    std::cerr << "Received icmp packet, but bit error happened and then checksum mismatched, ignoring" << std::endl;
    return;
  }

  /* make response to received packet */

  // add source MAC address to the ARP cache. 
  if(m_arp.lookup(ipHeader->ip_src) == nullptr) {
    Buffer inSrcMac(ethernetHeader->ether_shost, ethernetHeader->ether_shost + ETHER_ADDR_LEN);
    m_arp.insertArpEntry(inSrcMac, ipHeader->ip_src);
  }

  // if a packet dies of old age, send a ICMP timeout response. 
  if (ipHeader->ip_ttl <= 0) {
    std::cerr << "Received icmp packet, but time exceeding, send this signal" << std::endl;
    sendIcmpT3Packet(packetBuffer, inIface, 11, 0);
    return;
  }

  // destination ip address is targeted to router,
  // which indicates an *icmp* packet
  if (findIfaceByIp(ipHeader->ip_dst)) { 
    // check packet size
    if (packetBuffer.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr)) {
      std::cerr << "Received icmp packet, but size is less than icmp minimum, ignoring" << std::endl;
      return;
    }

    // if the packet is not an icmp echo request, send icmp "unreachable port or host" packet
    if (ipHeader->ip_p != ip_protocol_icmp && icmpHeader->icmp_type != 8) { 
      std::cerr << "Received icmp packet, but protocol data is not icmp or packet is not echo request, send this signal" << std::endl;
      sendIcmpT3Packet(packetBuffer, inIface, 3, 3) ; 
      return; 
    }

    // send echo reply to the echo request(received packet)
    sendIcmpPacket(packetBuffer, inIface, 0, 0);

  }

  // destination ip address is not targeted to router,
  // which indicates a *normal ip* packet
  else {
    /* Forward packet */
    if (ipHeader->ip_ttl == 1) {
      std::cerr << "Received icmp packet, but time exceeding, send this signal" << std::endl;
      sendIcmpT3Packet(packetBuffer, inIface, 11, 0);
      return;
    }

    // look up the routing table
    RoutingTableEntry routingEntry = { 0 };
    try {
      routingEntry = m_routingTable.lookup(ipHeader->ip_dst);
    } catch (...) { 
      std::cerr << "Received ip packet, but cannot find dest ip address in the routing table, dropping" << std::endl;
      return;
    }

    const Interface* outIface = findIfaceByName(routingEntry.ifName);
    if (!outIface) {
      std::cout << "`Received ip packet, but packet has the interface the router does not have, dropping" << std::endl;
      return; 
    }

    // look up the arp cache to know destination mac address
    auto arpEntry = m_arp.lookup(ipHeader->ip_dst);
    if (!arpEntry) {  // can't find such entry
      m_arp.queueRequest(ipHeader->ip_dst, packetBuffer, routingEntry.ifName);
      return;
    }
    else {            // find such entry
      // modify some info and forward
      memcpy(ethernetHeader->ether_dhost, &(arpEntry->mac[0]), ETHER_ADDR_LEN);
      memcpy(ethernetHeader->ether_shost, &(outIface->addr[0]), ETHER_ADDR_LEN);
      ipHeader->ip_ttl--;
      ipHeader->ip_sum = 0;
      ipHeader->ip_sum = cksum(ipHeader, sizeof(ip_hdr));

      sendPacket(packetBuffer, outIface->name);
    }
  }
}

void
SimpleRouter::sendArpPacket(const uint32_t srcIp, const Buffer& srcMac, const uint32_t destIp, const Buffer& destMac, const arp_opcode arp_op) {
  const size_t frameSize = sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(arp_hdr);
  uint8_t outPacket[frameSize];
  // outPacket
  ethernet_hdr* outEthernetHeader = (ethernet_hdr*) outPacket;
  arp_hdr* outArpHeader = (arp_hdr*) (outPacket + sizeof(ethernet_hdr));

  // fill in ethernet header
  memcpy(outEthernetHeader->ether_dhost, &(destMac[0]), ETHER_ADDR_LEN);
  memcpy(outEthernetHeader->ether_shost, &(srcMac[0]), ETHER_ADDR_LEN);
  outEthernetHeader->ether_type = htons(ethertype_arp);

  // fill in arp header
  outArpHeader->arp_hrd = htons(arp_hrd_ethernet);
  outArpHeader->arp_pro = htons(ethertype_ip);
  outArpHeader->arp_hln = 0x06;
  outArpHeader->arp_pln = 0x04;
  outArpHeader->arp_op = htons(arp_op);
  memcpy(outArpHeader->arp_sha, &(srcMac[0]), ETHER_ADDR_LEN);
  outArpHeader->arp_sip = srcIp;
  memcpy(outArpHeader->arp_tha, &(destMac[0]), ETHER_ADDR_LEN);
  outArpHeader->arp_tip = destIp;

  // convert to Buffer
  Buffer outPacketBuffer(outPacket, outPacket + frameSize);

  // find interface and send arp reply packet
  const Interface* outIface = findIfaceByIp(srcIp);
  sendPacket(outPacketBuffer, outIface->name);
}

void
SimpleRouter::sendIcmpPacket(const Buffer& inPacketBuffer, const Interface* inIface, uint8_t type, uint8_t code) {
  uint8_t* inPacket = (uint8_t*) inPacketBuffer.data();
  // NOTE: length of icmp packet maybe not equal to `sizeof(ethernet_hdr) + sizeof(ip_header) + sizeof(icmp_header)`
  size_t frameSize = inPacketBuffer.size();
  uint8_t* outPacket = new uint8_t[frameSize];
  memcpy(outPacket, inPacket, frameSize);
  // inPacket
  ethernet_hdr* inEthernetHeader = (ethernet_hdr*) inPacket;
  ip_hdr* inIpHeader = (ip_hdr*) (inPacket + sizeof(ethernet_hdr));
  // outPacket
  ethernet_hdr* outEthernetHeader = (ethernet_hdr*) outPacket;
  ip_hdr* outIpHeader = (ip_hdr*) (outPacket + sizeof(ethernet_hdr));
  icmp_hdr* outIcmpHeader = (icmp_hdr*) (outPacket + sizeof(ethernet_hdr) + sizeof(ip_hdr));

  // fill in ethernet header
  memcpy(outEthernetHeader->ether_shost, inEthernetHeader->ether_dhost, ETHER_ADDR_LEN);
  memcpy(outEthernetHeader->ether_dhost, inEthernetHeader->ether_shost, ETHER_ADDR_LEN);

  // fill in ip header
  outIpHeader->ip_ttl = 64;
  outIpHeader->ip_p = ip_protocol_icmp;
  if (type == 0) { // icmp echo reply
    outIpHeader->ip_dst = inIpHeader->ip_src;
    outIpHeader->ip_src = inIpHeader->ip_dst;
  }
  else { // icmp packet indicating errors
    outIpHeader->ip_dst = inIpHeader->ip_src;
    outIpHeader->ip_src = inIface->ip;
  }
  outIpHeader->ip_sum = 0;
  outIpHeader->ip_sum = cksum(outIpHeader, sizeof(ip_hdr));

  // fill in icmp header
  outIcmpHeader->icmp_type = type;
  outIcmpHeader->icmp_code = code;
  outIcmpHeader->icmp_sum = 0;
  outIcmpHeader->icmp_sum = cksum(outIcmpHeader, inIpHeader->ip_len - sizeof(ip_hdr));

  Buffer outPacketBuffer(outPacket, outPacket + frameSize);
  sendPacket(outPacketBuffer, inIface->name);
  delete outPacket;
}

void
SimpleRouter::sendIcmpT3Packet(const Buffer& inPacketBuffer, const Interface* inIface, uint8_t type, uint8_t code) 
{ 
  uint8_t* inPacket = (uint8_t*) inPacketBuffer.data();
  const size_t frameSize = sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr);
  uint8_t outPacket[frameSize];
  memcpy(outPacket, inPacket, frameSize);
  // inPacket
  ethernet_hdr* inEthernetHeader = (ethernet_hdr*) inPacket;
  ip_hdr* inIpHeader = (ip_hdr*) (inPacket + sizeof(ethernet_hdr));
  // outPacket
  ethernet_hdr* outEthernetHeader = (ethernet_hdr*) outPacket;
  ip_hdr* outIpHeader = (ip_hdr*) (outPacket + sizeof(ethernet_hdr));
  icmp_t3_hdr* outIcmpHeader = (icmp_t3_hdr*) (outPacket + sizeof(ethernet_hdr) + sizeof(ip_hdr));
  
  // fill in ethernet header
  memcpy(outEthernetHeader->ether_shost, inEthernetHeader->ether_dhost, ETHER_ADDR_LEN);
  memcpy(outEthernetHeader->ether_dhost, inEthernetHeader->ether_shost, ETHER_ADDR_LEN);

  // fill in ip header
  outIpHeader->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
  outIpHeader->ip_ttl = 64;
  outIpHeader->ip_p = ip_protocol_icmp;
  outIpHeader->ip_dst = inIpHeader->ip_src;
  outIpHeader->ip_src = inIface->ip;
  outIpHeader->ip_sum = 0;
  outIpHeader->ip_sum = cksum(outIpHeader, sizeof(ip_hdr));

  // fill in icmp header
  outIcmpHeader->icmp_type = type;
  outIcmpHeader->icmp_code = code;
  outIcmpHeader->unused = 0;
  memcpy(outIcmpHeader->data, inIpHeader, ICMP_DATA_SIZE);
  outIcmpHeader->icmp_sum = 0;
  outIcmpHeader->icmp_sum = cksum(outIcmpHeader, sizeof(icmp_t3_hdr));

  Buffer outPacketBuffer(outPacket, outPacket + frameSize);
  sendPacket(outPacketBuffer, inIface->name);
}


//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {

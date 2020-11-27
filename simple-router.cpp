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

void handleArpPacket(const Buffer& packetBuffer, const Interface* inIface) {
  uint8_t* packet = packetBuffer.data();
  arp_hdr* arpHeader = (arp_hdr*) (packet + sizeof(ethernet_hdr));

  /* sanity check */

  // check packet size
  if (packetBuffer.size() < sizeof(ethernet_hdr) + sizeof(arp_hdr)) {
    std::cerr << "Received packet, but size is less than arp minimum, ignoring" << std::endl;      
    return;
  }

  // check hardware type, protocol type, opcode
  if (arpHeader->arp_hrd != arp_hrd_ethernet || arpHeader->arp_pro != ethertype_ip ||
      arpHeader->arp_op != arp_op_request || arpHeader->arp_op != arp_op_reply) {
    std::cerr << "Received arp packet, but hardware type, protocol type or operator code is unknown, ignoring" << std::endl;
    return;
  }

  Buffer arpTargetMac(arpHeader->arp_tha, arpHeader->arp_tha + ETHER_ADDR_LEN);
  Buffer arpSourceMac(arpHeader->arp_sha, arpHeader->arp_sha + ETHER_ADDR_LEN);

  /* handle arp request/reply */

  if (arpHeader->arp_op == arp_op_request) {
    // examine destination hardware address(target mac address)
    if (!isBroadcastMac(arpTargetMac)) {
      std::cerr << "Received arp request packet, but target mac address is not broadcasted one, ignoring" << std::endl;
      return;
    }

    /* add request info to arp cache */
    entry = m_arp.lookup(ipHeader->ip_src);
    if (!entry) {
      m_arp.insertArpEntry(arpSourceMac, arpHeader->arp_sip);  
    }
    
    /* make response */
    const size_t frameSize = sizeof(arp_hdr) + sizeof(ethernet_hdr);
    uint8_t frameRaw[frameSize];

    // fill in ethernet header
    ethernet_hdr* frameEthernetHeader = (ethernet_hdr*)frameRaw;
    memcpy(frameEthernetHeader->ether_dhost, arpHeader->sha, ETHER_ADDR_LEN);
    memcpy(frameEthernetHeader->ether_shost, &(inIface->addr[0]), ETH_ADDR_LEN);
    frameEthernetHeader->ether_type = ethertype_arp;

    // fill in arp header
    arp_hdr* frameArpHeader = (arp_hdr*)(frameRaw + sizeof(ethernet_hdr));
    frameArpHeader->arp_hrd = arp_hrd_ethernet;
    frameArpHeader->arp_pro = ethertype_ip;
    frameArpHeader->arp_hln = 0x06;
    frameArpHeader->arp_pln = 0x04;
    frameArpHeader->arp_op = arp_op_reply;
    memcpy(frameArpHeader->arp_sha, &(inIface->addr[0]), ETHER_ADDR_LEN);
    frameArpHeader->arp_sip = inIface->ip;
    memcpy(frameArpHeader->arp_tha, arpHeader->arp_sha, ETHER_ADDR_LEN);
    frameArpHeader->arp_tip = arpHeader->arp_tip;

    // convert to buffer
    Buffer frame(frameRaw, frameRaw + frameSize);

    // send arp reply packet
    sendPacket(frame, inIface->name);
    return;
  }
  else if (arpHeader->arp_op == arp_op_reply) {
    // check destination hardware address(target mac address)
    if (!isRouterMac(arpTargetMac, inIface)) {
      std::cerr << "Received arp reply packet, but target mac address is not router's one, ignoring" << std::endl;
      return;
    }

    /* add request info to arp cache */
    // ! maybe need to check entry existence before adding too!
    std::shared_ptr<ArpRequest> request = m_arp.insertArpEntry(arpSourceMac, arpHeader->arp_sip);  

    /* send all packets attached to the arp request */

    for (auto it = request.packets.begin(); it != request.packets.end(); it++) {
      uint8_t* packetRaw = it->packet.data();
      ethernet_hdr* ethernetHeader = (ethernet_hdr*) (packetRaw);
      memcpy(ethernetHeader->ether_dhost, arpHeader->arp_sha, ETHER_ADDR_LEN);
      
      sendPacket(it->packet, it->iface);
    }

    /* remove the arp request from request queue maintained by m_arp*/

    m_arp.removeRequest(request);
  }
}

void handleIcmpPacket(const Buffer& packetBuffer, const Interface* inIface) {
  return;
}

void handleNormalIpPacket(const Buffer& packetBuffer, const Interface* inIface) {
  /* look up the arp cache table */
  std::shared_ptr<ArpEntry> arpEntry = m_arp.lookup(ipHeader->ip_dst);
  if (arpEntry) { // find successfully
    
  }

  /* add an arp request to queue maintained by m_arp*/


  /* send an arp request(broadcast) */

  return;
}

void handleIpPacket(const Buffer& packetBuffer, const Interface* inIface) {
  uint8_t* packet = packetBuffer.data();
  ethernet_hdr* ethernetHeader = (ethernet_hdr*) packet;
  ip_hdr* ipHeader = (ip_hdr*) (packet + sizeof(ethernet_hdr));
  icmp_hdr* icmpHeader = (icmp_hdr*) (packet + sizeof(ethernet_hdr) + sizeof(ip_hdr));

  /* sanity check packet */
  // check packet size
  if (packetBuffer.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)) {
    std::cerr << "Received ip packet, but size is less than ip minimum, ignoring" << std::endl;
    return;
  }

  // check checksum of packet
  uint16_t ipChecksum = ipHeader->checksum;
  ipHeader->checksum = 0;
  if (cksum(ipHeader, sizeof(ip_hdr)) != ipChecksum) {
    std::cerr << "Received icmp packet, but bit error happened because of checksum mismatch, ignoring" << std::endl;
    return;
  }

  // add received packet info to arp cache
  // !!!: add variable type
  entry = m_arp.lookup(ipHeader->ip_src);
  if (!entry) {
    Buffer mac(ethernetHeader->ether_shost, ethernetHeader->ether_shost + ETHER_ADDR_LEN);
    m_arp.insertArpEntry(mac, ipHeader->ip_src);
  }
  
  // TODO: check if ttl <= 0, and send an icmp "time exceeding" packet
  if (ipHeader->ttl <= 0) {
    std::cerr << "Received icmp packet, but time exceeding, send this signal" << std::endl;
    sendIcmpT3Packet(packetBuffer, inIface, 11, 0);
    return;
  }

  // destination ip address is targeted to router,
  // which indicates an *icmp* packet
  if (ipHeader->ip_dst == iface->ip) {  // ? do other interfaces of router count?

    // check packet size
    if (packetBuffer.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr)) {
      std::cerr << "Received icmp packet, but size is less than icmp minimum, ignoring" << std::endl;
      return;
    }

    // TODO: check if packet isn't an icmp echo request, and send an icmp "unreachable port or host" packet
    if (ipHeader->ip_p != ip_protocol_icmp || icmpHeader->icmp_type != 8) {
      std::cerr << "Received icmp packet, but protocol data is not icmp or packet is not echo request, send this signal" << std::endl;
      sendIcmpT3Packet(packetBuffer, inIface, 3, 3);
      return;
    }
    // send echo reply to the echo request(received packet)
    sendIcmpPacket(packet, inIface, 0, 0);
  }

  // destination ip address is not targeted to router,
  // which indicates a normal ip packet
  else {
    RoutingTableEntry entry
    handleNormalIpPacket(packetBuffer, iface);
  }
}

void sendIcmpPacket(const Buffer& inPacketBuffer, const Interface* inIface, uint8_t type, uint8_t code) {
  uint8_t* inPacket = inPacketBuffer.data();
  const size_t frameSize = sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr);
  uint8_t outPacket[frameSize];
  memcpy(outPacket, inPacket, frameSize);
  // inPacket
  ethernet_hdr* inEthernetHeader = (ethernet_hdr*) inPacket;
  ip_hdr* inIpHeader = (ip_hdr*) (inPacket + sizeof(ethernet_hdr));
  // outPacket
  ethernet_hdr* outEthernetHeader = (ethernet_hdr*) outPacket;
  ip_hdr* outIpHeader = (ip_hdr*) (outPacket + sizeof(ethernet_hdr));
  icmp_hdr* outIcmpHeader = (icmp_hdr*) (outPacket + sizeof(ethernet_hdr) + sizeof(ip_hdr));

  // fill in ethernet header
  memcpy(outEthernetHeader->ether_shost, inIcmpHeader->ether_dhost, ETHER_ADDR_LEN);
  memcpy(outEthernetHeader->ether_dhost, inIcmpHeader->ether_shost, ETHER_ADDR_LEN);

  // fill in ip header
  outIpHeader->ip_len = sizeof(ip_hdr) + sizeof(icmp_t3_hdr);
  outIpHeader->ip_ttl = 64;
  outIpHeader->ip_p = ip_protocol_icmp;
  outIpHeader->checksum = 0;
  outIpHeader->checksum = cksum(outIpHeader, sizeof(ip_hdr));

  // fill in icmp header
  outIcmpHeader->icmp_type = type;
  outIcmpHeader->icmp_code = code;
  outIcmpHeader->checksum = 0;
  outIcmpHeader->checksum = cksum(outIcmpHeader, sizeof(ip_t3_hdr));

  Buffer outPacketBuffer(outPacket, outPacket + frameSize);
  sendPacket(outPacketBuffer, inIface->name);
}

void sendIcmpT3Packet(const Buffer& inPacketBuffer, const Interface* inIface, uint8_t type, uint8_t code) {
  uint8_t* inPacket = packetBuffer.data();
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
  memcpy(outEthernetHeader->ether_shost, inIcmpHeader->ether_dhost, ETHER_ADDR_LEN);
  memcpy(outEthernetHeader->ether_dhost, inIcmpHeader->ether_shost, ETHER_ADDR_LEN);

  // fill in ip header
  outIpHeader->ip_len = sizeof(ip_hdr) + sizeof(icmp_t3_hdr);
  outIpHeader->ip_ttl = 64;
  outIpHeader->ip_p = ip_protocol_icmp;
  outIpHeader->checksum = 0;
  outIpHeader->checksum = cksum(outIpHeader, sizeof(ip_hdr));

  // fill in icmp header
  outIcmpHeader->icmp_type = type;
  outIcmpHeader->icmp_code = code;
  outIcmpHeader->unused = 0;
  memcpy(outIcmpHeader->data, inIpHeader, ICMP_DATA_SIZE);
  outIcmpHeader->checksum = 0;
  outIcmpHeader->checksum = cksum(outIcmpHeader, sizeof(ip_t3_hdr));

  Buffer outPacketBuffer(outPacket, outPacket + frameSize);
  sendPacket(outPacketBuffer, inIface->name);
}

// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL IN

  // examine packet size(preliminary judgment)
  if (packet.size() < sizeof(ethernet_hdr)) {
    std::cerr << "Received packet, but size is less than ethernet minimum, ignoring" << std::endl;
    return;
  }

  uint8_t* frame = packet.data();
  ethernet_hdr* ethernetHeader = (ethernet_hdr*) frame;

  Buffer etherTargetMac(ethernetHeader->ether_dhost, ethernetHeader->ether_dhost + ETHER_ADDR_LEN);
  Buffer etherSourceMac(ethernetHeader->ether_shost, ethernetHeader->ether_shost + ETHER_ADDR_LEN);
  if (!isBroadcastMac(etherTargetMac) || !isRouterMac(etherTargetMac, iface)) {
    std::cerr << "Received packet, but target mac address in ethernet header is unknown, ignoring" << std::endl;
    return;
  }

  // handle packet according to its type(arp or ipv4)
  uint8_t* datagram = frame + sizeof(ethernet_hdr);
  if (ethernetHeader->ether_type == ethertype_arp) {
    arp_hdr* arpHeader = (arp_hdr*) datagram;

    // arp req/rep travels between two close nodes,
    // so mac addresses in ethernet header are equal to ones in arp header
    Buffer arpTargetMac(arpHeader->arp_tha, arpHeader->arp_tha + ETHER_ADDR_LEN);
    Buffer arpSourceMac(arpHeader->arp_sha, arpHeader->arp_sha + ETHER_ADDR_LEN);
    if (etherTargetMac != arpTargetMac or etherSourceMac != arpSourceMac) {
      std::cerr << "Received arp packet, mac addresses in ethernet header are not equal to ones in arp header, ignoring" << std::endl;
      return;
    }

    // destination ip address must be targeted to router,
    // otherwise router doesn't have to make any response
    if (arpHeader->arp_tip != iface->ip) {
      return;
    }

    handleArpPacket(packet, iface);
  } 
  else if (ethernet_hdr->ether_type == ethertype_ip) {
    ip_hdr* ipHeader = (ip_hdr*)datagram;
    
    handleIpPacket(packet, iface);
  } 
  else {
    std::cerr << "Received packet, but ether type is unknown, ignoring" << std::endl;
    return;
  }
}
//////////////////////////////////////////////////////////////////////////
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

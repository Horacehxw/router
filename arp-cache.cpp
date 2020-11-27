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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "core/protocol.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

void 
handleArpRequest(const std::shared_ptr<ArpRequest>& request) {
  time_point now = steady_clock::now();
  if (now - request.timeSent > seconds(1)) {
    if (request.nTimesSent >= MAX_SENT_TIME) {
      // TODO: send icmp host unreachable to source addr of all pkts waiting on this request
      // TODO: cache remove_request(request)
      removeRequest(request);
    } else {
      // TODO: send arp request
      const Interface* sIface = m_router.findIfaceByName(request.packets[0].iface);
      if (sIface == nullptr) {
        std::cout << "`handleArpRequest` error, packet has the interface the router does not have" << std::endl;
        return;
      }
      const Buffer broadcastMac(6, 0xff);

      const size_t frameSize = sizeof(arp_hdr) + sizeof(ethernet_hdr);
      uint8_t frameRaw[frameSize];

      // fill in ethernet header
      ethernet_hdr* ethernetHeader = (ethernet_hdr*)frameRaw;
      memcpy(ethernetHeader->ether_dhost, &(broadcastMac[0]), ETHER_ADDR_LEN);
      memcpy(ethernetHeader->ether_shost, &(sIface->addr[0]), ETH_ADDR_LEN);
      ethernetHeader->ether_type = ethertype_arp;

      // fill in arp header
      arp_hdr* arpHeader = (arp_hdr*)(frameRaw + sizeof(ethernet_hdr));
      arpHeader.arp_hrd = arp_hrd_ethernet;
      arpHeader.arp_pro = ethertype_ip;
      arpHeader.arp_hln = 0x06;
      arpHeader.arp_pln = 0x04;
      arpHeader.arp_op = arp_op_request;
      memcpy(arpHeader.arp_sha, &(sIface->addr[0]), ETHER_ADDR_LEN);
      arpHeader.arp_sip = sIface->ip;
      memcpy(arpHeader.arp_tha, &(broadcastMac[0]), ETHER_ADDR_LEN);
      arpHeader.arp_tip = request.ip;

      // convert to Buffer type
      Buffer frame(frameRaw, frameRaw + frameSize);

      // send frame
      m_router.sendPacket(frame, sIface->name);

      // update request info
      now = steady_clock::now();
      request->timeSent = now;
      request->nTimesSent++;
    }
  }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  // TODO: 重构！
  // handle arp requests
  for (const auto& request :m_arpRequests) {
    handleArpRequest(request);
  }

  // handle cache entries
  for (auto it = m_cacheEntries.begin(); it != m_cacheEntries.end(); ) {
    if (!entry->isValid) {
      it = m_cacheEntries.erase(it);
    } else {
      it++;
    }
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
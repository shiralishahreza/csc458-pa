#pragma once

#include "address.hh"
#include "arp_message.hh"
#include "ethernet_frame.hh"
#include "ipv4_datagram.hh"

#include <iostream>
#include <list>
#include <optional>
#include <queue>
#include <unordered_map>
#include <utility>

// A "network interface" that connects IP (the internet layer, or network layer)
// with Ethernet (the network access layer, or link layer).

// This module is the lowest layer of a TCP/IP stack
// (connecting IP with the lower-layer network protocol,
// e.g. Ethernet). But the same module is also used repeatedly
// as part of a router: a router generally has many network
// interfaces, and the router's job is to route Internet datagrams
// between the different interfaces.

// The network interface translates datagrams (coming from the
// "customer," e.g. a TCP/IP stack or router) into Ethernet
// frames. To fill in the Ethernet destination address, it looks up
// the Ethernet address of the next IP hop of each datagram, making
// requests with the [Address Resolution Protocol](\ref rfc::rfc826).
// In the opposite direction, the network interface accepts Ethernet
// frames, checks if they are intended for it, and if so, processes
// the the payload depending on its type. If it's an IPv4 datagram,
// the network interface passes it up the stack. If it's an ARP
// request or reply, the network interface processes the frame
// and learns or replies as necessary.
class NetworkInterface
{
private:
  // Ethernet (known as hardware, network-access, or link-layer) address of the interface
  EthernetAddress ethernet_address_;

  // IP (known as Internet-layer or network-layer) address of the interface
  Address ip_address_;

  // Structure representing an ARP table entry
  struct ARP_Entry {
    EthernetAddress eth_addr; // The Ethernet address associated with an IP address
    size_t ttl;               // Time-to-live value for this ARP table entry
  };
  // ARP Table: A mapping from IP addresses to ARP table entries
  std::unordered_map<uint32_t, ARP_Entry> arp_table_{};
  // Default Time-To-Live value for ARP table entries (30 seconds)
  const size_t arp_entry_default_ttl_ = 30000;
  
  // A map to keep track of when ARP replies are expected, with associated timeouts
  // The map holds IP addresses and the time until an ARP reply is expected for each
  std::unordered_map<uint32_t, size_t> waiting_arp_response_ip_addr_{};
  // Default Time-To-Live value for waiting ARP replies (5 seconds).
  const size_t arp_response_default_ttl_ = 5000;
  
  // A list of IP datagrams that are awaiting ARP replies
  std::list<std::pair<Address, InternetDatagram>> waiting_arp_internet_datagrams_{};

  // Outbound queue of Ethernet frames ready for transmission
  std::queue<EthernetFrame> _frames_out{};

  //Helper Functions to handle IPv4 and ARP Ethernet frames respectively
  static std::optional<InternetDatagram> handle_IPv4_frame(const EthernetFrame& frame);
  std::optional<InternetDatagram> handle_arp_frame(const EthernetFrame& frame);


  //Helper Function to construct an ARP message
  ARPMessage construct_arp_message(uint16_t opcode, 
                                  const EthernetAddress &target_eth_addr,
                                  uint32_t target_ip_addr);  
  //Helper Function to construct an Ethernet frame                                
  EthernetFrame construct_ethernet_frame(const EthernetAddress &dst_addr, 
                                        uint16_t type, 
                                        const std::vector<Buffer> &payload);
                                               

public:
  // Construct a network interface with given Ethernet (network-access-layer) and IP (internet-layer)
  // addresses
  NetworkInterface( const EthernetAddress& ethernet_address, const Address& ip_address );

  // Access queue of Ethernet frames awaiting transmission
  // Can be datagrams that are passed by IP layer, ARP requests to learn the MAC address of a 
  // next hop, and ARP replies to requests that are sent to us about our IP addresses.
  std::optional<EthernetFrame> maybe_send();

  // Sends an IPv4 datagram, encapsulated in an Ethernet frame (if it knows the Ethernet destination
  // address). Will need to use [ARP](\ref rfc::rfc826) to look up the Ethernet destination address
  // for the next hop.
  // ("Sending" is accomplished by making sure maybe_send() will release the frame when next called,
  // but please consider the frame sent as soon as it is generated.)
  void send_datagram( const InternetDatagram& dgram, const Address& next_hop );

  // Receives an Ethernet frame and responds appropriately.
  // If type is IPv4, returns the datagram.
  // If type is ARP request, learn a mapping from the "sender" fields, and send an ARP reply.
  // If type is ARP reply, learn a mapping from the "sender" fields.
  std::optional<InternetDatagram> recv_frame( const EthernetFrame& frame );

  // Called periodically when time elapses
  void tick( size_t ms_since_last_tick );
};

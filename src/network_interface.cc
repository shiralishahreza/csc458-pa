#include "network_interface.hh"
// already included in "network_interface.hh"
// #include "arp_message.hh"
// #include "ethernet_frame.hh"

using namespace std;

// ethernet_address: Ethernet (what ARP calls "hardware") address of the interface
// ip_address: IP (what ARP calls "protocol") address of the interface
NetworkInterface::NetworkInterface( const EthernetAddress& ethernet_address, const Address& ip_address )
  : ethernet_address_( ethernet_address ), ip_address_( ip_address )
{
  cerr << "DEBUG: Network interface has Ethernet address " << to_string( ethernet_address_ ) << " and IP address "
       << ip_address.ip() << "\n";
}

// dgram: the IPv4 datagram to be sent
// next_hop: the IP address of the interface to send it to (typically a router or default gateway, but
// may also be another host if directly connected to the same network as the destination)

// Note: the Address type can be converted to a uint32_t (raw 32-bit IP address) by using the
// Address::ipv4_numeric() method.
void NetworkInterface::send_datagram( const InternetDatagram& dgram, const Address& next_hop )
{
  // Conversion of next hop's IP address to a raw 32-bit representation, used in the ARP header
  const uint32_t next_hop_ip = next_hop.ipv4_numeric();
  // Search for the next hop's Ethernet address in the ARP table
  const auto &arp_iter = arp_table_.find(next_hop_ip);
  
  // Ethernet address not found in ARP table.
  if (arp_iter == arp_table_.end())
  {
    // If an ARP request for this IP address is not already pending,
    // broadcast an ARP request and add the IP address to the waiting list.
    // This prevents sending repeated ARP requests within a 5-second window.
    if (waiting_arp_response_ip_addr_.find(next_hop_ip) == waiting_arp_response_ip_addr_.end()) 
    {
      // Construction of an ARP Request message, setting the opcode to request and leaving the target MAC address empty.
      const ARPMessage arp_request = 
      construct_arp_message(ARPMessage::OPCODE_REQUEST, {}, next_hop_ip) ;
      // Construction of an Ethernet frame for the ARP request, setting the destination MAC to broadcast and the type to ARP.
      // The ARP message is serialized before being placed in the frame.
      const EthernetFrame eth_frame =
      construct_ethernet_frame(ETHERNET_BROADCAST, EthernetHeader::TYPE_ARP, serialize(arp_request));
      // Adding the Ethernet frame to the output queue, awaiting transmission.
      _frames_out.push(eth_frame);
      // Recording the current ARP request in the waiting list, with a TTL of 5 seconds.
      waiting_arp_response_ip_addr_[next_hop_ip] = arp_response_default_ttl_;
    }
    // Adding the datagram to the list of datagrams waiting for an ARP response.
    // Upon receiving the MAC address, this will be used to generate an Ethernet frame.
    waiting_arp_internet_datagrams_.emplace_back(next_hop, dgram);
  } 
  else 
  {
    // If the Ethernet address is found in the ARP table, create and send an Ethernet frame directly.
    // The destination MAC address is retrieved from the ARP table, and the type is set to IPv4.
    // The IP datagram is serialized before being placed in the frame.
    const EthernetFrame eth_frame =
    construct_ethernet_frame(arp_iter->second.eth_addr, EthernetHeader::TYPE_IPv4, serialize(dgram));
    // Adding the Ethernet frame to the output queue, awaiting transmission.
    _frames_out.push(eth_frame);
  }
}

// Processes an incoming Ethernet frame.
// If the frame is an IP packet or an ARP packet destined for this interface, it is processed accordingly.
optional<InternetDatagram> NetworkInterface::recv_frame( const EthernetFrame& frame )
{
  // Ignore frames that are neither destined for this interface's MAC address nor broadcast.
  if (frame.header.dst != ethernet_address_ && frame.header.dst != ETHERNET_BROADCAST){
    return std::nullopt;
  }
  // Determine the type of the Ethernet frame and handle accordingly.
  switch (frame.header.type) {
    case EthernetHeader::TYPE_IPv4:
      return handle_IPv4_frame(frame); //Process as an IPv4 frame.
    case EthernetHeader::TYPE_ARP:
      return handle_arp_frame(frame); //Process as an ARP frame.
    default:
      return std::nullopt; // Ignore other frame types.
  }
}


// Attempts to parse the payload of an Ethernet frame as an IPv4 datagram.
// If successful, returns the datagram; otherwise, returns an empty optional.
optional<InternetDatagram> NetworkInterface::handle_IPv4_frame(const EthernetFrame& frame) {
  Parser parser(frame.payload); // Create a Parser object from the Ethernet frame's payload.
  InternetDatagram datagram; //Create an instance of InternetDatagram to hold the parsed data.
  datagram.parse(parser); //Attempt to parse the payload as an IPv4 datagram.
  
  if (!parser.has_error()) {
      return datagram; // Parsing successful, return the datagram.
  } 
  return std::nullopt;  // Parsing failed, return an empty optional.
}

// Attempts to parse the payload of an Ethernet frame as an ARP message.
// If successful, processes the ARP message and updates ARP table and pending datagrams as necessary.
optional<InternetDatagram> NetworkInterface::handle_arp_frame(const EthernetFrame& frame) {
  Parser parser(frame.payload); // Create a Parser object from the Ethernet frame's payload.
  ARPMessage arp_msg; // Create an instance of ARPMessage to hold the parsed data.
  arp_msg.parse(parser);  // Attempt to parse the payload as an ARP message.

  if (!parser.has_error()) {
    // Extract useful information from the parsed ARP message.
    const uint32_t &src_ip_addr = arp_msg.sender_ip_address;
    const uint32_t &dst_ip_addr = arp_msg.target_ip_address;
    const EthernetAddress &src_eth_addr = arp_msg.sender_ethernet_address;
    const EthernetAddress &dst_eth_addr = arp_msg.target_ethernet_address;
    // Check if it's a valid ARP request directed to this interface.
    const bool is_valid_arp_request =
    (arp_msg.opcode == ARPMessage::OPCODE_REQUEST && dst_ip_addr == ip_address_.ipv4_numeric());
    // Check if it's a valid ARP reply in response to a previous request made by this interface.
    const bool is_valid_arp_reply = 
    (arp_msg.opcode == ARPMessage::OPCODE_REPLY && dst_eth_addr == ethernet_address_);
    
    if(is_valid_arp_request){
      // Respond to the valid ARP request.
      const ARPMessage arp_reply = 
      construct_arp_message(ARPMessage::OPCODE_REPLY, src_eth_addr, src_ip_addr) ;
      const EthernetFrame eth_frame =
      construct_ethernet_frame(src_eth_addr, EthernetHeader::TYPE_ARP, serialize(arp_reply));          
      _frames_out.push(eth_frame);
    }
    // If we received a valid ARP request or reply, update the ARP table and process pending datagrams.
    if(is_valid_arp_request || is_valid_arp_reply){
    // Update ARP Table
    arp_table_[src_ip_addr] = {src_eth_addr, arp_entry_default_ttl_};
    // Find and resend IP datagrams that were waiting for this ARP reply.
    for (auto iter = waiting_arp_internet_datagrams_.begin(); iter != waiting_arp_internet_datagrams_.end();/* nop */) { 
      if (iter->first.ipv4_numeric() == src_ip_addr) {
        //Resend IP packet again
        send_datagram(iter->second, iter->first);
        //Romove IP pack after send_datagram()
        iter = waiting_arp_internet_datagrams_.erase(iter);
      } 
      else{
        ++iter;
      }
    }
    // Delete corresponding entry in waiting_arp_response_ip_addr_
    waiting_arp_response_ip_addr_.erase(src_ip_addr);
    }
    // ARP frames do not result in IP datagrams being delivered to higher layers.
    return std::nullopt; 
  } 
  // If failed to parse ARP message, return null
  return std::nullopt; 
  
}

// ms_since_last_tick: the number of milliseconds since the last call to this method
void NetworkInterface::tick( const size_t ms_since_last_tick )
{
    // Delete expired ARP entry
    for (auto iter = arp_table_.begin(); iter != arp_table_.end(); /* nop */) {
        // If one entry expires, erase it
        if (iter->second.ttl <= ms_since_last_tick){
          iter = arp_table_.erase(iter);
        }
        // If one entry is not expired yet, subtract the ms_since_last_tick from TTL
        else {
          iter->second.ttl -= ms_since_last_tick;
          ++iter;
        }
    }
    // Remove the expired pending ARP reply entry
    for (auto iter = waiting_arp_response_ip_addr_.begin(); iter != waiting_arp_response_ip_addr_.end(); /* nop */) {
      // If one entry expires
      if (iter->second <= ms_since_last_tick) {
        uint32_t expired_ip = iter->first;
        // Remove the expired IP from the waiting_arp_response_ip_addr_
        iter = waiting_arp_response_ip_addr_.erase(iter);
        // Remove packets waiting for that IP from waiting_arp_internet_datagrams_
        waiting_arp_internet_datagrams_.remove_if([expired_ip](const auto& pair) {
          return pair.first.ipv4_numeric() == expired_ip;
        });
      } 
      // If one entry is not expired yet, subtract the ms_since_last_tick from TTL
      else {
        iter->second -= ms_since_last_tick;
        ++iter;
      }
    }
}

// Access queue of Ethernet frames awaiting transmission
optional<EthernetFrame> NetworkInterface::maybe_send()
{
  //If the queue is NOT empty
  if (!_frames_out.empty()) {
    // Get the oldest frame
    EthernetFrame frame = std::move(_frames_out.front());  
    // Remove it from the queue
    _frames_out.pop();  
    // Return the frame
    return frame;  
  } 
  
  // Return an empty optional if the queue is empty
  return std::nullopt;  
  
}

// A helper function to construct an ARP message with the specified parameters.
ARPMessage NetworkInterface::construct_arp_message(uint16_t opcode, 
                                                  const EthernetAddress &target_eth_addr,
                                                  uint32_t target_ip_addr)  
{
  ARPMessage arp_msg;
  arp_msg.opcode = opcode;  //OPCode: ARPMessage::OPCODE_REQUEST or ARPMessage::OPCODE_REPLY
  arp_msg.sender_ethernet_address = ethernet_address_;  //Sender MAC address
  arp_msg.sender_ip_address = ip_address_.ipv4_numeric(); //Sender IP address
  arp_msg.target_ethernet_address = target_eth_addr;  //Target MAC address, empty if it's a request
  arp_msg.target_ip_address = target_ip_addr;//Target IP address, next hop ip
  return arp_msg;
}

// A helper function to construct an Ethernet frame with the specified parameters.
EthernetFrame NetworkInterface::construct_ethernet_frame(const EthernetAddress &dst_addr, 
                                                        uint16_t type, 
                                                        const std::vector<Buffer> &payload)
{
  EthernetFrame eth_frame;
  //Broadcast MAC address if it's an ARP request, otherwise destination MAC address
  eth_frame.header.dst = dst_addr;  
  eth_frame.header.src = ethernet_address_; //Source MAC address
  eth_frame.header.type = type; //Frame type, EthernetHeader::TYPE_ARP or TYPE_IPv4
  eth_frame.payload = payload;  //Serialized data
  return eth_frame;
}



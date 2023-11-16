#include "arp_message.hh"
#include "ethernet_header.hh"
#include "ipv4_datagram.hh"
#include "network_interface_test_harness.hh"

#include <cstdlib>
#include <iostream>
#include <random>

using namespace std;

EthernetAddress random_private_ethernet_address()
{
  EthernetAddress addr;
  for ( auto& byte : addr ) {
    byte = random_device()(); // use a random local Ethernet address
  }
  addr.at( 0 ) |= 0x02; // "10" in last two binary digits marks a private Ethernet address
  addr.at( 0 ) &= 0xfe;

  return addr;
}

InternetDatagram make_datagram( const string& src_ip, const string& dst_ip ) // NOLINT(*-swappable-*)
{
  InternetDatagram dgram;
  dgram.header.src = Address( src_ip, 0 ).ipv4_numeric();
  dgram.header.dst = Address( dst_ip, 0 ).ipv4_numeric();
  dgram.payload.emplace_back( "hello" );
  dgram.header.len = static_cast<uint64_t>( dgram.header.hlen ) * 4 + dgram.payload.size();
  dgram.header.compute_checksum();
  return dgram;
}

ARPMessage make_arp( const uint16_t opcode,
                     const EthernetAddress sender_ethernet_address,
                     const string& sender_ip_address,
                     const EthernetAddress target_ethernet_address,
                     const string& target_ip_address )
{
  ARPMessage arp;
  arp.opcode = opcode;
  arp.sender_ethernet_address = sender_ethernet_address;
  arp.sender_ip_address = Address( sender_ip_address, 0 ).ipv4_numeric();
  arp.target_ethernet_address = target_ethernet_address;
  arp.target_ip_address = Address( target_ip_address, 0 ).ipv4_numeric();
  return arp;
}

EthernetFrame make_frame( const EthernetAddress& src,
                          const EthernetAddress& dst,
                          const uint16_t type,
                          vector<Buffer> payload )
{
  EthernetFrame frame;
  frame.header.src = src;
  frame.header.dst = dst;
  frame.header.type = type;
  frame.payload = std::move( payload );
  return frame;
}

int main()
{
  try {
    {
      const EthernetAddress local_eth = random_private_ethernet_address();
      const EthernetAddress remote_eth1 = random_private_ethernet_address();
      const EthernetAddress remote_eth2 = random_private_ethernet_address();
      NetworkInterfaceTestHarness test {
        "different ARP mappings are independent", local_eth, Address( "10.0.0.1", 0 ) };

      // first ARP mapping
      test.execute( ReceiveFrame {
        make_frame( remote_eth1,
                    ETHERNET_BROADCAST,
                    EthernetHeader::TYPE_ARP,
                    serialize( make_arp( ARPMessage::OPCODE_REQUEST, remote_eth1, "10.0.0.5", {}, "10.0.0.1" ) ) ),
        {} } );
      test.execute( ExpectFrame { make_frame(
        local_eth,
        remote_eth1,
        EthernetHeader::TYPE_ARP,
        serialize( make_arp( ARPMessage::OPCODE_REPLY, local_eth, "10.0.0.1", remote_eth1, "10.0.0.5" ) ) ) } );
      test.execute( ExpectNoFrame {} );

      test.execute( Tick { 15000 } );

      // second ARP mapping
      test.execute( ReceiveFrame {
        make_frame( remote_eth2,
                    ETHERNET_BROADCAST,
                    EthernetHeader::TYPE_ARP,
                    serialize( make_arp( ARPMessage::OPCODE_REQUEST, remote_eth2, "10.0.0.19", {}, "10.0.0.1" ) ) ),
        {} } );
      test.execute( ExpectFrame { make_frame(
        local_eth,
        remote_eth2,
        EthernetHeader::TYPE_ARP,
        serialize( make_arp( ARPMessage::OPCODE_REPLY, local_eth, "10.0.0.1", remote_eth2, "10.0.0.19" ) ) ) } );
      test.execute( ExpectNoFrame {} );

      test.execute( Tick { 10000 } );

      // outgoing datagram to first destination
      const auto datagram = make_datagram( "5.6.7.8", "13.12.11.10" );
      test.execute( SendDatagram { datagram, Address( "10.0.0.5", 0 ) } );

      // outgoing datagram to second destination
      const auto datagram2 = make_datagram( "100.99.98.97", "4.10.4.10" );
      test.execute( SendDatagram { datagram2, Address( "10.0.0.19", 0 ) } );

      test.execute(
        ExpectFrame { make_frame( local_eth, remote_eth1, EthernetHeader::TYPE_IPv4, serialize( datagram ) ) } );
      test.execute(
        ExpectFrame { make_frame( local_eth, remote_eth2, EthernetHeader::TYPE_IPv4, serialize( datagram2 ) ) } );
      test.execute( ExpectNoFrame {} );

      test.execute( Tick { 5010 } );

      // outgoing datagram to second destination (mapping still alive)
      const auto datagram3 = make_datagram( "150.140.130.120", "144.144.144.144" );
      test.execute( SendDatagram { datagram3, Address( "10.0.0.19", 0 ) } );
      test.execute(
        ExpectFrame { make_frame( local_eth, remote_eth2, EthernetHeader::TYPE_IPv4, serialize( datagram3 ) ) } );
      test.execute( ExpectNoFrame {} );

      // outgoing datagram to second destination (mapping has expired)
      const auto datagram4 = make_datagram( "244.244.244.244", "3.3.3.3" );
      test.execute( SendDatagram { datagram4, Address( "10.0.0.5", 0 ) } );
      test.execute( ExpectFrame { make_frame(
        local_eth,
        ETHERNET_BROADCAST,
        EthernetHeader::TYPE_ARP,
        serialize( make_arp( ARPMessage::OPCODE_REQUEST, local_eth, "10.0.0.1", {}, "10.0.0.5" ) ) ) } );
      test.execute( ExpectNoFrame {} );
    }
  } catch ( const exception& e ) {
    cerr << e.what() << endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

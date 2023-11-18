#include "router.hh"
#include "arp_message.hh"
#include "network_interface_test_harness.hh"
#include "router_common.hh"

#include <iostream>
#include <list>
#include <random>
#include <unordered_map>
#include <utility>

using namespace std;

void network_simulator()
{
  const string green = "\033[32;1m";
  const string normal = "\033[m";

  cerr << green << "Constructing network." << normal << "\n";

  Network network;

  cout << green << "\n\nTesting two hosts on the same network (dm42 to dm43)..." << normal << "\n\n";
  {
    auto dgram_sent = network.host( "dm42" ).send_to( network.host( "dm43" ).address() );
    dgram_sent.header.ttl--;
    dgram_sent.header.compute_checksum();
    network.host( "dm43" ).expect( dgram_sent );
    network.simulate();
  }

  cout << "\n\n\033[32;1mCongratulations! All datagrams were routed successfully.\033[m\n";
}

int main()
{
  try {
    network_simulator();
  } catch ( const exception& e ) {
    cerr << "\n\n\n";
    cerr << "\033[31;1mError: " << e.what() << "\033[m\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

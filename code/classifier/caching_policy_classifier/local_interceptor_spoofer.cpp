#include "local_interceptor_spoofer.h"
#include <thread>
#include "interceptor.h"
#include "random_generator.h"
#include "format.h"
using namespace Tins;

void LocalInterceptorSpoofer::start(boost::asio::io_service& io_service, response_generator_t response_generator)
{
	auto interceptor_thread = std::thread([&, response_generator]()
	{
		PacketSender sender;
		Interceptor interceptor;

		// All packets will be sent through the default interface
		//auto default_interface = Tins::NetworkInterface::default_interface();
		//auto device = default_interface.name();
		//sender.default_interface(device);

		interceptor.start([&](const Tins::PDU& pdu)
		{
			Tins::PDU* packet = pdu.clone();
			io_service.dispatch([&, packet](void)
			{
				// Do something with pdu
			//auto packet = &pdu;
				EthernetII eth = packet->rfind_pdu<EthernetII>();
				IP ip = packet->rfind_pdu<IP>();
				UDP udp = ip.rfind_pdu<UDP>();
				DNS dns = udp.rfind_pdu<RawPDU>().to<DNS>();

				//std::cout << fmt::format("Detected request id={0:d}, from=({1},{2:d}), to=({3},{4:d}), for {5}\n",
				//	dns.id(), ip.src_addr().to_string(), udp.sport(), ip.dst_addr().to_string(), udp.dport(), dns.queries().front().dname())
				//	<< std::endl;

				// TODO Modify dns here
				boost::optional<DNS> response = response_generator(dns); // TODO use spoofer...
				if (response)
				{
					// Build our packet
					auto pkt = /*EthernetII(eth.src_addr(), eth.dst_addr()) /*/
						IP(ip.src_addr(), ip.dst_addr()) /
						UDP(udp.sport(), udp.dport()) /
						response.get();
					IP ip_res = pkt.rfind_pdu<IP>();
					ip_res.id(random_uint16());

					// Send packet
					sender.send(pkt);
					std::cout << fmt::format("Sent spoof id={0:d}, from=({1},{2:d}), to=({3},{4:d})\n",
						dns.id(), ip.dst_addr().to_string(), udp.dport(), ip.src_addr().to_string(), udp.sport())
						<< std::endl;
				}

				delete packet;
			});
		});
	});
	interceptor_thread.detach();
}
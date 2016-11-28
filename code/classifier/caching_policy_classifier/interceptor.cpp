#include "interceptor.h"
#include "format.h"

using namespace Tins;

Interceptor::Interceptor()
{
}


Interceptor::~Interceptor()
{
}

bool Interceptor::spoofer_callback(callback_t callback, const PDU &pdu)
{
	EthernetII eth = pdu.rfind_pdu<EthernetII>();
	IP ip = pdu.rfind_pdu<IP>();
	UDP udp = ip.rfind_pdu<UDP>();
	DNS dns = udp.rfind_pdu<RawPDU>().to<DNS>();
	if (dns.type() == DNS::QUERY)
	{
		callback(pdu);
	}

	return true;
}

void Interceptor::start(callback_t callback)
{
	auto default_interface = Tins::NetworkInterface::default_interface();
	std::string device = default_interface.name();
	std::string my_ip = default_interface.addresses().ip_addr.to_string();

	auto conf = SnifferConfiguration{};
	conf.set_filter(fmt::format("udp and dst port 53 and src host {0} and not dst host {0}", my_ip));
	//conf.set_filter(fmt::format("udp and dst port 53", my_ip));
	conf.set_promisc_mode(true);
#ifdef WIN32
	conf.set_timeout(10);	//TODO: enable clumsy
#else
	conf.set_timeout(1);	//TODO: was -1
#endif
	Sniffer sniffer(device, conf);
	sniffer.sniff_loop([this, &callback](const PDU &pdu)
	{
//		std::cout << "A" << std::endl;
		return spoofer_callback(callback, pdu); 
	});
}
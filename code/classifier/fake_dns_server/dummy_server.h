#pragma once

#include <string>
#include "dns_server.h"

class DummyServer : public DnsServer
{
public:
	DummyServer(boost::asio::io_service& io_service, std::string fake_ip, std::string domain, std::string spf);
	~DummyServer();

private:
	std::string fake_ip_;
	std::string domain_;
	std::string spf_;
};


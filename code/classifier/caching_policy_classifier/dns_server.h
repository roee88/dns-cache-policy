#pragma once

#include <memory>
#include <functional>
#include <vector>
#include <boost/asio.hpp>
#include <boost/optional.hpp>
#include "delegator.h"
#include "tins.h"
#include "manager.h"

class DnsServer
{
public:
	DnsServer(boost::asio::io_service& io_service, const std::string& master_ip, uint16_t master_port);
	~DnsServer();
	
	void start();
	void register_manager(std::shared_ptr<Manager> manager);
	void unregister_manager(std::string identifier);

private:
	void do_receive();
	void handle_incoming(boost::system::error_code ec, std::size_t length);
	void from_delegator(uint8_t* data, std::size_t len);


	bool receiving;
	std::map<std::string, std::shared_ptr<Manager>> handlers_;
	std::unique_ptr<Delegator> delegator_;
	boost::asio::ip::udp::socket socket_;
	boost::asio::ip::udp::endpoint sender_endpoint_;
	boost::asio::deadline_timer deadline_;

	enum { max_length = 4096 };
	uint8_t data_[max_length];
};
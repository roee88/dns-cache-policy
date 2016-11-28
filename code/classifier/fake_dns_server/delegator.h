#pragma once

#include <string>
#include <cstdint>
#include <functional>
#include <boost/asio.hpp>

class Delegator
{
public:
	typedef std::function<void(uint8_t*, std::size_t)> incoming_callback_t;

	Delegator(boost::asio::io_service& io_service, const std::string& master_ip, uint16_t master_port, incoming_callback_t callback);
	~Delegator();

	void do_receive();
	void send(uint8_t* data, std::size_t length);

private:
	incoming_callback_t incoming_callback_;
	boost::asio::ip::udp::socket socket_;
	enum { max_length = 4096 };
	uint8_t data_[max_length];
};
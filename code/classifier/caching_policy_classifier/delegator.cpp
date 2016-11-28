#include "delegator.h"

Delegator::Delegator(boost::asio::io_service& io_service, const std::string & master_ip, uint16_t master_port, incoming_callback_t callback)
	: socket_(io_service), incoming_callback_(callback)
{
	socket_.connect(boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(master_ip), master_port));
	do_receive();
}

Delegator::~Delegator()
{
	socket_.close();
}

void Delegator::do_receive()
{
	socket_.async_receive(
		boost::asio::buffer(data_, max_length), [this](boost::system::error_code ec, std::size_t bytes_recvd) 
		{
			if (!ec && bytes_recvd > 0)
			{
				if (incoming_callback_)
				{
					// Note: parameters are only valid on callback function scope!
					incoming_callback_(data_, bytes_recvd);
				}
			}

			if (ec != boost::asio::error::operation_aborted)
			{
				// next packet
				do_receive();
			}
		}
	);
}

void Delegator::send(uint8_t* data, std::size_t length)
{
	socket_.send(boost::asio::buffer(data, length));
}

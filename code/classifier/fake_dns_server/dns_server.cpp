#include "dns_server.h"

#include <vector>
#include <boost/algorithm/string/predicate.hpp>
#include "make_unique.h"

DnsServer::DnsServer(boost::asio::io_service & io_service, const std::string& master_ip, uint16_t master_port)
	: socket_(io_service), deadline_(io_service), receiving(false)
{
	socket_.open(boost::asio::ip::udp::v6());
	socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v6(), 53));
	//boost::asio::ip::v6_only v6_only_option(false);
	//socket_.set_option(v6_only_option);

	delegator_ = std::make_unique<Delegator>(io_service, master_ip, master_port, [this](uint8_t* data, std::size_t len)
	{
		from_delegator(data, len);
	});
}

void DnsServer::start()
{
	do_receive();
}

DnsServer::~DnsServer()
{
}

void DnsServer::register_handler(response_generator_t handler)
{
	handlers_.push_back(handler);
}

void DnsServer::do_receive()
{
	if (receiving)
	{
		throw std::runtime_error{ "do_receive called but already receiving!" };
	}

	receiving = true;
	socket_.async_receive_from(boost::asio::buffer(data_, max_length), sender_endpoint_, [this](boost::system::error_code ec, std::size_t bytes_recvd)
	{
		receiving = false;
		try
		{
			handle_incoming(ec, bytes_recvd);
		}
		catch (Tins::malformed_packet& e)
		{
			std::cerr << e.what() << std::endl;
			do_receive();
		}
	});
}

void DnsServer::handle_incoming(boost::system::error_code ec, std::size_t length)
{
	// Check for valid buffer
	if (ec || length == 0)
	{
		std::cout << "ec " << ec.message() << std::endl;
		throw Tins::malformed_packet();
	}

	// Get dns request
	auto request = Tins::DNS(reinterpret_cast<uint8_t*>(&data_[0]), length);
	if (request.type() == Tins::DNS::RESPONSE)
	{
		std::cout << "is response" << std::endl;
		throw Tins::malformed_packet();
	}
	if (request.queries().size() != 1)
	{
		std::cout << "more than 1 query" << std::endl;
		throw Tins::malformed_packet();
	}

	//	If a handler callback generates a response we are done
	for (auto handler : handlers_)
	{
		auto response = handler(request);
		if (response)
		{
			// JIC
			response->type(Tins::DNS::RESPONSE);
			response->id(request.id());

			// Send spoofed response
			auto response_payload = response->serialize();
			socket_.async_send_to(boost::asio::buffer(response_payload.data(), response_payload.size()), sender_endpoint_,
				[this](boost::system::error_code /*ec*/, std::size_t /*bytes_sent*/) {
				do_receive();
			}
			);

			return; // handled
		}
	}

	// Delegate to master
	deadline_.expires_from_now(boost::posix_time::seconds(5));
	deadline_.async_wait([this](const boost::system::error_code&)
	{
		// No response from master within 5 seconds
		if (deadline_.expires_at() <= boost::asio::deadline_timer::traits_type::now())
		{
			std::cerr << "warning: no response from master within 5 seconds" << std::endl;
			do_receive();
		}
	});
	delegator_->send(data_, length);
}

void DnsServer::from_delegator(uint8_t * data, std::size_t len)
{
	// got it
	deadline_.cancel();

	//  send to client
	auto response_payload = std::vector<uint8_t>(data, data + len);
	socket_.async_send_to(boost::asio::buffer(response_payload.data(), response_payload.size()), sender_endpoint_, [this](boost::system::error_code /*ec*/, std::size_t /*bytes_sent*/) {
		// next request
		do_receive();
	});
}

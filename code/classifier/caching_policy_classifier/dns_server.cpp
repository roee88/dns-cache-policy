#include "dns_server.h"

#include <vector>
#include <boost/algorithm/string/predicate.hpp>
#include "make_unique.h"

DnsServer::DnsServer(boost::asio::io_service & io_service, const std::string& master_ip, uint16_t master_port)
	: socket_(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 53)), deadline_(io_service), receiving(false)
{
	delegator_ = std::make_unique<Delegator>(io_service, master_ip, master_port, [this](uint8_t* data, std::size_t len)
	{
		from_delegator(data, len);
	});
}

void DnsServer::start()
{
	socket_.get_io_service().dispatch([this] {
		do_receive();
	});	
}

DnsServer::~DnsServer()
{
	//std::cout << "DnsServer::~DnsServer()" << std::endl;
}

void DnsServer::register_manager(std::shared_ptr<Manager> manager)
{
	socket_.get_io_service().dispatch([this, manager] {
		handlers_.insert({ manager->identifier(), manager });
	});
}

void DnsServer::unregister_manager(std::string identifier)
{
	socket_.get_io_service().dispatch([this, identifier] {
		handlers_.erase(identifier);
	});
}

void DnsServer::do_receive()
{
	if (receiving)
	{
		throw std::runtime_error{ "do_receive called but already receiving!" };
		//std::cerr << "DnsServer: do_receive called but already receiving" << std::endl;
		//return;
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
			std::cerr << "DnsServer: " << e.what() << std::endl;
			do_receive();
		}
		catch (std::runtime_error& e)
		{
			std::cerr << "DnsServer: " << e.what() << std::endl;
			do_receive();
		}
	});
}

void DnsServer::handle_incoming(boost::system::error_code ec, std::size_t length)
{
	// Check for valid buffer
	if (ec || length == 0)
	{
		throw std::runtime_error{ ec.message() };
	}

	// Get dns request
	auto request = Tins::DNS(reinterpret_cast<uint8_t*>(&data_[0]), length);
	if (request.type() == Tins::DNS::RESPONSE)
	{
		throw std::runtime_error{"We got a response but expected request"};
	}
	if (request.queries().size() != 1)
	{
		throw std::runtime_error{ "More than 1 question in DNS request" };
	}

	//	If a handler callback generates a response we are done
	for (auto handler : handlers_)
	{
		auto response = handler.second->spoof_response(request);
		if (response)
		{
			// JIC
			response->type(Tins::DNS::RESPONSE);
			response->id(request.id());

			// Send spoofed response
			auto response_payload = response->serialize();
			socket_.async_send_to(boost::asio::buffer(response_payload.data(), response_payload.size()), sender_endpoint_,
				[this](boost::system::error_code ec, std::size_t bytes_sent) {
					if (ec != boost::asio::error::operation_aborted)
					{
						do_receive();
					}
				}
			);
			
			return; // handled
		}
	}

	// Delegate to master
	//deadline_.expires_from_now(boost::posix_time::seconds(1));
	//deadline_.async_wait([this](const boost::system::error_code&)
	//{
	//	// No response from master within a second
	//	if (deadline_.expires_at() <= boost::asio::deadline_timer::traits_type::now())
	//	{
	//		do_receive();
	//	}
	//});
	delegator_->send(data_, length);
}

void DnsServer::from_delegator(uint8_t * data, std::size_t len)
{
	// got it
	//deadline_.cancel();

	//  send to client
	auto response_payload = std::vector<uint8_t>(data, data + len);
	socket_.async_send_to(boost::asio::buffer(response_payload.data(), response_payload.size()), sender_endpoint_,
		[this](boost::system::error_code ec, std::size_t bytes_sent) {
			// next request
			if (ec != boost::asio::error::operation_aborted && !receiving)
			{
				do_receive();
			}
		}
	);
}

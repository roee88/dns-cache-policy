#include "direct_query_issuer.h"
#include "random_generator.h"
#include "make_unique.h"

#ifdef _DEBUG
#include <iostream>
#include "tins.h"
#endif

//void print_bytes(const unsigned char *data, size_t dataLen) {
//	std::cout << std::setfill('0');
//	for (size_t i = 0; i < dataLen; ++i) {
//		std::cout << std::hex << std::setw(2) << (int)data[i];
//		std::cout << (((i + 1) % 16 == 0) ? "\n" : " ");
//	}
//	std::cout << std::endl;
//}

DirectQueryIssuer::DirectQueryIssuer(boost::asio::io_service & io_service,
	const std::string & target_ip, uint16_t target_port)
{
	delegator_ = std::make_unique<Delegator>(io_service, target_ip, target_port,
		[this](uint8_t* data, std::size_t len) {
			Tins::DNS pkt{ data, len };
			//#ifdef _DEBUG
			//std::cout << "Got packet\n" << Tins::ExtDNS::to_string(pkt) << std::endl;
			//print_bytes(data, len);
	//#endif
			if (completed_callback_ && pkt.id() == request_id_)
			{
				request_id_ = 0;
				completed_callback_(pkt);
			}
	});
}

DirectQueryIssuer::~DirectQueryIssuer()
{
}

void DirectQueryIssuer::query(Tins::DNS::Query query)
{
	request_id_ = random_uint16();

	Tins::DNS dns;
	dns.recursion_desired(1);
	dns.authenticated_data(1);
	dns.id(request_id_);
	dns.add_query(query);
	auto payload = dns.serialize();

	delegator_->send(payload.data(), payload.size());
}

//DirectQueryIssuer::DirectQueryIssuer(boost::asio::io_service & io_service,
//	const std::string & target_ip, uint16_t target_port) : io_service_(io_service), target_ip_(target_ip), target_port_(target_port), sock_(nullptr)
//{
//}
//
//DirectQueryIssuer::~DirectQueryIssuer()
//{
//	if (sock_ != nullptr)
//	{
//		delete sock_;
//		sock_ = nullptr;
//	}
//}
//
//void DirectQueryIssuer::do_receive(uint16_t request_id)
//{
//        sock_->async_receive(boost::asio::buffer(data_, max_length), [this, request_id](boost::system::error_code ec, std::size_t bytes_recvd)
//        {
//                if (!ec && bytes_recvd > 0)
//                {
//                        Tins::DNS pkt{ data_, bytes_recvd };
//                        if (pkt.id() == request_id)
//                        {
//				if(completed_callback_)
//				{
//					std::cout << "Got packet\n"<< Tins::ExtDNS::to_string(pkt) << std::endl;
//        	                        completed_callback_(pkt);
//				}
//                        }
//			else
//			{
//				do_receive(request_id);
//			}
//                }
//        });
//
//}
//
//void DirectQueryIssuer::query(Tins::DNS::Query query)
//{
//	const auto request_id = random_uint16();
//
//	Tins::DNS dns;
//	dns.recursion_desired(1);
//	dns.authenticated_data(1);
//	dns.id(request_id);
//	dns.add_query(query);
//	auto payload = dns.serialize();
//
//	if (sock_ != nullptr)
//	{
//		delete sock_;
//		sock_ = nullptr;
//	}
//	sock_ = new boost::asio::ip::udp::socket{ io_service_ };
//	sock_->open(boost::asio::ip::udp::v4());
////	socket_.open(boost::asio::ip::udp::v6());
//	sock_->bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), random_uint16()));
//
//	// Connect
//	sock_->connect(boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(target_ip_), target_port_));
//
//	// Send
//	sock_->send(boost::asio::buffer(payload.data(), payload.size()));
//
//	// Receive
//	do_receive(request_id);
//}

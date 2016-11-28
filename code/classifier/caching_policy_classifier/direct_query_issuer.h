#pragma once

#include "query_issuer.h"

#include <memory>
#include <string>
#include <cstdint>
#include <boost/asio.hpp>
#include "delegator.h"
#include "tins.h"

class DirectQueryIssuer : public QueryIssuer
{
public:
	DirectQueryIssuer(boost::asio::io_service& io_service, const std::string & target_ip, uint16_t target_port);
	DirectQueryIssuer(const DirectQueryIssuer&) = delete;
	DirectQueryIssuer& operator=(DirectQueryIssuer const&) = delete;
	virtual ~DirectQueryIssuer();

	void query(Tins::DNS::Query query) override;

private:
	uint16_t request_id_;
	std::unique_ptr<Delegator> delegator_;

	//void do_receive(uint16_t request_id);
	//boost::asio::ip::udp::socket* sock_;
	//boost::asio::io_service& io_service_;
	//const std::string & target_ip_;
	//const uint16_t target_port_;
	//enum { max_length = 4096 };
	//uint8_t data_[max_length];

};

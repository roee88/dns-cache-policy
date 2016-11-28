#include "dummy_server.h"
#include <boost/algorithm/string.hpp>


DummyServer::DummyServer(boost::asio::io_service& io_service,
	std::string fake_ip, std::string domain, std::string spf)
	: DnsServer(io_service, "127.0.0.1", 1053), fake_ip_(fake_ip), domain_(domain), spf_(spf)
{
	register_handler([this](Tins::DNS& request) -> boost::optional<Tins::DNS>
	{
		auto query = request.queries().front();
		auto dname = query.dname();
		//std::string domain = query.dname().substr(1 + query.dname().find('.'));

		if ((domain_ == "any" || boost::ends_with(dname, domain_))
			&& (spf_ == "any" || boost::starts_with(dname, spf_)))
		{
			if (query.type() == Tins::DNS::A)
			{
				// Generate response
				auto response = Tins::DNS();
				response.type(Tins::DNS::RESPONSE);
				response.id(request.id());
				response.recursion_desired(request.recursion_desired());
				response.authoritative_answer(1);
				response.add_query(query);
				response.rcode(0);
				response.add_answer(Tins::DNS::Resource(dname, fake_ip_, Tins::DNS::A, query.query_class(), 15));
				return response;
			}
			else if (query.type() == Tins::DNS::AAAA)
			{
				// Generate response
				auto response = Tins::DNS();
				response.type(Tins::DNS::RESPONSE);
				response.id(request.id());
				response.recursion_desired(request.recursion_desired());
				response.authoritative_answer(1);
				response.add_query(query);
				response.rcode(0);
				return response;
			}
			//else if (query.type() == Tins::DNS::NS)
			//{
			//	// Generate response
			//	auto response = Tins::DNS();
			//	response.type(Tins::DNS::RESPONSE);
			//	response.id(request.id());
			//	response.recursion_desired(request.recursion_desired());
			//	response.authoritative_answer(1);
			//	response.add_query(query);
			//	response.rcode(0);
			//	response.add_answer(Tins::DNS::Resource(dname, "vm27.lab.sit.cased.de", Tins::DNS::NS, query.query_class(), 15));
			//	return response;
			//}

		}
		return boost::none;
	});

	start();
}


DummyServer::~DummyServer()
{
}
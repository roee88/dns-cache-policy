#include "test_step_query_dns.h"
#include <sstream>
#include <boost/algorithm/string.hpp>    

TestStepQueryDNS::TestStepQueryDNS(run_query_method_t run_query_method)
	: run_query_method_(run_query_method), response_(boost::none)
{
	completed_callback_ = nullptr;
}

std::string TestStepQueryDNS::to_string() const
{
	std::stringstream result;
	result << "DNS query " << query_.dname() << std::endl;
	return result.str();
}

void TestStepQueryDNS::run(io_service & io_service, completed_callback_t callback)
{
	completed_callback_ = callback;
	run_query_method_(query(), std::bind(&TestStepQueryDNS::on_query_completed, shared_from_this(), std::placeholders::_1));
}

void TestStepQueryDNS::stop()
{
	completed_callback_ = nullptr;
}

void TestStepQueryDNS::on_query_completed(boost::optional<Tins::DNS> response)
{
	if (response)
	{
		//if (boost::algorithm::to_lower_copy(query().dname()) != boost::algorithm::to_lower_copy(response->queries().front().dname()))
		//{
		//	std::cout << boost::algorithm::to_lower_copy(query().dname()) << " != " << boost::algorithm::to_lower_copy(response->queries().front().dname());
		//}
		response_ = response;
	}

	if (completed_callback_)
	{
		completed_callback_(*this);
		completed_callback_ = nullptr;
	}
}

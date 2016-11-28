#include "test_step_dns.h"
#include <sstream>

TestStepSpoofDNS::TestStepSpoofDNS(run_query_method_t run_query_method)
	: TestStepQueryDNS(run_query_method), rcode_(0), ra_(0), aa_(0), ad_(0)
{
}

std::string TestStepSpoofDNS::to_string() const
{
	std::stringstream result;

	result << "DNS" << std::endl;

	auto add_resources = [&](const Tins::DNS::resources_type& from) {
		for (auto answer : from)
		{
			result << "\t\t" 
				<< answer.dname() << " " 
				<< answer.data() << " " 
				<< Tins::ExtDNS::to_string((Tins::DNS::QueryType)answer.type()) 
				<< std::endl;
		}
	};

	result << "\tqueries" << std::endl;
	result << "\t\t" << query_.dname() << std::endl;

	if (!answers_.empty())
	{
		result << "\tanswers" << std::endl;
		add_resources(answers_);
	}
	if (!authorities_.empty())
	{
		result << "\tauthorities" << std::endl;
		add_resources(authorities_);
	}
	if (!additionals_.empty())
	{
		result << "\tadditionals" << std::endl;
		add_resources(additionals_);
	}

	return result.str();
}

bool TestStepSpoofDNS::want_spoof_at_count(int current) const
{
	return current == 1;
}

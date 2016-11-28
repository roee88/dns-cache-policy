#include "test_step_verify_by_query.h"


TestStepVerifyByQuery::TestStepVerifyByQuery(run_query_method_t run_query_method)
	: TestStepQueryDNS(run_query_method)
{
}

std::string TestStepVerifyByQuery::to_string() const
{
	return std::string(" verification by ") + TestStepQueryDNS::to_string();
}

bool TestStepVerifyByQuery::verify()
{
	if (!response())
		return false;;

	for (auto answer : response()->answers())
	{
		if (answer.type() == Tins::DNS::A)
		{
			//std::cout << "data " << answer.data() << " expected " << expected_ip_ << std::endl;
			if (answer.dname() == query().dname() && answer.data() == expected_ip_)
			{
				return true;
			}
		}
	}
	
	return false;
}

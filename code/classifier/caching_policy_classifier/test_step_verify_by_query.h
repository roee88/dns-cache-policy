#pragma once
#include "test_step_query_dns.h"

class TestStepVerifyByQuery : public TestStepQueryDNS
{
public:
	TestStepVerifyByQuery(run_query_method_t run_query_method);
	virtual ~TestStepVerifyByQuery() = default;
	virtual std::string to_string() const override;

	//
	bool verify();
	void set_expected_ip(std::string expected_ip) { expected_ip_ = expected_ip; }

private:
	std::string expected_ip_;

};

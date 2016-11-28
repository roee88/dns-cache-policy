#pragma once
#include <boost/optional.hpp>
#include "test_step_query_dns.h"
#include "query_issuer.h"
#include "tins.h"

class TestStepSpoofDNS :public TestStepQueryDNS
{
public:	
	TestStepSpoofDNS(run_query_method_t run_query_method);
	virtual ~TestStepSpoofDNS() = default;

	// Pretty print
	std::string to_string() const override;

	// Data
	Tins::DNS::resources_type& answers() { return answers_; }
	Tins::DNS::resources_type& authorities() { return authorities_; }
	Tins::DNS::resources_type& additionals() { return additionals_; }

	// Getters
	uint8_t rcode() const { return rcode_; }
	uint8_t ra() const { return ra_; }
	uint8_t aa() const { return aa_; }
	uint8_t ad() const { return ad_; }
	
	// Setters
	void rcode(uint8_t val) { rcode_ = val; }
	void ra(uint8_t val) { ra_ = val; }
	void aa(uint8_t val) { aa_ = val; }
	void ad(uint8_t val) { ad_ = val; }

	// Spoof count
	bool want_spoof_at_count(int current) const;

private:
	Tins::DNS::resources_type answers_;
	Tins::DNS::resources_type authorities_;
	Tins::DNS::resources_type additionals_;
	uint8_t rcode_;
	uint8_t ra_;
	uint8_t aa_;
	uint8_t ad_;
};
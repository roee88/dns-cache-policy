#pragma once
#include <map>
#include <string>
#include <vector>
#include "manager.h"
#include "dns_payload_set.h"
#include "test.h"
#include "test_step_query_dns.h"
#include "test_step_verify_by_query.h"
#include "test_step_dns.h"
#include "test_step_commands.h"
#include "tins.h"

class TestBuilder
{
public:
	TestBuilder(const oms_t& payloads);
	~TestBuilder();

	Test build_test_local(Manager& manager, std::string payload_name, std::string service_name);
	Test build_test_remote(Manager& manager, std::string payload_name, std::string service_name);

	void set_flags(uint8_t ra, uint8_t aa, uint8_t ad, uint8_t rcode);
	void set_mapping(std::map<std::string, std::vector<std::string>> mapping);

	std::shared_ptr<TestStepRunCommands> build_clear_cache_step(std::string service_name);

private:
	std::shared_ptr<TestStepQueryDNS> build_dns_query_step(Manager& manager, std::string dname, Tins::DNS::QueryType type);
	std::shared_ptr<TestStepSpoofDNS> build_dns_spoof_step(Manager& manager, std::string payload_name, uint32_t ttl);
	std::vector<std::shared_ptr<TestStepVerifyByQuery>> build_verify_steps(Manager& manager, std::string payload_name);

	std::map<std::string, std::vector<std::string>> mapping_;
	oms_t payloads_;
	uint8_t ra_;
	uint8_t aa_;
	uint8_t ad_;
	uint8_t rcode_;
};


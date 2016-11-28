#include "test_builder.h"
#include <boost/algorithm/string.hpp>
#include "format.h"
#include "test_step_commands.h"
#include "test_step_sleep.h"
#include "test_step_verify_by_query.h"
#include "command.h"
#include "random_generator.h"
#undef IN

using namespace std;
using namespace Tins;


/// <summary>
/// Extract variables from a string
/// </summary>
/// <param name="encoded">A string with variables.</param>
/// <returns>List of variables</returns>
vector<string> get_encoded_variables(string encoded)
{
	vector<string> variables;

	int pos = encoded.find("<", 0);
	while (pos != string::npos)
	{
		int end_pos = encoded.find(">", pos);
		if (end_pos == string::npos)
			throw std::runtime_error(fmt::format("invalid rule: {0} - missing '>'", encoded));
		variables.push_back(encoded.substr(pos + 1, end_pos - pos - 1));
		pos = encoded.find("<", pos + 1);
	}
	return variables;
}

/// <summary>
/// Automatic detection of variable value.
/// </summary>
/// <param name="mapping">The mapping.</param>
/// <param name="variable">The variable.</param>
/// <returns>True if value added to mapping</returns>
bool auto_detect_mapping(map<string, vector<string>>& mapping, const string& variable)
{
	// Already has value?
	if (mapping.find(variable) != mapping.end() && mapping.find(variable)->second.size() > 0)
		return true;

	// Subtitude rand with random string
	if (variable == "rand")
	{
		mapping["rand"].push_back(random_string(10));
	}

	// Subtitude verify with random string starting with "vrfy"
	else if (variable == "verify")
	{
		mapping["verify"].push_back(std::string("vrfy") + random_string(6));
	}

	// Automatically generate nameservers
	else if (boost::algorithm::ends_with(variable, "_ns"))
	{
		auto dname_var = variable.substr(0, variable.size() - 3);
		if (auto_detect_mapping(mapping, dname_var))
		{
			for (const auto& val : mapping[dname_var])
			{
				command(fmt::format("dig +short ns {0}", val), [&](const string& line) {
					string ovserved_ns = line;
					ovserved_ns.erase(std::remove(ovserved_ns.begin(), ovserved_ns.end(), '\n'), ovserved_ns.end());
					ovserved_ns.erase(ovserved_ns.size() - 1);
					std::cout << "automatically detected ns of " << val << ": " << ovserved_ns << std::endl;
					mapping[variable].push_back(ovserved_ns);
				});
			}
		}
	}

	// Automatically generate IP addresses
	else if (boost::algorithm::ends_with(variable, "_ip"))
	{
		auto dname_var = variable.substr(0, variable.size() - 3);
		if (auto_detect_mapping(mapping, dname_var))
		{
			for (const auto& val : mapping[dname_var])
			{
				command(fmt::format("dig +short {0}", val), [&](const string& line) {
					string ovserved_ip = line;
					ovserved_ip.erase(std::remove(ovserved_ip.begin(), ovserved_ip.end(), '\n'), ovserved_ip.end());
					std::cout << "automatically detected IP of " << val << ": " << ovserved_ip << std::endl;
					mapping[variable].push_back(ovserved_ip);
				});
			}
		}
	}

	return mapping.find(variable) != mapping.end() && mapping.find(variable)->second.size() > 0;
}

/// <summary>
/// Decode rule by subtituing variables with their concrete values.
/// </summary>
/// <param name="mapping">The variable mapping.</param>
/// <param name="encoded">The encoded rule.</param>
/// <returns></returns>
vector<string> decode_rule(map<string, vector<string>>& mapping, string encoded)
{
	vector<string> result;
	vector<string> variables = get_encoded_variables(encoded);
	string multi_var = "";

	string decoded = encoded;
	for (const auto& variable : variables)
	{
		std::vector<std::string> value;

		// No translation found
		if (mapping.find(variable) == mapping.end() || mapping.find(variable)->second.size() == 0)
		{
			if (!auto_detect_mapping(mapping, variable))
			{
				throw runtime_error(fmt::format("unknown variable {0}", variable));
			}
		}

		// Get value
		value = mapping.find(variable)->second;

		// Variable with multiple values
		if (value.size() > 1)
		{
			if (!multi_var.empty())
				throw runtime_error(fmt::format("{0} has more than one variable with many values", encoded));
			multi_var = variable;
		}
		// For normal variable just do the replace
		else
		{
			boost::replace_all(decoded, fmt::format("<{0}>", variable), value[0]);
		}
	}

	// add results for each value of the variable with multiple values
	if (!multi_var.empty())
	{
		auto value = mapping.find(multi_var);
		for (const auto& multi_var_translation : value->second)
		{
			string entry = decoded;
			boost::replace_all(entry, fmt::format("<{0}>", multi_var), multi_var_translation);
			result.push_back(entry);
		}
	}
	// or just add the single result otherwise
	else
	{
		result.push_back(decoded);
	}
	return result;
}

/// <summary>
/// Add resources from PayloadResource list to DNS::resources_type
/// </summary>
/// <param name="mapping">The variables mapping.</param>
/// <param name="from">From.</param>
/// <param name="to">To.</param>
/// <param name="ttl">The TTL value to use.</param>
void add_resources(map<string, vector<string>>& mapping, const vector<PayloadResource>& from, DNS::resources_type& to, uint32_t ttl)
{
	for (auto& answer : from)
	{
		auto keys = decode_rule(mapping, answer.key);
		auto values = decode_rule(mapping, answer.value);
		if (keys.size() > 1 && values.size() > 1)
		{
			if (keys.size() != values.size())
				throw runtime_error{ fmt::format("not supported: resource with #keys != #values and #keys > 1 and #values > 1") };

			for (size_t i = 0; i < keys.size(); ++i)
			{
				to.push_back({ keys[i], values[i], (uint16_t)ExtDNS::dns_qstring_to_type(answer.type), DNS::IN, ttl });
			}
		}
		else
		{
			for (auto& key : keys)
			{
				for (auto& value : values)
				{
					to.push_back({ key, value, (uint16_t)ExtDNS::dns_qstring_to_type(answer.type), DNS::IN, ttl });
				}
			}
		}
	}
};


/// <summary>
/// Initializes a new instance of the <see cref="TestBuilder"/> class.
/// </summary>
/// <param name="manager">The manager.</param>
TestBuilder::TestBuilder(const oms_t& payloads)
	: payloads_(payloads), ra_(0), aa_(0), ad_(0), rcode_(0)
{
}

/// <summary>
/// Set DNS flags to use.
/// </summary>
/// <param name="ra">The ra.</param>
/// <param name="aa">The aa.</param>
/// <param name="ad">The ad.</param>
/// <param name="rcode">The rcode.</param>
void TestBuilder::set_flags(uint8_t ra, uint8_t aa, uint8_t ad, uint8_t rcode)
{
	ra_ = ra;
	aa_ = aa;
	ad_ = ad;
	rcode_ = rcode;
}

/// <summary>
/// Set the variables mapping.
/// </summary>
/// <param name="mapping">The mapping.</param>
void TestBuilder::set_mapping(std::map<std::string, std::vector<std::string>> mapping)
{
	mapping_ = mapping;

	if (mapping_["refdomain"].empty())
	{
		mapping_["refdomain"] = mapping_["domain"];
	}

	if (mapping_["target_record"].empty())
	{
		mapping_["target_record"].push_back("www");
	}
}

/// <summary>
/// Finalizes an instance of the <see cref="TestBuilder"/> class.
/// </summary>
TestBuilder::~TestBuilder()
{
}

/// <summary>
/// Build a DNS query step.
/// </summary>
/// <param name="dname">The domain name.</param>
/// <param name="type">The type.</param>
/// <returns></returns>
std::shared_ptr<TestStepQueryDNS> TestBuilder::build_dns_query_step(Manager& manager, std::string dname, DNS::QueryType type)
{
	auto result = std::make_shared<TestStepQueryDNS>(std::bind(&Manager::send_dns_query, std::ref(manager), std::placeholders::_1, std::placeholders::_2));
	result->query().dname(dname);
	result->query().type(type);
	result->query().query_class(DNS::IN);
	return result;
}

/// <summary>
/// Build a verification steps list.
/// </summary>
/// <param name="payload_name">The OMS template name.</param>
/// <returns></returns>
std::vector<std::shared_ptr<TestStepVerifyByQuery>> TestBuilder::build_verify_steps(Manager& manager, std::string payload_name)
{
	std::vector<std::shared_ptr<TestStepVerifyByQuery>> steps;

	if (payloads_.find(payload_name) == payloads_.end())
		throw runtime_error{ "Unknown payload name" };
	Payload payload = payloads_[payload_name];

	for (auto verification_rule : payload.verification_rules)
	{
		istringstream iss(verification_rule);
		string domain_to_check;
		string expected_ip;
		iss >> domain_to_check >> expected_ip;

		// TODO: only testing first!!!
		auto domain_to_check_translated = decode_rule(mapping_, domain_to_check).front();
		auto expected_ip_translated = decode_rule(mapping_, expected_ip).front();

		auto step = std::make_shared<TestStepVerifyByQuery>(std::bind(&Manager::send_dns_query, std::ref(manager), std::placeholders::_1, std::placeholders::_2));
		step->query().dname(domain_to_check_translated);
		step->query().type(DNS::A);
		step->query().query_class(DNS::IN);
		step->set_expected_ip(expected_ip_translated);
		steps.push_back(step);
	}

	return steps;
}

/// <summary>
/// Build DNS spoofing step.
/// </summary>
/// <param name="payload_name">The OMS template name.</param>
/// <param name="ttl">The TTL value to use.</param>
/// <returns></returns>
std::shared_ptr<TestStepSpoofDNS> TestBuilder::build_dns_spoof_step(Manager& manager, std::string payload_name, uint32_t ttl)
{
	if (payloads_.find(payload_name) == payloads_.end())
		throw runtime_error{ "Unknown payload name" };
	Payload payload = payloads_[payload_name];

	auto result = std::make_shared<TestStepSpoofDNS>(std::bind(&Manager::send_dns_query, std::ref(manager), std::placeholders::_1, std::placeholders::_2));

	// Add query
	auto queries = decode_rule(mapping_, payload.query.dname);
	assert(queries.size() == 1);
	for (auto& query : queries)
	{
		result->query().dname(query);
		result->query().type(ExtDNS::dns_qstring_to_type(payload.query.type));
		result->query().query_class(DNS::IN);
	}

	// Add the other sections
	add_resources(mapping_, payload.answers, result->answers(), ttl);
	add_resources(mapping_, payload.authorities, result->authorities(), ttl);
	add_resources(mapping_, payload.additionals, result->additionals(), ttl);

	// Fix SOA records
	for (auto& auth : result->authorities())
	{
		if (auth.type() == DNS::SOA)
		{
			try
			{
				auth.data(ExtDNS::encode_soa_data(auth.data()));
			}
			catch (std::invalid_argument& e)
			{
				throw runtime_error(e.what());
			}
			catch (std::out_of_range& e)
			{
				throw runtime_error(e.what());
			}
		}
	}

	return result;
}

/// <summary>
/// Build clear cache step. Used only in local mode.
/// </summary>
/// <param name="service_name">The resolver application name (bind9, unbound or windns).</param>
/// <returns></returns>
std::shared_ptr<TestStepRunCommands> TestBuilder::build_clear_cache_step(std::string service_name)
{
	auto get_clear_cache_command = [&]() -> std::vector<std::string>
	{
		if (service_name == "bind9")
#ifdef WIN32
			return{ "rndc dumpdb - all", "net stop \"ISC BIND\"",  "net start \"ISC BIND\"" };
#else
			return{ "sudo rndc dumpdb - all", "sudo service bind9 restart" };
#endif
		if (service_name == "unbound")
			return{ "sudo unbound-control reload" };
		if (service_name == "windns")
			return{ "dnscmd . /clearcache" };
		throw runtime_error{ "unknown service name" };
	};

	return std::make_shared<TestStepRunCommands>(get_clear_cache_command());
}

/// <summary>
/// Build remote test.
/// </summary>
/// <param name="payload_name">The OMS template name.</param>
/// <param name="service_name">The resolver application name (bind9, unbound, windns or unknown).</param>
/// <returns>Newly created Test</returns>
Test TestBuilder::build_test_remote(Manager& manager, std::string payload_name, std::string service_name)
{
	Test test{
		fmt::format("{0} [RA={1:d}, AA={2:d}, AD={3:d}, RCODE={4:d}]",
		payload_name, ra_, aa_, ad_, rcode_)
	};

	// Get domain
	std::string domain = mapping_["domain"].front();
	if (boost::algorithm::starts_with(payload_name, "REF"))
		domain = mapping_["refdomain"].front();

	// Regenerate random parameters
	mapping_["rand"].clear();
	mapping_["rand"].push_back(random_string(10));
	mapping_["verify"].clear();
	mapping_["verify"].push_back(std::string("vrfy") + random_string(6));

	// Query "www.<domain>"
	for (const auto& target_record : mapping_["target_record"])
	{
		auto real_query = build_dns_query_step(manager, fmt::format("{0}.{1}", target_record, domain), DNS::QueryType::A);
		test.steps().push_back(real_query);
	}

	// Spoofing step
	auto fake_query = build_dns_spoof_step(manager, payload_name, 30);
	//auto fake_ttl = 2;
	//if ((service_name == "unknown" || service_name == "bind9") && boost::algorithm::starts_with(payload_name, "NS_NEW_"))
	//	fake_ttl += 10;
	//auto fake_query = build_dns_spoof_step(manager, payload_name, fake_ttl);
	fake_query->ra(ra_);
	fake_query->aa(aa_);
	fake_query->ad(ad_);
	fake_query->rcode(rcode_);
	test.steps().push_back(fake_query);

	// wait for cache syncrhonization
	test.steps().push_back(std::make_shared<TestStepSleep>(boost::posix_time::seconds(12)));
	//if ((service_name == "unknown" || service_name == "bind9") && boost::algorithm::starts_with(payload_name, "NS_NEW_"))
	//	test.steps().push_back(std::make_shared<TestStepSleep>(boost::posix_time::seconds(10)));

	// Verification step
	auto verification_steps = build_verify_steps(manager, payload_name);
	for (auto verification_step : verification_steps)
	{
		test.steps().push_back(verification_step);
	}

	// Wait enough time to clear all of our records from cache
	test.steps().push_back(std::make_shared<TestStepSleep>(boost::posix_time::seconds(20)));
	//test.steps().push_back(std::make_shared<TestStepSleep>(boost::posix_time::seconds(fake_ttl+1)));

	return test;
}


/// <summary>
/// Build local test.
/// </summary>
/// <param name="payload_name">The OMS template name.</param>
/// <param name="service_name">The resolver application name (bind9, unbound or windns).</param>
/// <returns>Newly created Test</returns>
Test TestBuilder::build_test_local(Manager& manager, std::string payload_name, std::string service_name)
{
	Test test{
		fmt::format("{0} [RA={1:d}, AA={2:d}, AD={3:d}, RCODE={4:d}]",
		payload_name, ra_, aa_, ad_, rcode_)
	};

	// Get domain
	std::string domain = mapping_["domain"].front();
	if (boost::algorithm::starts_with(payload_name, "REF"))
		domain = mapping_["refdomain"].front();

	// Clear cache
	test.steps().push_back(build_clear_cache_step(service_name));
	
	// Query TLDs TODO: needed?
	test.steps().push_back(build_dns_query_step(manager, "com", DNS::QueryType::NS));
	test.steps().push_back(build_dns_query_step(manager, "net", DNS::QueryType::NS));
	test.steps().push_back(build_dns_query_step(manager, "co.il", DNS::QueryType::NS));

	// Query "www.<domain>"
	auto real_query = build_dns_query_step(manager, fmt::format("www.{0}", domain), DNS::QueryType::A);
	test.steps().push_back(real_query);

	// TODO: needed?
    if(service_name == "unbound")
    {
        test.steps().push_back(std::make_shared<TestStepSleep>(boost::posix_time::seconds(1)));
    }

	//test.steps().push_back(std::make_shared<TestStepSleep>(boost::posix_time::seconds(2)));

	// Spoofing step
	auto fake_query = build_dns_spoof_step(manager, payload_name, 172800);
	fake_query->ra(ra_);
	fake_query->aa(aa_);
	fake_query->ad(ad_);
	fake_query->rcode(rcode_);
	test.steps().push_back(fake_query);

	// Wait a bit before verification on bind9
	if (service_name == "bind9")
	{
		test.steps().push_back(std::make_shared<TestStepSleep>(boost::posix_time::seconds(15)));
	}
	//test.steps().push_back(std::make_shared<TestStepSleep>(boost::posix_time::seconds(2)));

	// Verification step
	auto verification_steps = build_verify_steps(manager, payload_name);
	for (auto verification_step : verification_steps)
	{
		test.steps().push_back(verification_step);
	}

	return test;
}
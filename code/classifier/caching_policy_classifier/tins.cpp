#include "tins.h"
#include <stdio.h>
#include <ctype.h>
#include <string>
#include <cstdint>
#include <map>
#include <sstream>
#include "format.h"

using namespace std;
using namespace Tins;

string Tins::ExtDNS::to_string(DNS::QueryType type)
{
	switch (type)
	{
	case DNS::A:
		return "A";
	case DNS::AAAA:
		return "AAAA";
	case DNS::NS:
		return "NS";
	case DNS::SOA:
		return "SOA";
	case DNS::CNAME:
		return "CNAME";
	default:
		break;
	}
	return "UNKNOWN";
}

DNS::QueryType Tins::ExtDNS::dns_qstring_to_type(string type)
{
	if (type == "A")
		return DNS::A;
	if (type == "AAAA")
		return DNS::AAAA;
	if (type == "NS")
		return DNS::NS;
	if (type == "SOA")
		return DNS::SOA;
	if (type == "CNAME")
		return DNS::CNAME;
	throw runtime_error{ fmt::format("unknown type {0}", type) };
}

uint32_t parse_time(string time_str)
{
	static map<char, int> secs{ { 's', 1 },{ 'm', 60 },{ 'h',3600 },{ 'd',86400 },{ 'w',604800 } };

	char unit = ::tolower(time_str.back());
	if (secs.find(unit) != secs.end())
	{
		time_str.erase(time_str.end() - 1);
		return std::stoi(time_str) * secs[unit];
	}
	return std::stoi(time_str);
}

string Tins::ExtDNS::encode_soa_data(const string& soa_string)
{
	byte_array bytes;
	istringstream iss(soa_string);
	string value;

	// add mname and rname
	for (int i = 0; i < 2; ++i)
	{
		iss >> value;
		if (value.back() == '.')
			value.erase(value.end() - 1);

		string encoded_value = DNS::encode_domain_name(value);
		bytes.insert(bytes.end(), encoded_value.begin(), encoded_value.end());
	}
	int added = bytes.size();

	// prepare memory for time integers
	bytes.insert(bytes.end(), sizeof(uint32_t) * 5, 0);

	// add times
	for (int i = 0; i < 5; ++i)
	{
		iss >> value;
		uint32_t encoded_int = Endian::host_to_be(parse_time(value));
		std::memcpy(bytes.data() + added, &encoded_int, sizeof(uint32_t));
		added += sizeof(uint32_t);
	}

	return string(bytes.begin(), bytes.end());
}

std::string Tins::ExtDNS::to_string(const Tins::DNS& dns)
{
	stringstream result;

	auto add_resources = [&](const DNS::resources_type& from) {
		for (auto answer : from)
		{
			auto data = answer.data();
			//if (answer.type() == Tins::DNS::SOA)
			//{
			//	data.erase(std::remove_if(data.begin(), data.end(), 
			//		[](char c) {return isprint(c); }), data.end());
			//}

			result << "\t\t" << answer.dname() 
				<< " " << data 
				<< " " << Tins::ExtDNS::to_string((DNS::QueryType)answer.type())
				<< " " << answer.ttl() 
				<< endl;
		}
	};

	result << "\trcode " << (int)dns.rcode() << endl;

	result << "\tqueries" << endl;
	for (auto query : dns.queries())
	{
		result << "\t\t" << query.dname() << endl;
	}

	result << "\tanswers" << endl;
	add_resources(dns.answers());

	result << "\tauthorities" << endl;
	add_resources(dns.authority());

	result << "\tadditionals" << endl;
	add_resources(dns.additional());

	return result.str();

}

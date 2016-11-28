#pragma once

#include <string>
#include <map>
#include <vector>
#include "json11.hpp"

using namespace json11;

struct PayloadQuery
{
	std::string dname;
	std::string type;

	Json to_json() const {
		return Json::array{ dname, type }; 
	}

	void from_json(const Json::array& j) {
		dname = j[0].string_value(); 
		type = j[1].string_value(); 
	}
};

struct PayloadResource
{
	std::string key;
	std::string value;
	std::string type;

	Json to_json() const {
		return Json::array{ key, value, type }; 
	}

	void from_json(const Json::array& j) {
		key = j[0].string_value();
		value = j[1].string_value();
		type = j[2].string_value();
	}

};

struct Payload
{
	PayloadQuery query;
	std::vector<PayloadResource> answers;
	std::vector<PayloadResource> authorities;
	std::vector<PayloadResource> additionals;
	std::vector<std::string> verification_rules;

	Json to_json() const { return Json::array { query, answers, authorities, additionals, verification_rules}; }

	void from_json(const Json::array& j) {
		query.from_json(j[0].array_items());
		for (auto& item : j[1].array_items())
		{
			PayloadResource rr;
			rr.from_json(item.array_items());
			answers.push_back(rr);
		}
		for (auto& item : j[2].array_items())
		{
			PayloadResource rr;
			rr.from_json(item.array_items());
			authorities.push_back(rr);
		}
		for (auto& item : j[3].array_items())
		{
			PayloadResource rr;
			rr.from_json(item.array_items());
			additionals.push_back(rr);
		}
		for (auto& item : j[4].array_items())
		{
			verification_rules.push_back(item.string_value());
		}
	}
};

typedef std::map<std::string, Payload> oms_t;
oms_t getPayloads(const std::string& json_str);


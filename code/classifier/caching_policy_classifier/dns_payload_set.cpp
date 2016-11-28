#include "dns_payload_set.h"
#include <iostream>

oms_t getPayloads(const std::string& json_str)
{
	std::string err;
	auto json = Json::parse(json_str, err);
	if (!err.empty())
	{
		throw std::runtime_error{ err };
	}

	std::map<std::string, Payload> result;
	for (auto& item : json.object_items())
	{
		Payload payload;
		payload.from_json(item.second.array_items());
		result.insert({ item.first,  payload });
	}

	return result;
}
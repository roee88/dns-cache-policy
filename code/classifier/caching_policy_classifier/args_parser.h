#pragma once
#include <string>
#include <map>
#include <vector>
#include <boost/algorithm/string.hpp>

//static std::vector<std::string> get_payload_names_from_args(std::vector<std::string> args)
//{
//	std::vector<std::string> rules;
//	for (const auto& arg : args)
//	{
//		if (!arg.empty() && arg[0] == '-')
//		{
//			break;
//		}
//		rules.push_back(arg);
//	}
//	return rules;
//}

static std::map<std::string, std::vector<std::string>> get_args_mapping(std::vector<std::string> args)
{
	std::map<std::string, std::vector<std::string>> mapping;
	std::string current_variable;
	std::vector<std::string> current_value;

	auto add_to_mapping = [&]() {
		if (!current_variable.empty())
		{
			mapping.insert({ current_variable, current_value });
			current_variable = "";
			current_value.clear();
		}
	};

	for (const auto& arg : args)
	{
		if (!arg.empty() && arg[0] == '-')
		{
			add_to_mapping();
			current_variable = arg.substr(1);
		}
		else if (!current_variable.empty())
		{
			if (arg[0] == '\'' || arg[0] == '"')
			{
				//std::cout << arg.substr(1, arg.size() - 1) << endl;
				current_value.push_back(arg.substr(1, arg.size() - 1));
			}
			else
			{
				current_value.push_back(arg);
			}
		}
	}
	add_to_mapping();

	return mapping;
}

#pragma once

#include <string>

namespace Utils
{
	std::string detect_resolver_app(std::string target_ip, uint16_t target_port);
	std::string get_service_name(std::string resolver_app);
};


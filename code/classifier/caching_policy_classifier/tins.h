#pragma once

#include <string>
#undef IN
#include <tins/tins.h>

namespace Tins
{
	namespace ExtDNS
	{

		Tins::DNS::QueryType dns_qstring_to_type(std::string type);
		std::string encode_soa_data(const std::string& soa_string);
		std::string to_string(Tins::DNS::QueryType type);
		std::string to_string(const Tins::DNS& dns);

		enum RCode {
			NOERR = 0,
			NXDOMAIN = 3
		};
	}
}

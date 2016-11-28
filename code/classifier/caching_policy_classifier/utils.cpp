#include "utils.h"

#include <iostream>
#include "command.h"
#include "format.h"

namespace Utils
{
	std::string detect_resolver_app(std::string target_ip, uint16_t target_port)
	{
		std::string resolver_app = "unknown";;

		auto callback = [&resolver_app](const std::string& line)
		{
			if (line != "" && line != "\n")
			{
				resolver_app = line;
			}
		};

		auto cmd = fmt::format("fpdns -cs -p {1} {0}", target_ip, target_port);
		if (0 != command(cmd, callback))
		{
			resolver_app = "unknown";
		}

		return resolver_app;
	}

	std::string get_service_name(std::string resolver_app)
	{
		std::string service_name = "unknown";

		if (resolver_app.find("BIND") != std::string::npos)
		{
			service_name = "bind9";
		}
		else if (resolver_app.find("unbound") != std::string::npos)
		{
			service_name = "unbound";
		}
		else if (resolver_app.find("Windows") != std::string::npos)
		{
			service_name = "windns";
		}

		return service_name;
	}

}

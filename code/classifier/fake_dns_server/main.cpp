#include <string>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include "dummy_server.h"

namespace po = boost::program_options;

int main(int argc, char* argv[])
{
	po::options_description desc("Usage");
	desc.add_options()
		("help", "produce help message")
		("domain", po::value<std::string>()->default_value("any"), "Only spoof queries to this domain")
		("keyword", po::value<std::string>()->default_value("any"), "Only spoof queries starting with this keyword")
		("ip", po::value<std::string>()->default_value("6.6.6.6"), "Respond with fake answer giving this IP address")
		;

	po::variables_map opts;
	po::store(po::parse_command_line(argc, argv, desc), opts);

	try {
		po::notify(opts);
	}
	catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << "\n";
		return 1;
	}

	if (opts.count("help")) {
		std::cout << desc << "\n";
		return 1;
	}

	boost::asio::io_service io_service;

	std::string domain = opts["domain"].as<std::string>();
	std::string spf_keyword = opts["keyword"].as<std::string>();
	std::string fake_ip = opts["ip"].as<std::string>();	
	DummyServer server{ io_service, fake_ip, domain, spf_keyword};
	io_service.run();
	return 0;
}
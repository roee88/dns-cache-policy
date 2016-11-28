#include <memory>
#include <thread>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <streambuf>
#include <thread>
#include <future>

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>

#include "local_interceptor_spoofer.h"
#include "dns_server.h"
#include "manager.h"
#include "direct_query_issuer.h"
#include "random_generator.h"
#include "args_parser.h"

#include "test.h"
#include "test_builder.h"

#include "command.h"
#include "format.h"

#include "utils.h"
#include "tins.h"
#undef IN

#define LOCAL_HOST_ADDR "127.0.0.1"


bool is_resolver_alive(std::string target_ip, int target_port = 53)
{
	bool alive = false;
	command(fmt::format("dig +short +tries=1 @{0} google.com -p {1}", target_ip, target_port), [&](const std::string& line) {
		std::string ovserved_ip = line;
		ovserved_ip.erase(std::remove(ovserved_ip.begin(), ovserved_ip.end(), '\n'), ovserved_ip.end());
		if (ovserved_ip != "" && ovserved_ip[0] != ';')
			alive = true;
	});
	return alive;
}

bool is_valid_ipv4_address(std::string str)
{
	boost::system::error_code ec;
	boost::asio::ip::address::from_string(str, ec);
	if (!ec)
		return true;
	return false;
}

std::shared_ptr<Manager> create_manager(boost::asio::io_service& io_service,
	TestBuilder& builder, const std::vector<std::string>& templates,
	std::string target_ip, int target_port = 53)
{
	std::cout << "Create manager for " << target_ip << std::endl;
	if (!is_resolver_alive(target_ip, target_port))
		return nullptr;

	std::cout << "Alive " << target_ip << std::endl;

	// Get resolver app
	auto resolver_app = Utils::detect_resolver_app(target_ip, target_port);
	auto service_name = Utils::get_service_name(resolver_app);

	std::cout << "resolver app is " << resolver_app << std::endl;

#ifdef WIN32
	if (target_ip == LOCAL_HOST_ADDR && service_name == "unknown")
	{
		service_name = "windns";
	}
#endif

	// Create manager
	auto querier = std::make_shared<DirectQueryIssuer>(io_service, target_ip, target_port);
	auto manager = std::make_shared<Manager>(io_service, querier, target_ip, resolver_app);
	
	// In local mode clear cache for correct auto completion 
	if (target_ip == LOCAL_HOST_ADDR)
		builder.build_clear_cache_step(service_name)->lrp();

	// Build and add tests
	for (auto template_name : templates)
	{
		try
		{
			for (int num = 0; num <= 0b1111; ++num)
			{
				uint8_t ra = (num & 0b1000) ? 1 : 0;
				uint8_t aa = (num & 0b0100) ? 1 : 0;
				uint8_t ad = (num & 0b0010) ? 1 : 0;
				uint8_t rc = (num & 0b0001) ? 3 : 0;
				builder.set_flags(ra, aa, ad, rc);

				// TODO: this skips tests with RA=1 or AD=1 
				if (ra == 1 || ad == 1)
					continue;

				if (target_ip == LOCAL_HOST_ADDR)
					manager->add_test(builder.build_test_local(*manager, template_name, service_name));
				else
					manager->add_test(builder.build_test_remote(*manager, template_name, service_name));
			}
		}
		catch (std::runtime_error& e)
		{
			std::cerr << "Warning! rule " << template_name << " skipped - " << e.what() << std::endl;
		}
	}

	return manager;
}

oms_t load_oms(std::string filename)
{
	std::ifstream json_file(filename);
	std::string json_str((std::istreambuf_iterator<char>(json_file)), std::istreambuf_iterator<char>());
	return getPayloads(json_str);
}

int main(int argc, char* argv[])
{
	static const int CONCURRENCY = 100;

	auto args = std::vector<std::string>{ argv + 1, argv + argc };

	// Print usage
	if (args.size() < 2 || args[0][0] == '-')
	{
		std::cout << "Usage: " << argv[0] << " <target> [-templates arg] [-parameter arg]... " << std::endl;
		std::cout << "\t target \t Filename w/ list of target IP addresses or 127.0.0.1 for local test" << std::endl;
		std::cout << "\t templates \t OMS templates to test (=all)" << std::endl;
		std::cout << "\t parameter \t Explicit template parameters values" << std::endl;
		return 0;
	}

	// Parse argumets
	auto mapping = get_args_mapping(args);
	auto target = args[0];

	// Load OMS templates
	auto oms = load_oms("oms.json");

	// Get templates to try
	auto& templates = mapping["templates"];
	if (templates.empty() || std::find(templates.begin(), templates.end(), "all") != templates.end())
	{
		// Just load all
		templates.clear();
		for (auto entry : oms) { templates.push_back(entry.first); }
	}

	// Create tests builder
	TestBuilder builder{ oms };
	builder.set_mapping(mapping);

	// Setup io_service
	boost::asio::io_service io_service;
	boost::asio::io_service::work only_stop_explicitly(io_service);	// makes IO service keep running until explicit stop

	// Local mode
	if (target == LOCAL_HOST_ADDR)
	{
		// Create manager
		auto manager = create_manager(io_service, builder, templates, target);

		// Setup spoofing injection point
		LocalInterceptorSpoofer interceptor_spoofer;
		interceptor_spoofer.start(io_service, std::bind(&Manager::spoof_response, manager, std::placeholders::_1));
		std::this_thread::sleep_for(std::chrono::seconds(1));

		// Start io_service in separate thread
		auto io_service_thread = std::thread([&]()
		{
			io_service.run();
		});

		// Start manager
		manager->start();

		// Print results
		std::cout << manager->future().get();

		// Stop io_service
		io_service.stop();
		io_service_thread.join();
	}
	// Remote mode
	else
	{
		// Start io_service in separate thread
		auto io_service_thread = std::thread([&]()
		{
			io_service.run();
		});

		// Setup DNS Server as spoofing injection point
		DnsServer dns_server{ io_service, LOCAL_HOST_ADDR, 1053 };
		dns_server.start();

		// Wait a bit to make sure the DNS server runs
		std::this_thread::sleep_for(std::chrono::seconds(1));

		/* Run managers*/
	
		// Results futures
		std::list<std::future<Manager::Result>> futures;

		// Single target
		if (is_valid_ipv4_address(target))
		{
			auto manager = create_manager(io_service, builder, templates, target);
			if (manager)
			{
				futures.push_back(manager->future());
				dns_server.register_manager(manager);
				manager->start();
			}
		}
		// Multiple targets from file
		else
		{
			std::ifstream targets_file(target);
			std::string target_ip;
			while (std::getline(targets_file, target_ip))
			{
				target_ip.erase(std::remove(target_ip.begin(), target_ip.end(), '\n'), target_ip.end());
				if (target_ip == "")
					continue;

				// Create manager
				auto manager = create_manager(io_service, builder, templates, target_ip);
				if (!manager)
					continue;

				// Keep track of future result
				futures.push_back(manager->future());

				// Register manager in DNS server (also keeps manager alive)
				dns_server.register_manager(manager);

				// Start manager
				manager->start();

				// Only allow $CONCURRENCY concurrent targets
				if (futures.size() >= CONCURRENCY)
				{
					auto result = futures.front().get();
					std::cout << result << std::endl;

					futures.pop_front();
					dns_server.unregister_manager(result.identifier);
				}
			}
		}

		// Wait for any remaining targets
		for (auto& future : futures)
		{
			auto result = future.get();
			std::cout << result << std::endl;

			dns_server.unregister_manager(result.identifier);
		}

		// Stop io_service
		std::cout << "Stop io service" << std::endl;
		io_service.stop();
		io_service_thread.join();
	}

	return 0;
}

///// <summary>
///// Application entry point.
/////	Usage: app resolver_app target_ip target_port target_domain [Templates] [-Parameters]
/////		resolver_app	Resolver Application(auto, bind9, unbound, windns)
/////		target_ip		Target resolver IP
/////		target_port		Target resolver port(= 53)
/////		target_domain	Target domain to take control over
/////		Templates		Template names to test
/////		Parameters		Parameters values
/////
/////		Notes : If target_ip is not local then target_domain must be an authoritative
/////		domain of the local machine and the local dns server must run on port 1053.
///// </summary>
//int main(int argc, char* argv[])
//{
//	std::vector<std::string> arguments{ argv + 1, argv + argc };
//	const int const_args_count = 4;
//	if (arguments.size() < const_args_count)
//	{
//		std::cout << "Usage: " << argv[0] << " <resolver_app> <target_ip> <target_port> <target_domain> [Templates] [-Parameters]" << std::endl;
//		std::cout << "\t resolver_app \t Resolver Application \t (auto,bind9,unbound,windns)" << std::endl;
//		std::cout << "\t target_ip \t Target resolver IP \t" << std::endl;
//		std::cout << "\t target_port \t Target resolver port \t (=53)" << std::endl;
//		std::cout << "\t target_domain \t Target domain to take control over \t " << std::endl;
//		std::cout << "\t Templates \t Template names to test \t " << std::endl;
//		std::cout << "\t -Parameters \t Parameters values \t " << std::endl;
//		std::cout << " Notes: If target_ip is not local then target_domain must be an authoritative domain "
//			<< "of the local machine and the local dns server must run on port 1053." << std::endl;
//		return 1;
//	}
//
//	// Get local network parameters
//	auto default_interface = Tins::NetworkInterface::default_interface();
//	auto device_name = default_interface.name();
//	auto my_ip = default_interface.addresses().ip_addr.to_string();
//
//	// Get argument: target resolver application
//	std::string service_name = arguments[0];
//
//	// Get argument: target resolver ip
//	auto target_ip = arguments[1];
//	if (target_ip == my_ip)
//		target_ip = LOCAL_HOST_ADDR;
//	bool local_mode = (target_ip == LOCAL_HOST_ADDR);
//
//	// Get argument: target resolver port
//	uint16_t target_port = static_cast<uint16_t>(std::stoi(arguments[2]));
//
//	// Get argument: target domain
//	auto target_domain = arguments[3];	// on remote mode must be my domain!
//
//	// Automatic detection of resolver application
//	if (service_name == "auto")
//	{
//		service_name = "unknown";
//
////#ifdef WIN32
////		if (local_mode)
////		{
////			service_name = "windns";
////		}
////#else
//		service_name = Utils::detect_resolver_app(target_ip, target_port);
//		if (local_mode && service_name == "unknown")
//		{
//			std::cout << "I have no idea what resolver app is running here!" << std::endl;
//			return 1;
//		}
////#endif
//	}
//
//	// Print details
//	std::cout << "mode " << ((local_mode) ? "local" : "remote") << std::endl;
//	std::cout << "using device " << device_name << std::endl;
//	std::cout << "current machine ip " << my_ip << std::endl;
//	std::cout << "target domain " << target_domain << std::endl;
//	std::cout << "target resolver " << target_ip << ":" << target_port << std::endl;
//	std::cout << "resolver app is " << service_name << std::endl;
//	
//	if (service_name != "bind9" && service_name != "windns" && service_name != "unbound")
//		service_name = "unknown";
//
//	// TODO: check if resolver is alive
//	bool alive = false;
//	command(fmt::format("dig +short @{0} google.com -p {1}", target_ip, target_port), [&](const std::string& line) {
//		std::string ovserved_ip = line;
//		ovserved_ip.erase(std::remove(ovserved_ip.begin(), ovserved_ip.end(), '\n'), ovserved_ip.end());
//		if (ovserved_ip != "" && ovserved_ip[0] != ';')
//			alive = true;
//	});
//
//	if (!alive)
//	{
//		std::cout << "Error " << target_ip << ":" << target_port << " is offline!"<< std::endl;
//	}
//
//	// Load OMS templates
//	auto load_oms = []()
//	{
//		std::ifstream json_file("oms.json");
//		std::string json_str((std::istreambuf_iterator<char>(json_file)), std::istreambuf_iterator<char>());
//		return getPayloads(json_str);
//	};
//	auto oms = load_oms();
//
//	// Get payloads to try
//	std::vector<std::string> payloads;
//	if (arguments.size() > const_args_count)
//	{
//		payloads = get_payload_names_from_args({ arguments.begin() + const_args_count, arguments.end() });
//	}
//
//	if (payloads.empty())
//	{
//		// Just add all
//		for (auto pl : oms)
//		{
//			payloads.push_back(pl.first);
//		}
//	}
//
//	// Setup manager
//	boost::asio::io_service io_service;
//	boost::asio::io_service::work only_stop_explicitly(io_service);	// makes IO service keep running until explicit stop
//	DirectQueryIssuer querier{ io_service, target_ip, target_port };
//	Manager manager{ io_service, &querier };
//	TestBuilder builder{ manager, oms };
//
//	// Clear old cache for correct automatic mapping
//	if (local_mode)
//		builder.build_clear_cache_step(service_name)->lrp();
//
//	// Set basic mapping
//	builder.set_mapping(get_args_mapping(arguments));
//	builder.add_automatic_mappings(target_domain);
//
//	// Add tests (auto-mapping on the fly)
//	std::cout << "Adding tests" << std::endl;
//	for (auto pl_name : payloads)
//	{
//		std::cout << "Adding " << pl_name << std::endl;
//
//		try
//		{
//			for (int num = 0; num <= 0b1111; ++num)
//			{
//				uint8_t ra = (num & 0b1000) ? 1 : 0;
//				uint8_t aa = (num & 0b0100) ? 1 : 0;
//				uint8_t ad = (num & 0b0010) ? 1 : 0;
//				uint8_t rc = (num & 0b0001) ? 3 : 0;
//				builder.set_flags(ra, aa, ad, rc);
//
//				// TODO: this skips tests with RA=1 or AD=1 
//				if (ra == 1 || ad == 1)
//					continue;
//
//				if (local_mode)
//					manager.add_test(builder.build_test_local(pl_name, service_name));
//				else
//					manager.add_test(builder.build_test_remote(pl_name, service_name));
//			}
//		}
//		catch(std::runtime_error& e)
//		{
//			std::cout << "Warning! rule " << pl_name << " skipped - " << e.what() << std::endl;
//		}
//
//		//try
//		//{
//		//	builder.set_flags(0, 1, 1, 0);
//		//	if (local_mode)
//		//		manager.add_test(builder.build_test_local(pl_name, service_name));
//		//	else
//		//		manager.add_test(builder.build_test_remote(pl_name, service_name));
//		//}
//		//catch (std::runtime_error& e)
//		//{
//		//	std::cerr << "Warning! rule " << pl_name << " skipped - " << e.what() << std::endl;
//		//}
//
//	}
//
//	// Clear cache again
//	if (local_mode)
//		builder.build_clear_cache_step(service_name)->lrp();
//
//	// Start manager
//	std::cout << "Starting manager" << std::endl;
//	manager.start();
//
//	// Setup spoofing injection points
//	if (local_mode)
//	{
//		// Intercepts requests sent from the local resolver
//		LocalInterceptorSpoofer interceptor_spoofer;
//		interceptor_spoofer.start(io_service, std::bind(&Manager::spoof_response, std::ref(manager), std::placeholders::_1));
//		std::this_thread::sleep_for(std::chrono::seconds(1));
//		io_service.run();
//	}
//	else
//	{
//		// Intercepts requests we got from outside resolver
//		DnsServer dns_server{ io_service, LOCAL_HOST_ADDR, 1053 };
//		dns_server.register_handler(std::bind(&Manager::spoof_response, std::ref(manager), std::placeholders::_1));
//		dns_server.start();
//		io_service.run();
//	}
//
//	std::cout << "\nSUMMARY\n" << "-------\n";
//	for (auto result : manager.results())
//	{
//		std::cout << result << std::endl;
//	}
//
//	return 0;
//}

#pragma once
#include <list>
#include <string>
#include <future>
#include <atomic>
#include <iostream>

#include <boost/optional.hpp>
#include <boost/asio.hpp>

#include "query_issuer.h"
#include "test.h"
#include "test_step.h"
#include "tins.h"

class Manager
{
public:
	// Result structure
	struct Result
	{
		std::string identifier;
		std::string header;
		std::list<std::string> summary;

		friend std::ostream& operator<<(std::ostream& os, const Result& result);
	};

	// Construct
	Manager(boost::asio::io_service & io_service, std::shared_ptr<QueryIssuer> query_issuer, std::string identifier, std::string resolver_app);
	Manager(const Manager&) = delete;
	~Manager();

	// Interface functions (access from main thread)
	void start();
	void add_test(const Test& test);
	const std::string& identifier() const { return identifier_; }
	std::future<Result> future() { return promise_.get_future(); }

	// IO thread functions
	boost::optional<Tins::DNS> spoof_response(Tins::DNS& request);
	void send_dns_query(Tins::DNS::Query query, QueryIssuer::completed_callback_t callback);

private:
	// Flow functions
	void run_current_test();
	void run_current_step();
	void step_completed(TestStep& step);
	bool is_current_step(TestStep * step);
	void on_timeout(TestStep * step, const boost::posix_time::time_duration duration);
	void step_post_cleanup();

	std::string identifier_;

	boost::asio::io_service& io_service_;
	std::shared_ptr<QueryIssuer> query_issuer_;
	boost::asio::deadline_timer deadline_;

	std::atomic_bool active_;
	int retries_;
	int current_spoof_count_;

	std::list<Test> tests_;
	std::list<Test>::iterator current_test_;
	Test::steps_t::iterator current_step_;

	Result result_;
	std::promise<Result> promise_;

	std::ofstream output_;
};

#pragma once
#include <string>
#include <functional>
#include <boost/asio.hpp>

using boost::asio::io_service;

class TestStep
{
public:
	// Completion callback signature
	typedef std::function<void(TestStep&)> completed_callback_t;

	// Constructor & Destructor
	TestStep() = default;
	virtual ~TestStep() = default;

	// Interface functions
	virtual std::string to_string() const = 0;
	virtual void run(io_service&, completed_callback_t) = 0;
	virtual void stop() {};
	virtual boost::posix_time::time_duration timeout() { return boost::posix_time::pos_infin; }

};
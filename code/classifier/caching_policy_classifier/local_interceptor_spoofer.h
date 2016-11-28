#pragma once
#include <boost/asio.hpp>
#include <boost/optional.hpp>
#include "tins.h"

class LocalInterceptorSpoofer
{
public:
	typedef std::function<boost::optional<Tins::DNS>(Tins::DNS&)> response_generator_t;

	LocalInterceptorSpoofer() = default;
	~LocalInterceptorSpoofer() = default;
	void start(boost::asio::io_service& io_service, response_generator_t response_generator);
};


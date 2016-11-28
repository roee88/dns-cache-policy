#pragma once

#include <functional>
#include <boost/optional.hpp>
#include "tins.h"

class QueryIssuer
{
public:
	typedef std::function<void(boost::optional<Tins::DNS>)> completed_callback_t;

	QueryIssuer() = default;
	QueryIssuer(const QueryIssuer&) = delete;
	QueryIssuer& operator=(QueryIssuer const&) = delete;
	virtual ~QueryIssuer() = default;

	virtual void query(Tins::DNS::Query query) = 0;
	void set_completed_callback(completed_callback_t c) { completed_callback_ = c; }

protected:
	completed_callback_t completed_callback_;
};
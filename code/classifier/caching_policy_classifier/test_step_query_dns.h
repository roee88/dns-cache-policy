#pragma once
#include <memory>
#include <boost/optional.hpp>
#include "test_step.h"
#include "query_issuer.h"
#include "tins.h"

class TestStepQueryDNS : public TestStep, public std::enable_shared_from_this<TestStepQueryDNS>
{
public:
	// Send query function pointer
	typedef std::function<void(Tins::DNS::Query, QueryIssuer::completed_callback_t)> run_query_method_t;

	// Construct
	TestStepQueryDNS(run_query_method_t run_query_method);
	virtual ~TestStepQueryDNS() = default;

	// Interface functions
	std::string to_string() const override;
	void run(io_service& io_service, completed_callback_t callback) override;
	void stop() override;
	virtual boost::posix_time::time_duration timeout() override { return boost::posix_time::seconds(6); }	// TODO: was 5

	// Getters
	Tins::DNS::Query& query() { return query_; }
	boost::optional<Tins::DNS>& response() { return response_; }
	
private:
	// Callback for run_query_method_t completion
	void on_query_completed(boost::optional<Tins::DNS> response);

	run_query_method_t run_query_method_;
	completed_callback_t completed_callback_;

protected:
	Tins::DNS::Query query_;
	boost::optional<Tins::DNS> response_;
};

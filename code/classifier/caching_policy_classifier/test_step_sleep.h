#pragma once
#include "test_step.h"

class TestStepSleep : public TestStep
{
public:
	TestStepSleep(boost::posix_time::time_duration duration);

	std::string to_string() const override;
	void run(boost::asio::io_service& io_service, completed_callback_t callback) override;

private:
	std::shared_ptr<boost::asio::deadline_timer> deadline_;
	boost::posix_time::time_duration duration_;
};


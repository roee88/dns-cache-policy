#include "test_step_sleep.h"
#include <sstream>

TestStepSleep::TestStepSleep(boost::posix_time::time_duration duration)
	: duration_(duration)
{
}

void TestStepSleep::run(boost::asio::io_service& io_service, completed_callback_t callback)
{
	deadline_ = std::make_shared<boost::asio::deadline_timer>(io_service);
	deadline_->expires_from_now(duration_);
	deadline_->async_wait([callback, this](const boost::system::error_code& e)
	{
		callback(*this);
	});
}

std::string TestStepSleep::to_string() const
{
	std::stringstream result;
	result << "Sleep(" << duration_.total_milliseconds() << ")" << std::endl;
	return result.str();
}

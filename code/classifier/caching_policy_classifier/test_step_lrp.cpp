#include "test_step_lrp.h"
#include <thread>

void TestStepLongRunningProcess::run(boost::asio::io_service& io_service, completed_callback_t callback)
{
	auto t = std::thread([&io_service, callback, this]()
	{
		lrp();
		io_service.dispatch([callback, this](void)
		{
			callback(*this);
		});
	});
	t.detach();
}

#pragma once
#include "test_step.h"

class TestStepLongRunningProcess :	public TestStep
{
public:
	virtual void lrp() = 0;
	void run(boost::asio::io_service& io_service, completed_callback_t callback) override;
};


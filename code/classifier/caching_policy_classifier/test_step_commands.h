#pragma once
#include "test_step_lrp.h"
#include <string>
#include <vector>

class TestStepRunCommands : public TestStepLongRunningProcess
{
public:
	TestStepRunCommands(std::vector<std::string> commands);
	~TestStepRunCommands();

	virtual void lrp() override;
	std::string to_string() const override;

private:
	std::vector<std::string> commands_;
};


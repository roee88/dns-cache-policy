#include "test_step_commands.h"
#include <sstream>
#include "command.h"

TestStepRunCommands::TestStepRunCommands(std::vector<std::string> commands) 
	: commands_(commands)
{
}

TestStepRunCommands::~TestStepRunCommands()
{
}

void TestStepRunCommands::lrp()
{
	for (const auto& cmd : commands_)
	{
		command(cmd);
	}
}

std::string TestStepRunCommands::to_string() const
{
	std::stringstream result;
	result << "Commands ( ";
	for (const auto& command : commands_)
	{
		result << command << "; ";
	}
	result << ")" << std::endl;
	return result.str();

	return std::string();
}

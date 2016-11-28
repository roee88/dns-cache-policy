#pragma once

#include <string>
#include <list>
#include <memory>
#include "test_step.h"

class Test
{
public:
	Test(std::string name);
	~Test();

	typedef std::list<std::shared_ptr<TestStep>> steps_t;
	steps_t& steps() { return steps_; };

	const std::string& name() const { return name_; };

private:
	std::string name_;
	steps_t steps_;
};


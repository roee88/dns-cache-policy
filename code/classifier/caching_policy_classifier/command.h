#pragma once
#include <string>
#include <functional>

int command(std::string cmd, std::function<void(const std::string&)> callback=nullptr);
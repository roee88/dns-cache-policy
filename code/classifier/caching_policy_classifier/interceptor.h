#pragma once
#include <functional>
#include "tins.h"

class Interceptor
{
public:
	typedef std::function<void(const Tins::PDU&)> callback_t;

	Interceptor();
	~Interceptor();

	void start(callback_t callback);

private:
	bool spoofer_callback(callback_t callback, const Tins::PDU & pdu);
	callback_t callback_;

};


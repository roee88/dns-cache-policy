#include "manager.h"
#include <boost/algorithm/string/predicate.hpp>
#include "test_step_dns.h"
#include "test_step_verify_by_query.h"
#include "format.h"
#include "tins.h"


Manager::Manager(boost::asio::io_service & io_service, std::shared_ptr<QueryIssuer> query_issuer, std::string identifier, std::string resolver_app)
	: io_service_(io_service), deadline_(io_service), query_issuer_(query_issuer), identifier_(identifier), active_(false), current_spoof_count_(0), retries_(0)
{
	result_.identifier = identifier_;
	result_.header = resolver_app;

	output_.open(std::string{ "output/" } +identifier + ".log");
	output_ << identifier_ << std::endl;
	output_ << resolver_app << std::endl;
}

Manager::~Manager()
{
	//std::cout << "Manager::~Manager()" << std::endl;
	output_.close();
}

void Manager::add_test(const Test & test)
{
	tests_.push_back(test);
}

void Manager::start()
{
	io_service_.dispatch([&]() {
		active_ = true;
		current_test_ = tests_.begin();
		run_current_test();
	});
}

void Manager::run_current_test()
{
	// All tests completed?
	if (current_test_ == tests_.end())
	{
		// Write summary file
		std::ofstream summary_file;
		summary_file.open(std::string{ "output/" } +identifier_ + ".sum");
		summary_file << result_;
		summary_file.close();

		// Finish
		promise_.set_value(result_);
		active_ = false;
		return;
	}

	// Run test
	output_ << "Running test " << current_test_->name() << std::endl;
	output_ << "==============================================\n" << std::endl;
	current_step_ = current_test_->steps().begin();
	run_current_step();
}

void Manager::run_current_step()
{
	// All steps completed?
	if (current_step_ == current_test_->steps().end())
	{
		// TODO: check for success here
		output_ << "Test completed: " << current_test_->name() << std::endl << std::endl;

		// Next test
		++current_test_;
		run_current_test();
		return;
	}

	// Set timeout handler
	auto timeout_duration = current_step_->get()->timeout();
	if (timeout_duration != boost::posix_time::pos_infin)
	{
		TestStep* step = current_step_->get();
		deadline_.expires_from_now(timeout_duration);
		deadline_.async_wait([this, step, timeout_duration](const boost::system::error_code& ec)
		{
			if (!ec /*ec != boost::asio::error::operation_aborted*/)
			{
				on_timeout(step, timeout_duration);
			}
		});
	}

	// Run now
	output_ << "running step: " << current_step_->get()->to_string() << std::endl;
	current_step_->get()->run(io_service_,
		std::bind(&Manager::step_completed, this, std::placeholders::_1));
}

void Manager::step_completed(TestStep & step)
{
	if (!is_current_step(&step))
	{
		std::cerr << "ERROR!!! step_completed called with unexpected step" << std::endl
			<< "Active=" << active_ << std::endl;
		if (active_)
		{
			std::cerr << "ID=" << identifier_ << std::endl;

			if (current_test_ != tests_.end())
			{
				std::cerr << "Test=" << current_test_->name() << std::endl;
				std::cerr << "Exptected=";
				if (current_step_ != current_test_->steps().end())
					std::cerr << "end" << std::endl;
				else
					std::cerr << current_step_->get()->to_string() << std::endl;
				std::cerr << "Got=" << step.to_string() << std::endl;
			}
		}
		return;
	}

	assert(current_step_->get() == &step);
	//if (current_step_->get() != &step)
	//	return;

	// Cleanup after step completion
	step_post_cleanup();

	// Write DNS response if available
	TestStepQueryDNS* query_step = dynamic_cast<TestStepQueryDNS*>(&step);
	if (query_step != nullptr && query_step->response())
	{
		output_ << "Got packet\n" << Tins::ExtDNS::to_string(query_step->response().get()) << std::endl;
	}

	// Write verification result if available
	TestStepVerifyByQuery* verification_step = dynamic_cast<TestStepVerifyByQuery*>(&step);
	if (verification_step != nullptr)
	{
		bool success = verification_step->verify();
		std::string success_str = (success) ? "SUCCESS!" : "FAILED";
		output_ << success_str << std::endl;
		result_.summary.push_back(fmt::format("{0}\t{1}", current_test_->name(), success_str));
	}

	// Next step
	++current_step_;
	run_current_step();
}

bool Manager::is_current_step(TestStep* step)
{
	return active_ && current_test_ != tests_.end() &&
		current_step_ != current_test_->steps().end() && step == current_step_->get();
}

void Manager::on_timeout(TestStep* step, const boost::posix_time::time_duration duration)
{
	const int MAX_RETRIES = 1;

	if (deadline_.expires_at() <= boost::asio::deadline_timer::traits_type::now() && is_current_step(step))
	{
		++retries_;
		if (retries_ > MAX_RETRIES)
		{
			// Cleanup after step timeout
			step_post_cleanup();

			// Write result
			output_ << "Timeout! Skipping test " << current_test_->name() << std::endl << std::endl;
			result_.summary.push_back(fmt::format("{0}\t{1}", current_test_->name(), "TIMEOUT"));

			// Next step
			++current_test_;
			run_current_test();
		}
		else
		{
			output_ << "retry after timeout" << std::endl;

			// Set timeout handler
			if (duration != boost::posix_time::pos_infin)
			{
				deadline_.expires_from_now(duration);
				deadline_.async_wait([this, step, duration](const boost::system::error_code& ec)
				{
					if (!ec /*ec != boost::asio::error::operation_aborted*/)
					{
						on_timeout(step, duration);
					}
				});
			}

			// Run again
			current_step_->get()->stop();
			query_issuer_->set_completed_callback(nullptr);
			current_step_->get()->run(io_service_,
				std::bind(&Manager::step_completed, this, std::placeholders::_1));
		}
	}

	//const int MAX_RETRIES = 2;

	//// Expired
	//if (deadline_.expires_at() <= boost::asio::deadline_timer::traits_type::now())
	//{
	//	// Wait again
	//	++retries_;	// TODO: max retries!
	//	if (retries_ > MAX_RETRIES)
	//	{
	//		output_ << "Timeout! Skipping test " << current_test_->name() << std::endl << std::endl;
	//		result_.summary.push_back(fmt::format("{0}\t{1}", current_test_->name(), "TIMEOUT"));
	//		current_step_->get()->stop();
	//		++current_test_;
	//		run_current_test();
	//	}
	//	else
	//	{
	//		output_ << "retry" << std::endl;
	//		deadline_.expires_from_now(duration);
	//		deadline_.async_wait([this, duration](const boost::system::error_code& ec)
	//		{
	//			if (ec != boost::asio::error::operation_aborted)
	//			{
	//				on_timeout(duration);
	//			}
	//		});

	//		// Run step
	//		current_step_->get()->run(io_service_,
	//			std::bind(&Manager::step_completed, this, std::placeholders::_1));
	//	}
	//}
}

void Manager::step_post_cleanup()
{
	current_step_->get()->stop();
	query_issuer_->set_completed_callback(nullptr);
	retries_ = 0;
	deadline_.cancel();
}

void Manager::send_dns_query(Tins::DNS::Query query, QueryIssuer::completed_callback_t callback)
{
	current_spoof_count_ = 0;
	query_issuer_->set_completed_callback(callback);
	query_issuer_->query(query);
}

boost::optional<Tins::DNS> Manager::spoof_response(Tins::DNS& request)
{
	if (!active_)
		return boost::none;

	TestStepSpoofDNS* step = dynamic_cast<TestStepSpoofDNS*>(current_step_->get());
	if (step != nullptr)
	{
		auto query = request.queries().front();
		if (query.dname() == step->query().dname())
		{
			++current_spoof_count_;
			if (!step->want_spoof_at_count(current_spoof_count_))
				return boost::none;

			// Spoof response
			auto response = Tins::DNS();
			response.type(Tins::DNS::RESPONSE);
			response.id(request.id());
			response.recursion_desired(request.recursion_desired());
			response.add_query(query);

			response.rcode(step->rcode());
			response.recursion_available(step->ra());
			response.authoritative_answer(step->aa());
			response.authenticated_data(step->ad());

			if (response.rcode() != Tins::ExtDNS::RCode::NXDOMAIN)
			{
				for (const auto& resource : step->answers())
				{
					response.add_answer(resource);
				}
			}
			for (const auto& resource : step->authorities())
			{
				response.add_authority(resource);
			}
			for (const auto& resource : step->additionals())
			{
				response.add_additional(resource);
			}

			return response;
		}
	}

	// I don't want to spoof
	return boost::none;
}

std::ostream& operator<<(std::ostream& os, const Manager::Result& result)
{
	os << "\nSUMMARY\n" << "-------\n";
	os << result.identifier << std::endl;
	os << result.header << std::endl;
	for (auto line : result.summary)
	{
		os << line << std::endl;
	}
	return os;
}

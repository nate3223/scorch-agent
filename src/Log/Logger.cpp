#include "Logger.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/async.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include <memory>

namespace
{
#ifndef NDEBUG
	constexpr auto kLogLevel = spdlog::level::debug;
#else
	constexpr auto kLogLevel = spdlog::level::info;
#endif
}

spdlog::logger& Logger::Instance()
{
	static Logger sLogger;
	return *sLogger.m_logger;
}

Logger::Logger()
{
	if (! spdlog::thread_pool())
		spdlog::init_thread_pool(8192, 1);

	std::vector<spdlog::sink_ptr> sinks;

	auto stdout_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt >();
	auto rotating = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("ScorchClient.log", 1024 * 1024 * 5, 10);
	sinks.push_back(stdout_sink);
	sinks.push_back(rotating);

	m_logger = std::make_shared<spdlog::async_logger>("logs", sinks.begin(), sinks.end(), spdlog::thread_pool(), spdlog::async_overflow_policy::block);

	m_logger->set_pattern("%^%Y-%m-%d %H:%M:%S.%e [%L] [th#%t]%$ : %v");
	m_logger->set_level(kLogLevel);
	m_logger->flush_on(spdlog::level::err);

	spdlog::register_logger(m_logger);
}

Logger::~Logger()
{
	spdlog::shutdown();
}

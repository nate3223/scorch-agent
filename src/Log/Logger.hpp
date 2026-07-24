#pragma once

#include <spdlog/spdlog.h>

#include <memory>

class Logger
{
public:
	static spdlog::logger& Instance();

private:
	Logger();
	~Logger();

	std::shared_ptr<spdlog::logger>	m_logger;
};

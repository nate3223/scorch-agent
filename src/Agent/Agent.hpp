#pragma once

#include <boost/asio/awaitable.hpp>

#include <memory>

class AgentPrivate;

class Agent
{
public:
									Agent();
									~Agent();

	boost::asio::awaitable<void>	run();

private:
	std::unique_ptr<AgentPrivate>	m_p;
};

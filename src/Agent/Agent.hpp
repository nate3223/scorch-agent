#pragma once

#include <boost/asio/awaitable.hpp>

#include <memory>

class AgentPrivate;

enum class AgentState
{
	Disconnected,
	Connecting,
	Pairing,
	Authenticating,
	Connected,
};

class Agent
{
public:
									Agent();
									~Agent();

	boost::asio::awaitable<void>	run();

	AgentState						state() const;

private:
	std::unique_ptr<AgentPrivate>	m_p;
};

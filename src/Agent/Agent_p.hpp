#pragma once

#include "Agent.hpp"
#include "AgentCredentials.hpp"
#include "Logger.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace asio = boost::asio;

using tcp = asio::ip::tcp;
using TLSSocket = asio::ssl::stream<tcp::socket>;
using Buffer = std::vector<std::byte>;

class AgentPrivate
{
public:
	struct Context
	{
		std::string	host;
		std::string	port;
		TLSSocket	socket;
	};
									AgentPrivate();

	void							setState(AgentState state) const;

	asio::awaitable<Context>		connect(std::string host, std::string port);

	asio::awaitable<void>			eventLoop();

	asio::awaitable<void>			authenticate();
	asio::awaitable<void>			pair();
	asio::awaitable<void>			listen();
	asio::awaitable<Buffer>			read();
	asio::awaitable<void>			handleMessage(std::string_view message);


	void							close(Context&& ctx);

	spdlog::logger&					m_logger;

	std::optional<Context>			m_context;
	tcp::resolver					m_resolver;

	mutable AgentState				m_state = AgentState::Disconnected;

	AgentCredentials				m_credentials;
};
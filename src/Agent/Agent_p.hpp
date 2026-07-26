#pragma once

#include "Agent.hpp"
#include "AgentCredentials.hpp"
#include "Logger.hpp"

#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ssl.hpp>

#include <capnp/message.h>
#include <capnp/serialize.h>
#include <ScorchProtocol.capnp.h>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace asio = boost::asio;

using tcp = asio::ip::tcp;
using TLSSocket = asio::ssl::stream<tcp::socket>;
using Buffer = std::vector<std::byte>;
using AgentMessage = scorch::protocol::AgentMessage::Builder;
using ServerMessage = scorch::protocol::ServerMessage::Reader;

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

	template <typename Callback>
		requires std::invocable<Callback, AgentMessage&>
	asio::awaitable<void>			sendAgentMessage(Callback&& callback)
	{
		capnp::MallocMessageBuilder message;
		AgentMessage agentMessage = message.initRoot<scorch::protocol::AgentMessage>();

		callback(agentMessage);

		co_await writeMessage(message);
	}

	template <typename Callback>
		requires std::invocable<Callback, ServerMessage&>
	asio::awaitable<void>			readServerMessage(Callback&& callback)
	{
		auto response = co_await read();

		if (response.size() % sizeof(capnp::word) != 0)
			throw std::runtime_error("Invalid Cap'n Proto message size");

		auto reader = capnp::FlatArrayMessageReader(
			kj::ArrayPtr<const capnp::word>(
				reinterpret_cast<const capnp::word*>(response.data()),
				response.size() / sizeof(capnp::word)
			)
		);

		ServerMessage serverMessage = reader.getRoot<scorch::protocol::ServerMessage>();

		callback(serverMessage);

		co_return;
	}

	asio::awaitable<void>			writeMessage(capnp::MallocMessageBuilder& message);

	void							close(Context&& ctx);

	spdlog::logger&					m_logger;

	std::optional<Context>			m_context;
	tcp::resolver					m_resolver;

	mutable AgentState				m_state = AgentState::Disconnected;

	AgentCredentials				m_credentials;
};
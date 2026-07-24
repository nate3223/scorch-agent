#include "Agent.hpp"
#include "Agent_p.hpp"

#include "ASIOManager.hpp"
#include "Logger.hpp"

#include <format>
#include <optional>

namespace
{
	constexpr auto kHostname = "localhost";
	constexpr auto kPort = "3224";
}

Agent::Agent()
	: m_p(std::make_unique<AgentPrivate>())
{

}

asio::awaitable<void> Agent::run()
{
	while (true)
	{
		{
			std::optional<WebSocket> webSocket;
			try
			{
				webSocket.emplace(co_await m_p->connect(kHostname, kPort));
				co_await m_p->authenticate(*webSocket);
				co_await m_p->listen(*webSocket);
			}
			catch (const std::exception& e)
			{
				Logger::Instance().error(e.what());
			}

			if (webSocket)
				m_p->close(std::move(*webSocket));
		}

		asio::steady_timer timer(co_await asio::this_coro::executor);

		timer.expires_after(std::chrono::seconds(5));

		co_await timer.async_wait(asio::use_awaitable);
	}
}

Agent::~Agent() = default;

AgentPrivate::AgentPrivate()
	: m_resolver(ASIOManager::Instance().ioContext())
{

}

asio::awaitable<WebSocket> AgentPrivate::connect(std::string host, std::string port)
{
	Logger::Instance().info(std::format("Connecting to {} on port {}...", host, port));

	m_host = std::move(host);
	m_port = std::move(port);

	auto executor = co_await asio::this_coro::executor;

	asio::ssl::stream<asio::ip::tcp::socket> webSocket(executor, ASIOManager::Instance().sslContext());
	auto endpoints = co_await m_resolver.async_resolve(m_host, m_port, asio::use_awaitable);

	// Verify the server's certificate
	webSocket.set_verify_mode(asio::ssl::verify_peer);

	//	Verify:
	//		- Certificate was signed by a trusted CA
	//		- Certificate was actually issued to the connected host
	webSocket.set_verify_callback(asio::ssl::host_name_verification(m_host));

	// Sets the hostname so that the server selects the appropriate certificate
	// for the associated IP address
	SSL_set_tlsext_host_name(webSocket.native_handle(), m_host.c_str());

	co_await asio::async_connect(webSocket.next_layer(), endpoints, asio::use_awaitable);

	Logger::Instance().info("Awaiting TLS handshake...");
	co_await webSocket.async_handshake(asio::ssl::stream_base::client, asio::use_awaitable);

	Logger::Instance().info("Connected");
	co_return webSocket;
}

asio::awaitable<void> AgentPrivate::authenticate(WebSocket& webSocket)
{
	Logger::Instance().info("Authenticating...");

	Logger::Instance().info("Authenticated");
	co_return;
}

asio::awaitable<void> AgentPrivate::listen(WebSocket& webSocket)
{
	while (true)
	{
		Logger::Instance().debug("Waiting for message");
		std::string message = co_await read(webSocket);
		Logger::Instance().debug(std::format("Message received: \"{}\"", message));

		co_await handleMessage(webSocket, message);
	}
}

asio::awaitable<std::string> AgentPrivate::read(WebSocket& webSocket)
{
	co_return "";
}

asio::awaitable<void> AgentPrivate::handleMessage(WebSocket& webSocket, std::string_view message)
{
	co_return;
}

void AgentPrivate::close(WebSocket&& webSocket)
{
	Logger::Instance().info("Closing websocket");
	boost::system::error_code ec;
	webSocket.next_layer().shutdown(tcp::socket::shutdown_both, ec);
	webSocket.next_layer().close(ec);
}

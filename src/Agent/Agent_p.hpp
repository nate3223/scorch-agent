#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

#include <string>
#include <string_view>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;

using tcp = asio::ip::tcp;
using WebSocket = asio::ssl::stream<tcp::socket>;

class AgentPrivate
{
public:
			AgentPrivate();

	asio::awaitable<WebSocket>		connect(std::string host, std::string port);
	asio::awaitable<void>			authenticate(WebSocket& webSocket);
	asio::awaitable<void>			listen(WebSocket& webSocket);
	asio::awaitable<std::string>	read(WebSocket& webSocket);
	asio::awaitable<void>			handleMessage(WebSocket& webSocket, std::string_view message);
	void							close(WebSocket&& webSocket);


	std::string						m_host;
	std::string						m_port;
	tcp::resolver					m_resolver;
};
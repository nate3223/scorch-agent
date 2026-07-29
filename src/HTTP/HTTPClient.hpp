#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl/context.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace scorch::agent::http
{
	struct Header
	{
		std::string	name;
		std::string	value;
	};

	struct Request
	{
		std::string			url;
		std::string			method;
		std::vector<Header>	headers;
		std::vector<std::byte>	body;
	};

	struct Response
	{
		std::uint16_t			status;
		std::vector<Header>		headers;
		std::vector<std::byte>	body;
	};

	struct ParsedURL
	{
		bool		secure;
		std::string	host;
		std::string	port;
		std::string	target;
		std::string	hostHeader;
	};

	ParsedURL ParseURL(std::string_view url);

	boost::asio::awaitable<Response> Execute(
		Request request,
		boost::asio::ssl::context& sslContext
	);
}

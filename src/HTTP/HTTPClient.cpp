#include "HTTPClient.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/system/system_error.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstring>
#include <limits>
#include <ranges>
#include <stdexcept>
#include <utility>

namespace asio = boost::asio;
namespace beast = boost::beast;
using tcp = asio::ip::tcp;

namespace
{
	constexpr auto kRequestTimeout = std::chrono::seconds(15);
	constexpr std::uint64_t kMaximumResponseBodySize = 768 * 1024;

	bool HasInvalidURLCharacter(std::string_view value)
	{
		return std::ranges::any_of(value, [](unsigned char character) {
			return character <= 0x20 || character == 0x7f;
		});
	}

	std::string ValidatePort(std::string_view value)
	{
		if (value.empty())
			throw std::invalid_argument("HTTP URL contains an empty port");

		unsigned int port = 0;
		const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), port);
		if (error != std::errc{} || end != value.data() + value.size() ||
			port == 0 || port > std::numeric_limits<std::uint16_t>::max())
		{
			throw std::invalid_argument("HTTP URL contains an invalid port");
		}

		return std::string(value);
	}

	beast::http::request<beast::http::vector_body<std::uint8_t>> MakeRequest(
		const scorch::agent::http::Request& request,
		const scorch::agent::http::ParsedURL& url
	)
	{
		const auto method = beast::http::string_to_verb(request.method);
		if (method == beast::http::verb::unknown)
			throw std::invalid_argument("Unsupported HTTP method: " + request.method);

		beast::http::request<beast::http::vector_body<std::uint8_t>> result{
			method,
			url.target,
			11
		};

		for (const auto& header : request.headers)
			result.insert(header.name, header.value);

		result.set(beast::http::field::host, url.hostHeader);
		result.body().resize(request.body.size());
		if (! request.body.empty())
			std::memcpy(result.body().data(), request.body.data(), request.body.size());
		result.prepare_payload();
		return result;
	}

	template <typename Stream>
	asio::awaitable<scorch::agent::http::Response> SendRequest(
		Stream& stream,
		beast::http::request<beast::http::vector_body<std::uint8_t>> request
	)
	{
		beast::get_lowest_layer(stream).expires_after(kRequestTimeout);
		co_await beast::http::async_write(stream, request, asio::use_awaitable);

		beast::flat_buffer buffer;
		beast::http::response_parser<beast::http::vector_body<std::uint8_t>> parser;
		parser.body_limit(kMaximumResponseBodySize);

		beast::get_lowest_layer(stream).expires_after(kRequestTimeout);
		co_await beast::http::async_read(stream, buffer, parser, asio::use_awaitable);
		auto response = parser.release();

		scorch::agent::http::Response result;
		result.status = static_cast<std::uint16_t>(response.result_int());
		for (const auto& header : response.base())
		{
			result.headers.push_back({
				std::string(header.name_string()),
				std::string(header.value())
			});
		}

		result.body.resize(response.body().size());
		if (! response.body().empty())
			std::memcpy(result.body.data(), response.body().data(), response.body().size());
		co_return result;
	}
}

namespace scorch::agent::http
{
	ParsedURL ParseURL(std::string_view url)
	{
		if (url.empty() || HasInvalidURLCharacter(url))
			throw std::invalid_argument("HTTP URL is empty or contains invalid characters");

		const auto schemeEnd = url.find("://");
		if (schemeEnd == std::string_view::npos)
			throw std::invalid_argument("HTTP URL must include http:// or https://");

		std::string scheme(url.substr(0, schemeEnd));
		std::ranges::transform(scheme, scheme.begin(), [](unsigned char character) {
			return static_cast<char>(std::tolower(character));
		});

		const bool secure = scheme == "https";
		if (! secure && scheme != "http")
			throw std::invalid_argument("Only HTTP and HTTPS URLs are supported");

		const auto remainder = url.substr(schemeEnd + 3);
		const auto authorityEnd = remainder.find_first_of("/?#");
		const auto authority = remainder.substr(0, authorityEnd);
		if (authority.empty())
			throw std::invalid_argument("HTTP URL is missing a host");
		if (authority.find('@') != std::string_view::npos)
			throw std::invalid_argument("HTTP URL user information is not supported");

		ParsedURL result;
		result.secure = secure;

		std::string authorityHost;
		if (authority.front() == '[')
		{
			const auto closeBracket = authority.find(']');
			if (closeBracket == std::string_view::npos || closeBracket == 1)
				throw std::invalid_argument("HTTP URL contains an invalid IPv6 host");

			result.host = authority.substr(1, closeBracket - 1);
			authorityHost = std::string(authority.substr(0, closeBracket + 1));

			const auto suffix = authority.substr(closeBracket + 1);
			if (! suffix.empty())
			{
				if (suffix.front() != ':')
					throw std::invalid_argument("HTTP URL contains an invalid authority");
				result.port = ValidatePort(suffix.substr(1));
			}
		}
		else
		{
			const auto colon = authority.rfind(':');
			if (colon != std::string_view::npos)
			{
				if (authority.find(':') != colon)
					throw std::invalid_argument("IPv6 hosts in HTTP URLs must use brackets");
				result.host = authority.substr(0, colon);
				result.port = ValidatePort(authority.substr(colon + 1));
			}
			else
			{
				result.host = authority;
			}
			authorityHost = result.host;
		}

		if (result.host.empty())
			throw std::invalid_argument("HTTP URL is missing a host");

		if (result.port.empty())
			result.port = secure ? "443" : "80";

		if (authorityEnd == std::string_view::npos)
		{
			result.target = "/";
		}
		else
		{
			const auto path = remainder.substr(authorityEnd);
			if (path.front() == '#')
				throw std::invalid_argument("HTTP URL fragments are not supported");
			if (path.find('#') != std::string_view::npos)
				throw std::invalid_argument("HTTP URL fragments are not supported");
			result.target = path.front() == '?' ? "/" + std::string(path) : std::string(path);
		}

		const bool defaultPort =
			(secure && result.port == "443") ||
			(! secure && result.port == "80");
		result.hostHeader = defaultPort
			? authorityHost
			: authorityHost + ":" + result.port;

		return result;
	}

	asio::awaitable<Response> Execute(Request request, asio::ssl::context& sslContext)
	{
		const auto url = ParseURL(request.url);
		auto executor = co_await asio::this_coro::executor;
		tcp::resolver resolver(executor);
		auto endpoints = co_await resolver.async_resolve(url.host, url.port, asio::use_awaitable);
		auto outgoing = MakeRequest(request, url);

		if (! url.secure)
		{
			beast::tcp_stream stream(executor);
			stream.expires_after(kRequestTimeout);
			co_await stream.async_connect(endpoints, asio::use_awaitable);
			auto response = co_await SendRequest(stream, std::move(outgoing));

			boost::system::error_code ignored;
			stream.socket().shutdown(tcp::socket::shutdown_both, ignored);
			co_return response;
		}

		beast::ssl_stream<beast::tcp_stream> stream(executor, sslContext);
		if (! SSL_set_tlsext_host_name(stream.native_handle(), url.host.c_str()))
		{
			throw boost::system::system_error(
				static_cast<int>(ERR_get_error()),
				asio::error::get_ssl_category()
			);
		}

		stream.set_verify_callback(asio::ssl::host_name_verification(url.host));
		beast::get_lowest_layer(stream).expires_after(kRequestTimeout);
		co_await beast::get_lowest_layer(stream).async_connect(endpoints, asio::use_awaitable);

		beast::get_lowest_layer(stream).expires_after(kRequestTimeout);
		co_await stream.async_handshake(asio::ssl::stream_base::client, asio::use_awaitable);
		auto response = co_await SendRequest(stream, std::move(outgoing));

		boost::system::error_code ignored;
		beast::get_lowest_layer(stream).expires_after(kRequestTimeout);
		co_await stream.async_shutdown(asio::redirect_error(asio::use_awaitable, ignored));
		co_return response;
	}
}

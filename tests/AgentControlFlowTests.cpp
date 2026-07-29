#include "Agent/Agent_p.hpp"
#include "HTTP/HTTPClient.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>

#include <capnp/message.h>

#include <cassert>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <thread>

namespace
{
	auto MakeResponse(capnp::MallocMessageBuilder& message)
	{
		auto response = message.initRoot<scorch::protocol::ServerMessage>();
		response.setMessageId(2);
		response.setReplyTo(1);
		response.initHeartbeat().setTimestamp(42);
		return response;
	}

	auto MakePending(boost::asio::io_context& context)
	{
		return std::make_shared<PendingRequest<int>>(
			context.get_executor(),
			[](ServerMessage received) {
				assert(received.getReplyTo() == 1);
				return 42;
			}
		);
	}

	template <typename BeforeRun>
	void AwaitPending(
		boost::asio::io_context& context,
		const std::shared_ptr<PendingRequest<int>>& pending,
		int& result,
		BeforeRun beforeRun
	)
	{
		std::exception_ptr error;
		boost::asio::co_spawn(
			context,
			[pending, &result]() -> boost::asio::awaitable<void> {
				result = co_await pending->wait();
			},
			[&error](std::exception_ptr exception) {
				error = std::move(exception);
			}
		);

		beforeRun();
		context.run();

		if (error)
			std::rethrow_exception(error);
	}
}

int main()
{
	{
		const auto url = scorch::agent::http::ParseURL("https://example.com:8443/api/start?force=1");
		assert(url.secure);
		assert(url.host == "example.com");
		assert(url.port == "8443");
		assert(url.target == "/api/start?force=1");
		assert(url.hostHeader == "example.com:8443");
	}

	{
		const auto url = scorch::agent::http::ParseURL("http://[::1]/");
		assert(! url.secure);
		assert(url.host == "::1");
		assert(url.port == "80");
		assert(url.target == "/");
		assert(url.hostHeader == "[::1]");
	}

	{
		boost::asio::io_context serverContext;
		tcp::acceptor acceptor(serverContext, { tcp::v4(), 0 });
		std::jthread server([&] {
			tcp::socket socket(serverContext);
			acceptor.accept(socket);

			boost::asio::streambuf request;
			boost::asio::read_until(socket, request, "\r\n\r\n");

			const std::string response =
				"HTTP/1.1 200 OK\r\n"
				"Content-Length: 2\r\n"
				"Connection: close\r\n"
				"\r\n"
				"OK";
			boost::asio::write(socket, boost::asio::buffer(response));
		});

		boost::asio::io_context clientContext;
		boost::asio::ssl::context sslContext(boost::asio::ssl::context::tls_client);
		std::optional<scorch::agent::http::Response> result;
		std::exception_ptr error;

		boost::asio::co_spawn(
			clientContext,
			[&]() -> boost::asio::awaitable<void> {
				scorch::agent::http::Request request{
					.url = "http://127.0.0.1:" +
						std::to_string(acceptor.local_endpoint().port()) +
						"/status",
					.method = "GET"
				};
				result = co_await scorch::agent::http::Execute(
					std::move(request),
					sslContext
				);
			},
			[&error](std::exception_ptr exception) {
				error = std::move(exception);
			}
		);

		clientContext.run();
		if (error)
			std::rethrow_exception(error);

		assert(result);
		assert(result->status == 200);
		assert(result->body.size() == 2);
		assert(std::to_integer<char>(result->body[0]) == 'O');
		assert(std::to_integer<char>(result->body[1]) == 'K');
	}

	{
		capnp::MallocMessageBuilder message;
		auto outgoing = message.initRoot<scorch::protocol::ServerMessage>();
		outgoing.initError().setMessage("owned message");

		auto serialized = capnp::messageToFlatArray(message);
		auto bytes = serialized.asBytes();
		Buffer storage(bytes.size());
		std::memcpy(storage.data(), bytes.begin(), bytes.size());

		ReceivedMessage received(std::move(storage));
		assert(received.message.isError());
		assert(received.message.getError().getMessage() == "owned message");
	}

	{
		capnp::MallocMessageBuilder message;
		auto request = message.initRoot<scorch::protocol::ServerMessage>();
		request.setMessageId(1);
		request.initShareRequest().setInfo("share details");

		assert(request.isShareRequest());
		assert(std::string(request.getShareRequest().getInfo().cStr()) == "share details");
	}

	{
		boost::asio::io_context context;
		capnp::MallocMessageBuilder message;
		auto response = MakeResponse(message);
		auto pending = MakePending(context);

		pending->complete(response.asReader());

		int result = 0;
		AwaitPending(context, pending, result, [] {});
		assert(result == 42);
	}

	{
		boost::asio::io_context context;
		capnp::MallocMessageBuilder message;
		auto response = MakeResponse(message);
		auto pending = MakePending(context);

		int result = 0;
		AwaitPending(context, pending, result, [&context, pending, response] {
			boost::asio::post(context, [pending, response] {
				pending->complete(response.asReader());
			});
		});
		assert(result == 42);
	}
}

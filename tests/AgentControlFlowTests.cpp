#include "Agent/Agent_p.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

#include <capnp/message.h>

#include <cassert>
#include <cstring>
#include <exception>
#include <memory>

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

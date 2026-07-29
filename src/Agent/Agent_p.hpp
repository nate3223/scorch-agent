#pragma once

#include "Agent.hpp"
#include "AgentCredentials.hpp"
#include "Log/Logger.hpp"

#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/unordered_map.hpp>

#include <capnp/message.h>
#include <capnp/serialize.h>
#include <ScorchProtocol.capnp.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace asio = boost::asio;

using tcp = asio::ip::tcp;
using TLSSocket = asio::ssl::stream<tcp::socket>;
using Buffer = std::vector<std::byte>;
using AgentMessage = scorch::protocol::AgentMessage::Builder;
using ServerMessage = scorch::protocol::ServerMessage::Reader;

struct ReceivedMessage
{
	explicit ReceivedMessage(Buffer storage)
		: storage(std::move(storage))
		, reader(kj::heap<capnp::FlatArrayMessageReader>(
			kj::ArrayPtr<const capnp::word>(
				reinterpret_cast<const capnp::word*>(this->storage.data()),
				this->storage.size() / sizeof(capnp::word)
			)
		))
		, message(reader->getRoot<scorch::protocol::ServerMessage>())
	{
	}

	Buffer							storage;
	kj::Own<capnp::MessageReader>	reader;
	ServerMessage					message;
};

class AsyncSignal
{
public:
	explicit AsyncSignal(asio::any_io_executor executor)
		: m_timer(std::move(executor))
	{
		m_timer.expires_at(std::chrono::steady_clock::time_point::max());
	}

	asio::awaitable<void> wait()
	{
		if (! m_completed)
		{
			boost::system::error_code ec;
			co_await m_timer.async_wait(asio::redirect_error(asio::use_awaitable, ec));
			if (! m_completed)
				throw boost::system::system_error(ec);
		}

		if (m_error)
			std::rethrow_exception(m_error);
	}

	void complete(std::exception_ptr error = {})
	{
		if (m_completed)
			return;

		m_completed = true;
		m_error = std::move(error);
		m_timer.cancel();
	}

	bool completed() const noexcept
	{
		return m_completed;
	}

private:
	asio::steady_timer	m_timer;
	std::exception_ptr	m_error;
	bool				m_completed = false;
};

class AsyncMutex
{
public:
	class Guard
	{
	public:
		explicit Guard(AsyncMutex& mutex) noexcept
			: m_mutex(&mutex)
		{
		}

		Guard(const Guard&) = delete;
		Guard& operator=(const Guard&) = delete;

		Guard(Guard&& other) noexcept
			: m_mutex(std::exchange(other.m_mutex, nullptr))
		{
		}

		~Guard()
		{
			if (m_mutex)
				m_mutex->unlock();
		}

	private:
		AsyncMutex* m_mutex;
	};

	explicit AsyncMutex(asio::any_io_executor executor)
		: m_executor(std::move(executor))
	{
	}

	asio::awaitable<Guard> lock()
	{
		if (! m_locked)
		{
			m_locked = true;
			co_return Guard(*this);
		}

		auto waiter = std::make_shared<AsyncSignal>(m_executor);
		m_waiters.push_back(waiter);

		try
		{
			co_await waiter->wait();
		}
		catch (...)
		{
			auto it = std::ranges::find(m_waiters, waiter);
			if (it != m_waiters.end())
				m_waiters.erase(it);
			throw;
		}

		co_return Guard(*this);
	}

private:
	void unlock()
	{
		if (m_waiters.empty())
		{
			m_locked = false;
			return;
		}

		auto waiter = std::move(m_waiters.front());
		m_waiters.pop_front();
		waiter->complete();
	}

	asio::any_io_executor						m_executor;
	std::deque<std::shared_ptr<AsyncSignal>>	m_waiters;
	bool										m_locked = false;
};

class PendingRequestBase
{
public:
	virtual			~PendingRequestBase() = default;
	virtual void	complete(ServerMessage response) = 0;
	virtual void	fail(std::exception_ptr error) = 0;
};

template <typename T>
class PendingRequest
	: public PendingRequestBase
{
public:
	using Parser = std::function<T(ServerMessage)>;

	PendingRequest(asio::any_io_executor executor, Parser parser)
		: m_completion(std::move(executor))
		, m_parser(std::move(parser))
	{
	}

	asio::awaitable<T> wait()
	{
		co_await m_completion.wait();
		if (! m_result)
			throw std::logic_error("Pending request completed without a result");

		co_return std::move(*m_result);
	}

	void complete(ServerMessage response) override
	{
		if (m_completion.completed())
			return;

		try
		{
			m_result = m_parser(response);
		}
		catch (...)
		{
			m_completion.complete(std::current_exception());
			return;
		}

		m_completion.complete();
	}

	void fail(std::exception_ptr error) override
	{
		m_completion.complete(std::move(error));
	}

private:
	AsyncSignal			m_completion;
	Parser				m_parser;
	std::optional<T>	m_result;
};

class AgentPrivate
{
public:
	struct Context
	{
		Context(std::string host, std::string port, TLSSocket&& socket)
			: host(std::move(host))
			, port(std::move(port))
			, socket(std::move(socket))
			, writeMutex(this->socket.get_executor())
		{
		}

		std::string	host;
		std::string	port;
		TLSSocket	socket;
		AsyncMutex	writeMutex;

		std::uint64_t	messageId = 0;
		boost::unordered_map<std::uint64_t, std::shared_ptr<PendingRequestBase>> pendingRequests;
	};
									AgentPrivate();

	void							setState(AgentState state) const;

	asio::awaitable<void>			run();
	asio::awaitable<std::shared_ptr<Context>> connect(std::string host, std::string port);
	asio::awaitable<void>			eventLoop();

	asio::awaitable<void>			authenticate();
	asio::awaitable<void>			pair();
	asio::awaitable<void>			connected();
	asio::awaitable<void>			handleUnexpectedInitializationMessage(ServerMessage message, std::string_view expected);

	// Connected
	asio::awaitable<void>			handleConnectedMessage(std::shared_ptr<Context> context, ReceivedMessage receive);
	asio::awaitable<void>			onHeartbeat(std::shared_ptr<Context> context, scorch::protocol::Heartbeat::Reader heartbeat, std::uint64_t requestId);
	asio::awaitable<void>			onCommandRequest(std::shared_ptr<Context> context, scorch::protocol::CommandRequest::Reader request, std::uint64_t requestId);
	asio::awaitable<void>			onShareRequest(std::shared_ptr<Context> context, scorch::protocol::ShareRequest::Reader request, std::uint64_t requestId);
	asio::awaitable<bool>			requestShareApproval(std::string info);
	void							onResponse(const std::shared_ptr<Context>& context, ServerMessage response);
	asio::awaitable<void>			sendProtocolError(std::shared_ptr<Context> context, std::uint64_t replyTo, std::string_view message);

	// CommandRequests
	asio::awaitable<void>			onHTTPCommand(std::shared_ptr<Context> context, scorch::protocol::HttpCommand::Reader command, std::uint64_t requestId);

	asio::awaitable<Buffer>			read(const std::shared_ptr<Context>& context);

	template <typename Callback>
		requires std::invocable<Callback&, AgentMessage&>
	asio::awaitable<void>			sendAgentMessage(Callback callback, std::uint64_t messageId = 0, std::uint64_t replyTo = 0, std::shared_ptr<Context> context = {})
	{
		if (! context)
			context = m_context;
		if (! context)
			throw std::runtime_error("Agent is not connected");

		capnp::MallocMessageBuilder message;
		AgentMessage agentMessage = message.initRoot<scorch::protocol::AgentMessage>();

		agentMessage.setMessageId(messageId);
		agentMessage.setReplyTo(replyTo);
		callback(agentMessage);

		co_await writeMessage(message, std::move(context));
	}

	template <typename T, typename Callback, typename Parser>
		requires (std::invocable<Callback&, AgentMessage&> && std::invocable<Parser&, ServerMessage>)
	asio::awaitable<T>				sendRequest(std::shared_ptr<Context> context, Callback callback, Parser parser)
	{
		if (! context)
			throw std::runtime_error("Agent is not connected");

		const std::uint64_t messageId = nextMessageId(context);
		auto pending = std::make_shared<PendingRequest<T>>(m_strand, std::move(parser));
		context->pendingRequests.emplace(messageId, pending);

		try
		{
			co_await sendAgentMessage(std::move(callback), messageId, 0, context);
		}
		catch (...)
		{
			context->pendingRequests.erase(messageId);
			throw;
		}

		co_return co_await pending->wait();
	}

	template <typename Callback>
		requires std::invocable<Callback&, ServerMessage&>
	asio::awaitable<void>			readServerMessage(Callback callback, std::shared_ptr<Context> context = {})
	{
		if (! context)
			context = m_context;
		if (! context)
			throw std::runtime_error("Agent is not connected");

		ReceivedMessage received = co_await readServerMessage(context);
		callback(received.message);
		co_return;
	}

	asio::awaitable<ReceivedMessage>	readServerMessage(const std::shared_ptr<Context>& context);

	asio::awaitable<void>				writeMessage(capnp::MallocMessageBuilder& message,std::shared_ptr<Context> context);

	std::uint64_t						nextMessageId(const std::shared_ptr<Context>& context);
	void								failPendingRequests(const std::shared_ptr<Context>& context, std::exception_ptr error);
	void								disconnect(const std::shared_ptr<Context>& context);

	asio::strand<asio::any_io_executor>	m_strand;
	asio::thread_pool					m_consoleThread{ 1 };
	tcp::resolver						m_resolver;
	spdlog::logger&						m_logger;

	std::shared_ptr<Context>			m_context;
	mutable AgentState					m_state = AgentState::Disconnected;
	AgentCredentials					m_credentials;
};

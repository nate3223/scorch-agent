#include "Agent.hpp"
#include "Agent_p.hpp"

#include "ASIO/ASIOManager.hpp"
#include "HTTP/HTTPClient.hpp"
#include "Log/Logger.hpp"

#include <cstring>
#include <format>
#include <iostream>
#include <limits>
#include <optional>

namespace
{
	constexpr auto kHostname = "localhost";
	constexpr auto kPort = "3224";
	constexpr uint32_t kMaxMessageSize = 1024 * 1024;

	inline bool IsInvalidInititationMessage(const ServerMessage& serverMessage)
	{
		return serverMessage.getMessageId() != 0 || serverMessage.getReplyTo() != 0;
	}
}

template <>
struct std::formatter<AgentState> : std::formatter<std::string_view> {
	auto format(AgentState state, std::format_context& ctx) const {
		std::string_view name = "Unknown";
		switch (state)
		{
			case AgentState::Disconnected:		name = "Disconnected";		break;
			case AgentState::Connecting:		name = "Connecting";		break;
			case AgentState::Pairing:			name = "Pairing";			break;
			case AgentState::Authenticating:	name = "Authenticating";	break;
			case AgentState::Connected:			name = "Connected";			break;
		}
		return std::formatter<std::string_view>::format(name, ctx);
	}
};

Agent::Agent()
	: m_p(std::make_unique<AgentPrivate>())
{

}

Agent::~Agent() = default;

asio::awaitable<void> Agent::run()
{
	co_await asio::co_spawn(
		m_p->m_strand,
		m_p->run(),
		asio::use_awaitable
	);
}

AgentState Agent::state() const
{
	return m_p->m_state;
}

AgentPrivate::AgentPrivate()
	: m_strand(asio::make_strand(ASIOManager::Instance().ioContext()))
	, m_resolver(m_strand)
	, m_logger(Logger::Instance())
{

}

asio::awaitable<void> AgentPrivate::run()
{
	while (true)
	{
		try
		{
			m_context = co_await connect(kHostname, kPort);
			co_await eventLoop();
		}
		catch (const std::exception& error)
		{
			m_logger.error("Agent connection failed; retrying in 5 seconds: {}", error.what());
		}

		if (m_context)
			disconnect(m_context);
		m_context.reset();

		asio::steady_timer timer(co_await asio::this_coro::executor);
		timer.expires_after(std::chrono::seconds(5));
		co_await timer.async_wait(asio::use_awaitable);
	}
}

void AgentPrivate::setState(AgentState state) const
{
	if (std::exchange(m_state, state) != m_state)
		m_logger.debug(std::format("Changing state to {}", state));
}

asio::awaitable<std::shared_ptr<AgentPrivate::Context>> AgentPrivate::connect(std::string host, std::string port)
{
	setState(AgentState::Connecting);
	m_logger.info(std::format("Connecting to Scorch server at {}:{}", host, port));

	auto executor = co_await asio::this_coro::executor;

	TLSSocket socket(executor, ASIOManager::Instance().sslContext());
	auto endpoints = co_await m_resolver.async_resolve(host, port, asio::use_awaitable);

	//	Verify:
	//		- Certificate was signed by a trusted CA
	//		- Certificate was actually issued to the connected host
	socket.set_verify_callback(asio::ssl::host_name_verification(host));

	// Sets the hostname so that the server selects the appropriate certificate
	// for the associated IP address
	SSL_set_tlsext_host_name(socket.native_handle(), host.c_str());

	co_await asio::async_connect(socket.next_layer(), endpoints, asio::use_awaitable);

	m_logger.debug("Starting TLS handshake");
	co_await socket.async_handshake(asio::ssl::stream_base::client, asio::use_awaitable);

	m_logger.info("Connected to Scorch server");
	co_return std::make_shared<Context>(
		std::move(host),
		std::move(port),
		std::move(socket)
	);
}

asio::awaitable<void> AgentPrivate::eventLoop()
{
	while (m_state != AgentState::Disconnected)
	{
		switch (m_state)
		{
			case AgentState::Connecting:
			case AgentState::Authenticating:
				co_await authenticate();
				break;
			case AgentState::Pairing:
				co_await pair();
				break;
			case AgentState::Connected:
				co_await connected();
				break;
			default:
				break;
		}
	}
}

asio::awaitable<void> AgentPrivate::authenticate()
{
	assert(m_state == AgentState::Connecting || m_state == AgentState::Authenticating);

	const std::optional<std::string> uuidOpt = m_credentials.getUUID();
	if (! uuidOpt.has_value())
	{
		setState(AgentState::Pairing);
		co_return;
	}

	const std::string& uuid = *uuidOpt;

	m_logger.info("Authenticating agent {}", uuid);
	setState(AgentState::Authenticating);

	co_await sendAgentMessage([uuid](AgentMessage& agentMessage) {
		auto authInit = agentMessage.initAuthenticationInitiation();
		authInit.setUuid(kj::StringPtr(uuid.data(), uuid.size()));
	});

	std::string signature;
	ReceivedMessage initiation = co_await readServerMessage(m_context);
	ServerMessage initiationMessage = initiation.message;
	if (IsInvalidInititationMessage(initiationMessage) || ! initiationMessage.isAuthenticationInitiation())
	{
		co_await handleUnexpectedInitializationMessage(
			initiationMessage,
			"AuthenticationInitiation"
		);
		co_return;
	}

	auto authInitResponse = initiationMessage.getAuthenticationInitiation();
	if (authInitResponse.isInvalidUuid())
	{
		m_logger.warn("Server rejected agent UUID {}; requesting a new pairing code", uuid);
		setState(AgentState::Pairing);
		co_return;
	}
	if (authInitResponse.isRetry())
	{
		m_logger.warn("Server requested an authentication retry for agent {}", uuid);
		setState(AgentState::Connecting);
		co_return;
	}
	if (! authInitResponse.isChallenge())
	{
		co_await handleUnexpectedInitializationMessage(
			initiationMessage,
			"AuthenticationInitiation challenge, invalidUuid, or retry"
		);
		co_return;
	}

	auto challengeMessage = authInitResponse.getChallenge().getChallenge();
	std::string_view challenge(
		reinterpret_cast<const char*>(challengeMessage.begin()),
		challengeMessage.size()
	);

	m_logger.debug("Signing authentication challenge for agent {}", uuid);
	bool challengeSigned = true;
	try
	{
		signature = m_credentials.signChallenge(challenge);
	}
	catch (const std::exception& error)
	{
		m_logger.error("Failed to sign challenge: {}", error.what());
		challengeSigned = false;
	}

	if (! challengeSigned)
	{
		auto context = m_context;
		co_await sendAgentMessage([](AgentMessage& agentMessage) {
			agentMessage.initError().setMessage("Unable to process authentication challenge");
		}, 0, 0, context);
		disconnect(context);
		co_return;
	}

	co_await sendAgentMessage([&signature](AgentMessage& agentMessage) {
		auto authReq = agentMessage.initAuthenticationRequest();

		authReq.setSignature(
			kj::ArrayPtr<const kj::byte>(
				reinterpret_cast<const kj::byte*>(signature.data()),
				signature.size()
			)
		);
	});

	ReceivedMessage result = co_await readServerMessage(m_context);
	ServerMessage resultMessage = result.message;
	if (IsInvalidInititationMessage(resultMessage) || ! resultMessage.isAuthenticationResult())
	{
		co_await handleUnexpectedInitializationMessage(
			resultMessage,
			"AuthenticationResult"
		);
		co_return;
	}

	auto authResult = resultMessage.getAuthenticationResult();
	if (authResult.isChallengeFailed())
	{
		m_logger.warn("Authentication challenge failed for agent {}; retrying", uuid);
		setState(AgentState::Connecting);
		co_return;
	}
	if (! authResult.isSuccess())
	{
		co_await handleUnexpectedInitializationMessage(
			resultMessage,
			"AuthenticationResult success or challengeFailed"
		);
		co_return;
	}

	m_logger.info("Agent {} authenticated successfully", uuid);
	setState(AgentState::Connected);

	co_return;
}

asio::awaitable<void> AgentPrivate::pair()
{
	assert(m_state == AgentState::Pairing);

	const std::string uuid = m_credentials.generateUUID();

	co_await sendAgentMessage([this, &uuid](AgentMessage& agentMessage) {
		auto pairRequest = agentMessage.initPair();

		pairRequest.setUuid(kj::StringPtr(uuid.data(), uuid.size()));
		pairRequest.setPublicKey(
			kj::ArrayPtr<const kj::byte>(
				reinterpret_cast<const kj::byte*>(m_credentials.getPublicKey().data()),
				m_credentials.getPublicKey().size()
			)
		);
	});

	std::string pairCode;
	ReceivedMessage pairCodeMessage = co_await readServerMessage(m_context);
	ServerMessage pairCodeEnvelope = pairCodeMessage.message;
	if (IsInvalidInititationMessage(pairCodeEnvelope) || ! pairCodeEnvelope.isPairCode())
	{
		co_await handleUnexpectedInitializationMessage(
			pairCodeEnvelope,
			"PairCode"
		);
		co_return;
	}

	auto pairCodeResult = pairCodeEnvelope.getPairCode();
	if (pairCodeResult.isInvalid())
	{
		m_logger.warn("Server rejected generated agent UUID {}; retrying", uuid);
		co_return;
	}
	if (pairCodeResult.isRetry())
	{
		m_logger.warn("Server requested another pairing code for agent {}", uuid);
		co_return;
	}
	if (! pairCodeResult.isValid())
	{
		co_await handleUnexpectedInitializationMessage(
			pairCodeEnvelope,
			"PairCode valid, invalid, or retry"
		);
		co_return;
	}

	pairCode = pairCodeResult.getValid().getCode();

	m_logger.info(std::format("Pairing code: {}", pairCode));

	std::string pairingInfo;
	// Await user entering pair code
	ReceivedMessage pairingMessage = co_await readServerMessage(m_context);
	ServerMessage pairingEnvelope = pairingMessage.message;
	if (IsInvalidInititationMessage(pairingEnvelope) || ! pairingEnvelope.isPairingResult())
	{
		co_await handleUnexpectedInitializationMessage(
			pairingEnvelope,
			"PairingResult"
		);
		co_return;
	}

	auto pairingResult = pairingEnvelope.getPairingResult();
	if (pairingResult.isTimedOut())
	{
		m_logger.warn("Pairing code expired; requesting another");
		co_return;
	}
	if (! pairingResult.isSuccess())
	{
		co_await handleUnexpectedInitializationMessage(
			pairingEnvelope,
			"PairingResult success or timedOut"
		);
		co_return;
	}

	auto pairingSuccess = pairingResult.getSuccess();
	pairingInfo = pairingSuccess.getPairingInfo();

	m_logger.info("Pairing approval requested");
	std::cout << "Did you authorize this pairing request? " << pairingInfo << " [y / N]: " << std::flush;
	std::string response;
	std::getline(std::cin, response);

	const bool authorised = response == "y" || response == "Y";
	m_logger.info("Pairing request {}", authorised ? "approved" : "rejected");
	co_await sendAgentMessage([authorised](AgentMessage& agentMessage) {
		auto pairingConfirmation = agentMessage.initPairingConfirmation();
		if (authorised)
			pairingConfirmation.setApproved();
		else
			pairingConfirmation.setRejected();
	});

	setState(AgentState::Authenticating);
}

asio::awaitable<void> AgentPrivate::handleUnexpectedInitializationMessage(ServerMessage message, std::string_view expected)
{
	auto context = m_context;

	if (message.isError())
	{
		m_logger.warn(
			"Server reset initialization: {}",
			message.getError().getMessage().cStr()
		);
	}
	else
	{
		const std::string error = std::format(
			"Unexpected initialization message; expected {}",
			expected
		);
		m_logger.warn(error);

		co_await sendAgentMessage([&error](AgentMessage& agentMessage) {
			agentMessage.initError().setMessage(
				kj::StringPtr(error.data(), error.size())
			);
		}, 0, 0, context);
	}

	// Restart on a fresh stream so queued messages from the failed
	// initialization attempt cannot trigger another reset.
	disconnect(context);
}

asio::awaitable<void> AgentPrivate::connected()
{
	assert(m_state == AgentState::Connected);
	auto context = m_context;

	try
	{
		while (m_state == AgentState::Connected && m_context == context)
		{
			auto received = co_await readServerMessage(context);
			const uint64_t messageId = received.message.getMessageId();
			const uint64_t replyTo = received.message.getReplyTo();

			if (messageId == 0)
			{
				m_logger.warn("Ignoring connected message without an ID");
				continue;
			}

			if (replyTo != 0)
			{
				onResponse(context, received.message);
				continue;
			}

			asio::co_spawn(
				m_strand,
				[this, context, messageId, received = std::move(received)]() mutable -> asio::awaitable<void> {
					try
					{
						co_await handleConnectedMessage(context, std::move(received));
					}
					catch (const std::exception& error)
					{
						m_logger.error("Failed to handle server message {}: {}", messageId, error.what());
						disconnect(context);
					}
					catch (...)
					{
						m_logger.error("Failed to handle server message {}: unknown error", messageId);
						disconnect(context);
					}
				},
				asio::detached
			);
		}
	}
	catch (...)
	{
		failPendingRequests(context, std::current_exception());
		throw;
	}

	if (! context->pendingRequests.empty())
	{
		failPendingRequests(
			context,
			std::make_exception_ptr(std::runtime_error("Server disconnected"))
		);
	}
}

asio::awaitable<void> AgentPrivate::handleConnectedMessage(std::shared_ptr<Context> context,ReceivedMessage received)
{
	const uint64_t messageId = received.message.getMessageId();

	switch (received.message.which())
	{
		case scorch::protocol::ServerMessage::HEARTBEAT:
			co_await onHeartbeat(context, received.message.getHeartbeat(), messageId);
			break;

		case scorch::protocol::ServerMessage::COMMAND:
			co_await onCommandRequest(context, received.message.getCommand(), messageId);
			break;

		case scorch::protocol::ServerMessage::SHARE_REQUEST:
			co_await onShareRequest(context, received.message.getShareRequest(), messageId);
			break;

		case scorch::protocol::ServerMessage::ERROR:
			m_logger.error(
				"Received uncorrelated protocol error in message {}: {}",
				messageId,
				received.message.getError().getMessage().cStr()
			);
			break;

		default:
			m_logger.warn(
				"Server message {} has unsupported type {}",
				messageId,
				static_cast<unsigned int>(received.message.which())
			);
			co_await sendProtocolError(context, messageId, "Unsupported message");
			break;
	}
}

asio::awaitable<void> AgentPrivate::onHeartbeat(std::shared_ptr<Context> context, scorch::protocol::Heartbeat::Reader heartbeat, uint64_t requestId)
{
	m_logger.trace("Received heartbeat request {}", requestId);
	auto ms = heartbeat.getTimestamp();
	co_await sendAgentMessage([ms](AgentMessage& agentMessage) {
		auto heartbeat = agentMessage.initHeartbeat();
		heartbeat.setTimestamp(ms);
	}, nextMessageId(context), requestId, context);

	co_return;
}

asio::awaitable<void> AgentPrivate::onCommandRequest(std::shared_ptr<Context> context, scorch::protocol::CommandRequest::Reader request, uint64_t requestId)
{
	auto which = request.which();
	m_logger.trace("Received command request {} with type {}", requestId, static_cast<int>(which));

	using Type = decltype(which);
	switch (which)
	{
		case Type::HTTP:
			co_await onHTTPCommand(context, request.getHttp(), requestId);
			co_return;
		default:
			break;
	}

	const std::string errorMessage = std::format("Unknown command request type {}", static_cast<int>(which));
	m_logger.warn("Command request {} has unknown type {}", requestId, static_cast<int>(which));
	co_await sendAgentMessage([errorMessage](AgentMessage& agentMessage) {
		auto commandResponse = agentMessage.initCommand();
		commandResponse.setError(kj::StringPtr(errorMessage.data(), errorMessage.size()));
	}, nextMessageId(context), requestId, context);

	co_return;
}

asio::awaitable<void> AgentPrivate::onShareRequest(
	std::shared_ptr<Context> context,
	scorch::protocol::ShareRequest::Reader request,
	uint64_t requestId
)
{
	m_logger.info("Share approval requested for message {}", requestId);
	const bool approved = co_await requestShareApproval(request.getInfo().cStr());
	m_logger.info("Share request {} {}", requestId, approved ? "approved" : "rejected");

	co_await sendAgentMessage([approved](AgentMessage& agentMessage) {
		auto confirmation = agentMessage.initShareConfirmation();
		if (approved)
			confirmation.setApproved();
		else
			confirmation.setRejected();
	}, nextMessageId(context), requestId, context);
}

asio::awaitable<bool> AgentPrivate::requestShareApproval(std::string info)
{
	co_return co_await asio::co_spawn(
		m_consoleThread,
		[info = std::move(info)]() -> asio::awaitable<bool> {
			std::cout << "Share request: " << info << "\nAuthorize sharing this agent? [y / N]: " << std::flush;

			std::string response;
			std::getline(std::cin, response);
			co_return response == "y" || response == "Y";
		},
		asio::use_awaitable
	);
}

void AgentPrivate::onResponse(const std::shared_ptr<Context>& context, ServerMessage response)
{
	const uint64_t replyTo = response.getReplyTo();
	m_logger.trace("Received response to message {}", replyTo);

	auto it = context->pendingRequests.find(replyTo);
	if (it == context->pendingRequests.end())
	{
		m_logger.warn("Server replied to unknown message {}", replyTo);
		return;
	}

	auto pending = it->second;
	context->pendingRequests.erase(it);
	pending->complete(response);
}

asio::awaitable<void> AgentPrivate::sendProtocolError(std::shared_ptr<Context> context, uint64_t replyTo, std::string_view message)
{
	co_await sendAgentMessage([message](AgentMessage& agentMessage) {
		agentMessage.initError().setMessage(kj::StringPtr(message.data(), message.size()));
	}, nextMessageId(context), replyTo, context);
}

asio::awaitable<void> AgentPrivate::onHTTPCommand(std::shared_ptr<Context> context, scorch::protocol::HttpCommand::Reader command, uint64_t requestId)
{
	scorch::agent::http::Request request;
	request.url = command.getUrl().cStr();
	request.method = command.getMethod().cStr();
	m_logger.debug("Executing HTTP command {} with method {}", requestId, request.method);

	const auto requestHeaders = command.getHeaders();
	request.headers.reserve(requestHeaders.size());
	for (const auto header : requestHeaders)
	{
		request.headers.push_back({
			header.getName().cStr(),
			header.getValue().cStr()
		});
	}

	const auto requestBody = command.getBody();
	request.body.assign(
		reinterpret_cast<const std::byte*>(requestBody.begin()),
		reinterpret_cast<const std::byte*>(requestBody.end())
	);

	std::optional<scorch::agent::http::Response> response;
	std::string errorMessage;
	try
	{
		response = co_await scorch::agent::http::Execute(
			std::move(request),
			ASIOManager::Instance().sslContext()
		);
	}
	catch (const std::exception& error)
	{
		errorMessage = std::format("HTTP request failed: {}", error.what());
		m_logger.warn("HTTP command {} failed: {}", requestId, error.what());
	}

	if (! response)
	{
		co_await sendAgentMessage([errorMessage](AgentMessage& agentMessage) {
			auto commandResponse = agentMessage.initCommand();
			commandResponse.setTimestamp(
				std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::system_clock::now().time_since_epoch()
				).count()
			);
			commandResponse.setError(
				kj::StringPtr(errorMessage.data(), errorMessage.size())
			);
		}, nextMessageId(context), requestId, context);
		co_return;
	}

	m_logger.debug(
		"HTTP command {} completed with status {}",
		requestId,
		response->status
	);

	co_await sendAgentMessage([response = std::move(*response)](AgentMessage& agentMessage) {
		auto commandResponse = agentMessage.initCommand();
		commandResponse.setTimestamp(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::system_clock::now().time_since_epoch()
			).count()
		);

		auto httpResponse = commandResponse.initHttpResponse();
		httpResponse.setStatusCode(response.status);

		if (response.headers.size() > std::numeric_limits<capnp::uint>::max())
			throw std::length_error("Too many HTTP response headers");

		auto headers = httpResponse.initHeaders(static_cast<capnp::uint>(response.headers.size()));
		for (capnp::uint i = 0; i < headers.size(); ++i)
		{
			headers[i].setName(response.headers[i].name);
			headers[i].setValue(response.headers[i].value);
		}

		httpResponse.setBody(
			kj::ArrayPtr<const kj::byte>(
				reinterpret_cast<const kj::byte*>(response.body.data()),
				response.body.size()
			)
		);
	}, nextMessageId(context), requestId, context);
}

asio::awaitable<Buffer> AgentPrivate::read(const std::shared_ptr<Context>& context)
{
	uint32_t size;

	co_await asio::async_read(
		context->socket,
		asio::buffer(&size, sizeof(size)),
		asio::use_awaitable
	);

	size = ntohl(size);
	if (size > kMaxMessageSize)
		throw std::runtime_error("Message too large");

	Buffer buffer(size);

	co_await asio::async_read(
		context->socket,
		asio::buffer(buffer),
		asio::use_awaitable
	);

	co_return buffer;
}

asio::awaitable<ReceivedMessage> AgentPrivate::readServerMessage(const std::shared_ptr<Context>& context)
{
	auto response = co_await read(context);

	if (response.size() % sizeof(capnp::word) != 0)
		throw std::runtime_error("Invalid Cap'n Proto message size");

	co_return ReceivedMessage(std::move(response));
}

asio::awaitable<void> AgentPrivate::writeMessage(capnp::MallocMessageBuilder& message, std::shared_ptr<Context> context)
{
	auto serialized = capnp::messageToFlatArray(message);
	auto bytes = serialized.asBytes();

	const uint32_t size = htonl(static_cast<uint32_t>(bytes.size()));
	Buffer frame(sizeof(size) + bytes.size());

	std::memcpy(frame.data(), &size, sizeof(size));
	std::memcpy(frame.data() + sizeof(size), bytes.begin(), bytes.size());

	auto lock = co_await context->writeMutex.lock();
	co_await asio::async_write(
		context->socket,
		asio::buffer(frame),
		asio::use_awaitable
	);
}

uint64_t AgentPrivate::nextMessageId(const std::shared_ptr<Context>& context)
{
	uint64_t id = ++context->messageId;

	while (id == 0 || context->pendingRequests.contains(id))
		id = ++context->messageId;
	
	return id;
}

void AgentPrivate::failPendingRequests(const std::shared_ptr<Context>& context,std::exception_ptr error)
{
	for (auto& entry : context->pendingRequests)
		entry.second->fail(error);

	context->pendingRequests.clear();
}

void AgentPrivate::disconnect(const std::shared_ptr<Context>& context)
{
	if (m_context == context)
		setState(AgentState::Disconnected);

	if (! context->pendingRequests.empty())
	{
		failPendingRequests(
			context,
			std::make_exception_ptr(std::runtime_error("Server disconnected"))
		);
	}

	if (! context->socket.next_layer().is_open())
		return;

	m_logger.info("Closing connection to Scorch server");
	boost::system::error_code ec;
	context->socket.next_layer().cancel(ec);
	context->socket.next_layer().shutdown(tcp::socket::shutdown_both, ec);
	context->socket.next_layer().close(ec);
}

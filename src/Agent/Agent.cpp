#include "Agent.hpp"
#include "Agent_p.hpp"

#include "ASIOManager.hpp"
#include "Logger.hpp"

#include <format>
#include <iostream>
#include <optional>

namespace
{
	constexpr auto kHostname = "localhost";
	constexpr auto kPort = "3224";
	constexpr std::uint32_t kMaxMessageSize = 1024 * 1024;
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
	while (true)
	{
		{
			try
			{
				m_p->m_context.reset();
				m_p->m_context.emplace(co_await m_p->connect(kHostname, kPort));
				co_await m_p->eventLoop();
			}
			catch (const std::exception& e)
			{
				Logger::Instance().error(e.what());
			}

			if (m_p->m_context)
				m_p->close(std::move(*m_p->m_context));
			m_p->m_context.reset();
		}

		asio::steady_timer timer(co_await asio::this_coro::executor);

		timer.expires_after(std::chrono::seconds(5));

		co_await timer.async_wait(asio::use_awaitable);
	}
}

AgentState Agent::state() const
{
	return m_p->m_state;
}

AgentPrivate::AgentPrivate()
	: m_resolver(ASIOManager::Instance().ioContext())
	, m_logger(Logger::Instance())
{

}

void AgentPrivate::setState(AgentState state) const
{
	if (std::exchange(m_state, state) != m_state)
		m_logger.debug(std::format("Changing state to {}", state));
}

asio::awaitable<AgentPrivate::Context> AgentPrivate::connect(std::string host, std::string port)
{
	setState(AgentState::Connecting);
	m_logger.info(std::format("Connecting to {} on port {}...", host, port));

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

	m_logger.info("Awaiting TLS handshake...");
	co_await socket.async_handshake(asio::ssl::stream_base::client, asio::use_awaitable);

	m_logger.info("Connected");
	co_return Context{
		.host	= std::move(host),
		.port	= std::move(port),
		.socket	= std::move(socket),
	};
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
				co_await listen();
				break;
			default:
				break;
		}
	}
}

asio::awaitable<void> AgentPrivate::authenticate()
{
	assert(m_state == AgentState::Connecting || m_state == AgentState::Authenticating);
	bool success = true;

	if (! m_credentials.getUUID().has_value())
	{
		setState(AgentState::Pairing);
		co_return;
	}

	std::string_view uuid = *m_credentials.getUUID();

	m_logger.info("Authenticating...");
	setState(AgentState::Authenticating);

	co_await sendAgentMessage([uuid](AgentMessage& agentMessage) {
		auto authInit = agentMessage.initAuthenticationInitiation();
		authInit.setUuid(kj::StringPtr(uuid.data(), uuid.size()));
	});

	std::string signature;

	co_await readServerMessage([this, &signature, &success](ServerMessage& serverMessage) {
		if (! serverMessage.isAuthenticationInitiation())
		{
			m_logger.error("Unexpected server response. Expected AuthenticationInitiation");
			success = false;
			return;
		}

		auto authInitResponse = serverMessage.getAuthenticationInitiation();
		if (authInitResponse.isInvalidUuid())
		{
			m_logger.info("Server says UUID is invalid. Requesting new pairing code.");
			setState(AgentState::Pairing);
			success = false;
			return;
		}
		else if (! authInitResponse.isChallenge())
		{
			m_logger.error("AuthenticationInitiation was not successful for an unknown reason.");
			success = false;
			return;
		}

		auto challengeMessage = authInitResponse.getChallenge().getChallenge();
		std::string_view challenge(
			reinterpret_cast<const char*>(challengeMessage.begin()),
			challengeMessage.size()
		);

		m_logger.debug("Challenge received. Signing");
		try
		{
			signature = m_credentials.signChallenge(challenge);
		}
		catch (const std::exception& e)
		{
			m_logger.error("Failed to sign challenge: {}", e.what());
			success = false;
			return;
		}
	});
	if (! success)
		co_return;

	co_await sendAgentMessage([&signature](AgentMessage& agentMessage) {
		auto authReq = agentMessage.initAuthenticationRequest();

		authReq.setSignature(
			kj::ArrayPtr<const kj::byte>(
				reinterpret_cast<const kj::byte*>(signature.data()),
				signature.size()
			)
		);
	});

	co_await readServerMessage([this, &success](ServerMessage& serverMessage) {
		if (! serverMessage.isAuthenticationResult())
		{
			m_logger.error("Unexpected server response. Expected AuthenticationResult");
			success = false;
			return;
		}

		auto authResult = serverMessage.getAuthenticationResult();
		if (authResult.isChallengeFailed())
		{
			m_logger.error("Challenge failed. Retrying");
			success = false;
			return;
		}
		else if (! authResult.isSuccess())
		{
			m_logger.error("Authentication Request was not successful for an unknown reason");
			success = false;
			return;
		}
	});
	if (! success)
		co_return;

	m_logger.info("Authentication successful");
	setState(AgentState::Connected);

	co_return;
}

asio::awaitable<void> AgentPrivate::pair()
{
	assert(m_state == AgentState::Pairing);
	bool success = true;

	co_await sendAgentMessage([this](AgentMessage& agentMessage) {
		auto pairRequest = agentMessage.initPair();

		std::string_view uuid = m_credentials.generateUUID();
		pairRequest.setUuid(kj::StringPtr(uuid.data(), uuid.size()));
		pairRequest.setPublicKey(
			kj::ArrayPtr<const kj::byte>(
				reinterpret_cast<const kj::byte*>(m_credentials.getPublicKey().data()),
				m_credentials.getPublicKey().size()
			)
		);
	});

	std::string pairCode;

	co_await readServerMessage([this, &success, &pairCode](ServerMessage& serverMessage) {
		if (! serverMessage.isPairCode())
		{
			m_logger.error("Unexpected server response. Expected PairCode");
			success = false;
			return;
		}

		auto pairCodeResult = serverMessage.getPairCode();
		success = pairCodeResult.isValid();
		if (pairCodeResult.isInvalid())
			m_logger.info("Server rejected UUID. Retrying");
		else if (pairCodeResult.isRetry())
			m_logger.info("Server asked to request for another pairing code. Retrying");

		if (! success)
			return;

		pairCode = pairCodeResult.getValid().getCode();
	});
	if (! success)
		co_return;

	m_logger.info(std::format("Pairing Code received: {}", pairCode));

	std::string pairingInfo;
	// Await user entering pair code
	co_await readServerMessage([this, &success, &pairingInfo](ServerMessage& serverMessage) {
		if (! serverMessage.isPairingResult())
		{
			m_logger.error("Unexpected server response. Expected PairingResult");
			success = false;
			return;
		}

		auto pairingResult = serverMessage.getPairingResult();
		if (pairingResult.isTimedOut())
		{
			m_logger.info("Pairing timed out. Requesting new Pairing Code");
			success = false;
			return;
		}
		else if (! pairingResult.isSuccess())
		{
			m_logger.error("Pairing was not succesful due to an unknown reason");
			success = false;
			return;
		}
		auto pairingSuccess = pairingResult.getSuccess();
		pairingInfo = pairingSuccess.getPairingInfo();
	});
	if (! success)
		co_return;

	m_logger.info("Pairing request confirmed: {}", pairingInfo);
	std::cout << "Did you authorize this pairing request? " << pairingInfo << " [y / N]: " << std::flush;
	std::string response;
	std::getline(std::cin, response);

	const bool authorised = response == "y" || response == "Y";
	co_await sendAgentMessage([authorised](AgentMessage& agentMessage) {
		auto pairingConfirmation = agentMessage.initPairingConfirmation();
		if (authorised)
			pairingConfirmation.setApproved();
		else
			pairingConfirmation.setRejected();
	});

	setState(AgentState::Authenticating);
}

asio::awaitable<void> AgentPrivate::listen()
{
	assert(m_state == AgentState::Connected);

	while (m_state == AgentState::Connected)
	{
		auto message = co_await read();
	}

	co_return;
}

asio::awaitable<Buffer> AgentPrivate::read()
{
	uint32_t size;

	co_await asio::async_read(
		m_context->socket,
		asio::buffer(&size, sizeof(size)),
		asio::use_awaitable
	);

	size = ntohl(size);
	if (size > kMaxMessageSize)
		throw std::runtime_error("Message too large");

	Buffer buffer(size);

	co_await asio::async_read(
		m_context->socket,
		asio::buffer(buffer),
		asio::use_awaitable
	);

	co_return buffer;
}

asio::awaitable<void> AgentPrivate::handleMessage(std::string_view message)
{
	co_return;
}

asio::awaitable<void> AgentPrivate::writeMessage(capnp::MallocMessageBuilder& message)
{
	auto serialized = capnp::messageToFlatArray(message);
	auto bytes = serialized.asBytes();

	std::uint32_t size = htonl(static_cast<std::uint32_t>(bytes.size()));

	co_await asio::async_write(
		m_context->socket,
		asio::buffer(&size, sizeof(size)),
		asio::use_awaitable
	);

	co_await asio::async_write(
		m_context->socket,
		asio::buffer(bytes.begin(), bytes.size()),
		asio::use_awaitable
	);
}

void AgentPrivate::close(Context&& ctx)
{
	m_logger.info("Closing websocket");
	boost::system::error_code ec;
	ctx.socket.next_layer().shutdown(tcp::socket::shutdown_both, ec);
	ctx.socket.next_layer().close(ec);
}

#include "ASIOManager.hpp"
#include "ASIOManager_p.hpp"

#include "Logger.hpp"

#include <cstdlib>

ASIOManager& ASIOManager::Instance()
{
	static ASIOManager gManager;
	return gManager;
}

ASIOManager::ASIOManager()
	: m_p(std::make_unique<ASIOManagerPrivate>())
{

}

ASIOManager::~ASIOManager() = default;

asio::io_context& ASIOManager::ioContext() const
{
	return m_p->m_ioContext;
}

asio::ssl::context& ASIOManager::sslContext() const
{
	return m_p->m_sslContext;
}

ASIOManagerPrivate::ASIOManagerPrivate()
	: m_sslContext(asio::ssl::context::tls_client)
	, m_workGuard(asio::make_work_guard(m_ioContext))
	, m_ioThread([this](std::stop_token) {
		m_ioContext.run();
	})
{
	const auto envValue = std::getenv("DISABLE_SSL_VERIFY");
	const bool disableSSLVerification = (envValue != nullptr && std::string(envValue) == "1");
	if (disableSSLVerification)
	{
		Logger::Instance().warn("SSL Verification Disabled. Be careful");
		m_sslContext.set_verify_mode(boost::asio::ssl::verify_none);
	}
	else
	{
		// Use the OS's trusted CAs
		m_sslContext.set_verify_mode(boost::asio::ssl::verify_peer);
		m_sslContext.set_default_verify_paths();
	}
}

ASIOManagerPrivate::~ASIOManagerPrivate()
{
	m_ioContext.stop();
}

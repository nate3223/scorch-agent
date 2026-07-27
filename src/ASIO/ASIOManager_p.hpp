#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <thread>

namespace asio = boost::asio;

class ASIOManagerPrivate
{
public:
	ASIOManagerPrivate();
	~ASIOManagerPrivate();

	using WorkGuard = asio::executor_work_guard<asio::io_context::executor_type>;

	// Must outlive all objects that use it.
	asio::io_context	m_ioContext;

	asio::ssl::context	m_sslContext;

	// Declared last so the IO thread is destroyed first.
	// The destructor must stop the context before member destruction begins.
	WorkGuard			m_workGuard;
	std::jthread		m_ioThread;
};

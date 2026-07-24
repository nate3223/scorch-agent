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

	asio::io_context	m_ioContext;
	asio::ssl::context	m_sslContext;
	WorkGuard			m_workGuard;
	std::jthread		m_ioThread;
};

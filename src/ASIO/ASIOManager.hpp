#pragma once

#include <memory>

namespace boost
{
	namespace asio
	{
		class io_context;
		namespace ssl
		{
			class context;
		}
	}
}

class ASIOManagerPrivate;

class ASIOManager
{
public:
	static ASIOManager&				Instance();

	boost::asio::io_context&		ioContext() const;
	boost::asio::ssl::context&		sslContext() const;

private:
									ASIOManager();
									~ASIOManager();

	std::unique_ptr<ASIOManagerPrivate>	m_p;
};

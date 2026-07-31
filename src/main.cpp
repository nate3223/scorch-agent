#include "Agent/Agent.hpp"
#include "ASIO/ASIOManager.hpp"
#include "Log/Logger.hpp"

#include <boost/asio.hpp>

int main(int argc, char* argv[])
{
	Logger::Instance().info("Scorch Agent started");

	Agent agent;

	auto& ioContext = ASIOManager::Instance().ioContext();
	boost::asio::co_spawn(ioContext, agent.run(), boost::asio::detached);

	ioContext.run();

	Logger::Instance().info("Scorch Agent stopped");

	return 0;
}

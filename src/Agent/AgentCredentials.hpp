#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>

class AgentCredentialsPrivate;

class AgentCredentials
{
public:
								AgentCredentials();
								~AgentCredentials();

	std::string					getPublicKey() const;
	std::string					getPrivateKey() const;
	std::optional<std::string>	getUUID() const;
	std::string					generateUUID();

	std::string					signChallenge(std::string_view challenge) const;

private:
	std::unique_ptr<AgentCredentialsPrivate>	m_p;
};

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

	std::string_view				getPublicKey() const;
	std::string_view				getPrivateKey() const;
	std::optional<std::string_view>	getUUID() const;
	std::string_view				generateUUID();

	std::string						signChallenge(std::string_view challenge) const;

private:
	std::unique_ptr<AgentCredentialsPrivate>	m_p;
};

#pragma once

#include <optional>
#include <string>

class AgentCredentialsPrivate
{
public:
	AgentCredentialsPrivate();

	std::string					m_publicKey;
	std::string					m_privateKey;
	std::optional<std::string>	m_uuid;
};

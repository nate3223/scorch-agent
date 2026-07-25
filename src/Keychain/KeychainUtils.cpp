#include "KeychainUtils.hpp"

#include <Keychain/keychain.h>

namespace
{
	constexpr auto kPackageName = "com.scorch.agent";
	constexpr auto kServiceName = "agent-identity";
}

std::optional<std::string> KeychainUtils::Load(const std::string& key)
{
	keychain::Error error;
	std::string value = keychain::getPassword(kPackageName, kServiceName, key, error);

	return error ? std::nullopt : std::optional<std::string>{ std::move(value) };
}

bool KeychainUtils::Save(const std::string& key, const std::string& value)
{
	keychain::Error error;
	keychain::setPassword(kPackageName, kServiceName, key, value, error);

	return error;
}

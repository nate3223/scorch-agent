#pragma once

#include <optional>
#include <string>

class KeychainUtils
{
public:
	static std::optional<std::string>	Load(const std::string& key);
	static bool							Save(const std::string& key, const std::string& value);
};

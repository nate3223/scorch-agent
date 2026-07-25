#include "AgentCredentials.hpp"
#include "AgentCredentials_p.hpp"

#include "KeychainUtils.hpp"
#include "Logger.hpp"

#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <openssl/evp.h>

#include <stdexcept>
#include <vector>

namespace
{
	constexpr auto kPublicKey	= "PublicKey";
	constexpr auto kPrivateKey	= "PrivateKey";
	constexpr auto kUUID		= "UUID";

	void GenerateKeyPair(std::string& privateKey, std::string& publicKey)
	{
		EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
		if (! context)
			throw std::runtime_error("Failed to create key context");

		std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> contextGuard(context, EVP_PKEY_CTX_free);
		if (EVP_PKEY_keygen_init(context) <= 0)
			throw std::runtime_error("Failed to initialisekey generation");

		EVP_PKEY* rawKey = nullptr;
		if (EVP_PKEY_keygen(context, &rawKey) <= 0)
			throw std::runtime_error("Failed to generate key pair");

		std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(rawKey, EVP_PKEY_free);
		std::vector<std::byte> privateKeyVec(32);
		std::vector<std::byte> publicKeyVec(32);

		size_t privateKeySize = privateKeyVec.size();
		size_t publicKeySize = publicKeyVec.size();

		if (EVP_PKEY_get_raw_private_key(key.get(), reinterpret_cast<unsigned char*>(privateKeyVec.data()), &privateKeySize) <= 0)
			throw std::runtime_error("Failed to extract private key");

		if (EVP_PKEY_get_raw_public_key(key.get(), reinterpret_cast<unsigned char*>(publicKeyVec.data()), &publicKeySize) <= 0)
			throw std::runtime_error("Failed to extract public key");

		privateKeyVec.resize(privateKeySize);
		publicKeyVec.resize(publicKeySize);

		privateKey.assign(reinterpret_cast<const char*>(privateKeyVec.data()), privateKeySize);
		publicKey.assign(reinterpret_cast<const char*>(publicKeyVec.data()), publicKeySize);
	}

	std::string SignChallenge(std::string_view privateKey, std::string_view challenge)
	{
		EVP_PKEY* rawKey = EVP_PKEY_new_raw_private_key(
			EVP_PKEY_ED25519,
			nullptr,
			reinterpret_cast<const unsigned char*>(privateKey.data()),
			privateKey.size()
		);

		if (! rawKey)
			throw std::runtime_error("Failed to create raw key from private key");

		std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(rawKey, EVP_PKEY_free);
		EVP_MD_CTX* rawContext = EVP_MD_CTX_new();

		if (! rawContext)
			throw std::runtime_error("Failed to create digest context");

		std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(rawContext, EVP_MD_CTX_free);
		if (EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, key.get()) <= 0)
			throw std::runtime_error("Failed to initialise signing");

		size_t signatureSize = 0;
		if (EVP_DigestSign(context.get(), nullptr, &signatureSize, reinterpret_cast<const unsigned char*>(challenge.data()), challenge.size()) <= 0)
			throw std::runtime_error("Failed to determine signature size");

		std::string signature(signatureSize, '\0');
		if (EVP_DigestSign(context.get(), reinterpret_cast<unsigned char*>(signature.data()), &signatureSize, reinterpret_cast<const unsigned char*>(challenge.data()), challenge.size()) <= 0)
			throw std::runtime_error("Failed to sign challenge");

		signature.resize(signatureSize);

		return signature;
	}

	std::string GenerateUUID()
	{
		boost::uuids::random_generator generator;
		return boost::uuids::to_string(generator());
	}
}

AgentCredentials::AgentCredentials()
	: m_p(std::make_unique<AgentCredentialsPrivate>())
{

}

AgentCredentials::~AgentCredentials() = default;

std::string_view AgentCredentials::getPublicKey() const
{
	return m_p->m_publicKey;
}

std::string_view AgentCredentials::getPrivateKey() const
{
	return m_p->m_privateKey;
}

std::optional<std::string_view> AgentCredentials::getUUID() const
{
	return m_p->m_uuid;
}

std::string_view AgentCredentials::generateUUID()
{
	m_p->m_uuid = GenerateUUID();
	KeychainUtils::Save(kUUID, *m_p->m_uuid);
	Logger::Instance().info(std::format("Generated new UUID: {}", *m_p->m_uuid));
	return *m_p->m_uuid;
}

std::string AgentCredentials::signChallenge(std::string_view challenge) const
{
	if (m_p->m_privateKey.empty())
		throw std::runtime_error("Attempted to sign challenge without a valid private key");

	return SignChallenge(m_p->m_privateKey, challenge);
}

AgentCredentialsPrivate::AgentCredentialsPrivate()
{
	std::optional<std::string> privateKey = KeychainUtils::Load(kPrivateKey);
	std::optional<std::string> publicKey = KeychainUtils::Load(kPublicKey);

	if (privateKey && publicKey)
	{
		m_privateKey = std::move(*privateKey);
		m_publicKey = std::move(*publicKey);
	}
	else
	{
		Logger::Instance().info("Generating keys for Agent credentials...");
		GenerateKeyPair(m_privateKey, m_publicKey);

		KeychainUtils::Save(kPrivateKey, m_privateKey);
		KeychainUtils::Save(kPublicKey, m_publicKey);
	}

	std::optional<std::string> uuid = KeychainUtils::Load(kUUID);
	if (uuid)
	{
		m_uuid = std::move(*uuid);
		Logger::Instance().info(std::format("Retrieved UUID from keychain: {}", *m_uuid));
	}
	else
	{
		Logger::Instance().info("No UUID found; agent requires pairing");
	}
}
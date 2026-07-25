cmake_minimum_required (VERSION 3.25)

if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
	set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
endif()

# Project name, version and description
project(ScorchAgent VERSION 1.0 DESCRIPTION "Agent for Scorch, a Discord Game Server Manager")

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
    cmake_policy(SET CMP0141 NEW)
    if(MSVC)
        set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "ProgramDatabase")
    endif()
endif()

include(FetchContent)

FetchContent_Declare(
	ScorchProtocol
	GIT_REPOSITORY https://github.com/nate3223/scorch-protocol.git
	GIT_TAG main
)
FetchContent_MakeAvailable(ScorchProtocol)

FetchContent_Declare(
    keychain
    GIT_REPOSITORY https://github.com/hrantzsch/keychain.git
    GIT_TAG        v1.3.1
)
FetchContent_MakeAvailable(keychain)

find_package(Boost REQUIRED COMPONENTS asio uuid)
find_package(OpenSSL REQUIRED)

# Create an executable
add_executable(${PROJECT_NAME}
	src/main.cpp
	
	src/Agent/Agent.cpp
	src/Agent/AgentCredentials.cpp

	src/ASIO/ASIOManager.cpp

	src/Keychain/KeychainUtils.cpp

	src/Log/Logger.cpp
)

set_target_properties(${PROJECT_NAME} PROPERTIES
	CXX_STANDARD 23
	CXX_STANDARD_REQUIRED ON
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    Boost::asio
	Boost::uuid
    OpenSSL::SSL
    OpenSSL::Crypto
	Scorch::Protocol
	keychain
)

if(NOT TARGET spdlog)
	# Stand-alone build
	find_package(spdlog REQUIRED)
endif()
target_link_libraries(${PROJECT_NAME} PRIVATE spdlog::spdlog $<$<BOOL:${MINGW}>:ws2_32>)

add_compile_options(-Wall -Wextra -Wpedantic -Wpessimizing-move -Wredundant-move)

target_include_directories(${PROJECT_NAME} PRIVATE
	src
	src/Agent
	src/ASIO
	src/Keychain
	src/Log
)

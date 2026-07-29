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

if(NOT TARGET spdlog)
	# Stand-alone build
	find_package(spdlog REQUIRED)
endif()

# Create an executable
add_executable(${PROJECT_NAME})
add_executable(Scorch::Client ALIAS ${PROJECT_NAME})

target_sources(${PROJECT_NAME}
	PUBLIC
		src/main.cpp

		src/Agent/Agent.cpp
		src/Agent/Agent.hpp
		src/Agent/Agent_p.hpp
		src/Agent/AgentCredentials.cpp
		src/Agent/AgentCredentials.hpp
		src/Agent/AgentCredentials_p.hpp

		src/ASIO/ASIOManager.cpp
		src/ASIO/ASIOManager.hpp
		src/ASIO/ASIOManager_p.hpp

		src/Keychain/KeychainUtils.cpp
		src/Keychain/KeychainUtils.hpp

		src/Log/Logger.cpp
		src/Log/Logger.hpp
)

target_compile_features(${PROJECT_NAME}
	PUBLIC
		cxx_std_23
)

target_compile_options(${PROJECT_NAME}
	PRIVATE
		$<$<CXX_COMPILER_ID:MSVC>:/W4>
		$<$<NOT:$<CXX_COMPILER_ID:MSVC>>:
			-Wall
			-Wextra
			-Wpedantic
			-Wpessimizing-move
			-Wredundant-move
		>
)

target_include_directories(${PROJECT_NAME}
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${PROJECT_NAME}
	PRIVATE
		Boost::asio
		Boost::uuid
		OpenSSL::SSL
		OpenSSL::Crypto
		Scorch::Protocol
		keychain
		spdlog::spdlog
		$<$<BOOL:${MINGW}>:ws2_32>
)

if(PROJECT_IS_TOP_LEVEL)
	include(CTest)

	if(BUILD_TESTING)
		add_executable(ScorchAgentControlFlowTests
			tests/AgentControlFlowTests.cpp
		)

		target_compile_features(ScorchAgentControlFlowTests PRIVATE cxx_std_23)
		target_include_directories(ScorchAgentControlFlowTests PRIVATE
			${CMAKE_CURRENT_SOURCE_DIR}/src
		)
		target_link_libraries(ScorchAgentControlFlowTests PRIVATE
			Scorch::Protocol
			Boost::asio
			Boost::uuid
			OpenSSL::SSL
			OpenSSL::Crypto
			spdlog::spdlog
		)

		add_test(NAME ScorchAgentControlFlowTests COMMAND ScorchAgentControlFlowTests)
	endif()
endif()

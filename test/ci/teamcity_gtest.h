/* Copyright 2015 Paul Shmakov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef H_TEAMCITY_GTEST
#define H_TEAMCITY_GTEST

#include <gtest/gtest.h>
#include <string>

#include "teamcity_messages.h"

namespace jetbrains {
namespace teamcity {

class TeamcityGoogleTestEventListener final : public ::testing::EmptyTestEventListener {
public:
	TeamcityGoogleTestEventListener();
	TeamcityGoogleTestEventListener(std::string flowid_)
		: flowid{std::move(flowid_)}
	{}


    // Fired before the test case starts.
	void OnTestCaseStart(const ::testing::TestCase& test_case) override;
    // Fired before the test starts.
	void OnTestStart(const ::testing::TestInfo& test_info) override;
    // Fired after the test ends.
	void OnTestEnd(const ::testing::TestInfo& test_info) override;
    // Fired after the test case ends.
	void OnTestCaseEnd(const ::testing::TestCase& test_case) override;

private:
    TeamcityMessages messages;
    std::string flowid;

    // Prevent copying.
	TeamcityGoogleTestEventListener(const TeamcityGoogleTestEventListener&) = delete;
	void operator =(const TeamcityGoogleTestEventListener&) = delete;
};

}
}

#endif  /* H_TEAMCITY_GTEST */

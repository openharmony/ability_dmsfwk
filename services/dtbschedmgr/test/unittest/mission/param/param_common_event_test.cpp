/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
 */

#include "gtest/gtest.h"

#define private public
#define protected public
#include "mission/param/param_common_event.h"
#undef private
#undef protected

#include "cJSON.h"
#include "want.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "ParamCommonEventTest";
const std::string TEST_BUNDLE_NAME = "com.ohos.testbundle";
} // namespace

class ParamCommonEventTest : public Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: ParamCommonEvent_Construct_001
 * @tc.desc: test ParamCommonEvent construct and event map init
 * @tc.type: FUNC
 */
HWTEST_F(ParamCommonEventTest, ParamCommonEvent_Construct_001, TestSize.Level1)
{
    DTEST_LOG << TAG << " ParamCommonEvent_Construct_001 start" << std::endl;
    ParamCommonEvent paramCommonEvent;
    EXPECT_FALSE(paramCommonEvent.handleEventFunc_.empty());
    EXPECT_EQ(paramCommonEvent.handleEventFunc_.size(), paramCommonEvent.eventHandles_.size());
    DTEST_LOG << TAG << " ParamCommonEvent_Construct_001 end" << std::endl;
}

/**
 * @tc.name: ParamCommonEvent_OnReceiveEvent_001
 * @tc.desc: test OnReceiveEvent ignore unknown action
 * @tc.type: FUNC
 */
HWTEST_F(ParamCommonEventTest, ParamCommonEvent_OnReceiveEvent_001, TestSize.Level1)
{
    DTEST_LOG << TAG << " ParamCommonEvent_OnReceiveEvent_001 start" << std::endl;
    ParamCommonEvent paramCommonEvent;
    AAFwk::Want want;
    want.SetAction("unknown.action.NOT_EXIST");
    EXPECT_NO_FATAL_FAILURE(paramCommonEvent.OnReceiveEvent(want));
    EXPECT_TRUE(paramCommonEvent.eventHandles_.count("unknown.action.NOT_EXIST") == 0);
    DTEST_LOG << TAG << " ParamCommonEvent_OnReceiveEvent_001 end" << std::endl;
}

/**
 * @tc.name: ParamCommonEvent_UpdateBlacklistInner_001
 * @tc.desc: test UpdateBlacklistInner with invalid root
 * @tc.type: FUNC
 */
HWTEST_F(ParamCommonEventTest, ParamCommonEvent_UpdateBlacklistInner_001, TestSize.Level1)
{
    DTEST_LOG << TAG << " ParamCommonEvent_UpdateBlacklistInner_001 start" << std::endl;
    ParamCommonEvent paramCommonEvent;
    EXPECT_FALSE(paramCommonEvent.UpdateBlacklistInner(nullptr));

    cJSON *rootArray = cJSON_CreateArray();
    ASSERT_NE(rootArray, nullptr);
    EXPECT_FALSE(paramCommonEvent.UpdateBlacklistInner(rootArray));
    cJSON_Delete(rootArray);
    DTEST_LOG << TAG << " ParamCommonEvent_UpdateBlacklistInner_001 end" << std::endl;
}

/**
 * @tc.name: ParamCommonEvent_UpdateBlacklistInner_002
 * @tc.desc: test UpdateBlacklistInner with valid version range rules
 * @tc.type: FUNC
 */
HWTEST_F(ParamCommonEventTest, ParamCommonEvent_UpdateBlacklistInner_002, TestSize.Level1)
{
    DTEST_LOG << TAG << " ParamCommonEvent_UpdateBlacklistInner_002 start" << std::endl;
    ParamCommonEvent paramCommonEvent;

    cJSON *root = cJSON_CreateObject();
    ASSERT_NE(root, nullptr);

    cJSON *bundleItem = cJSON_CreateObject();
    ASSERT_NE(bundleItem, nullptr);
    cJSON_AddItemToObject(root, TEST_BUNDLE_NAME.c_str(), bundleItem);

    cJSON *versionArray = cJSON_CreateArray();
    ASSERT_NE(versionArray, nullptr);
    cJSON_AddItemToObject(bundleItem, "versionCode", versionArray);

    // valid range "1-3"
    cJSON_AddItemToArray(versionArray, cJSON_CreateString("1-3"));
    // single version "5"
    cJSON_AddItemToArray(versionArray, cJSON_CreateString("5"));
    // invalid rule "abc" will be ignored
    cJSON_AddItemToArray(versionArray, cJSON_CreateString("abc"));

    EXPECT_TRUE(paramCommonEvent.UpdateBlacklistInner(root));
    EXPECT_EQ(paramCommonEvent.blackListMap_.size(), 1u);
    auto iter = paramCommonEvent.blackListMap_.find(TEST_BUNDLE_NAME);
    ASSERT_NE(iter, paramCommonEvent.blackListMap_.end());
    EXPECT_EQ(iter->second.size(), 2u);
    EXPECT_EQ(iter->second[0].first, 1u);
    EXPECT_EQ(iter->second[0].second, 3u);
    EXPECT_EQ(iter->second[1].first, 5u);
    EXPECT_EQ(iter->second[1].second, 5u);

    cJSON_Delete(root);
    DTEST_LOG << TAG << " ParamCommonEvent_UpdateBlacklistInner_002 end" << std::endl;
}

/**
 * @tc.name: ParamCommonEvent_CheckBlacklist_001
 * @tc.desc: test CheckBlacklist with different version ranges
 * @tc.type: FUNC
 */
HWTEST_F(ParamCommonEventTest, ParamCommonEvent_CheckBlacklist_001, TestSize.Level1)
{
    DTEST_LOG << TAG << " ParamCommonEvent_CheckBlacklist_001 start" << std::endl;
    ParamCommonEvent paramCommonEvent;

    paramCommonEvent.blackListMap_.clear();
    paramCommonEvent.blackListMap_[TEST_BUNDLE_NAME] = {
        {1u, 3u},
        {10u, 10u},
    };

    EXPECT_FALSE(paramCommonEvent.CheckBlacklist(TEST_BUNDLE_NAME, 0u));
    EXPECT_TRUE(paramCommonEvent.CheckBlacklist(TEST_BUNDLE_NAME, 2u));
    EXPECT_TRUE(paramCommonEvent.CheckBlacklist(TEST_BUNDLE_NAME, 10u));
    EXPECT_FALSE(paramCommonEvent.CheckBlacklist(TEST_BUNDLE_NAME, 11u));

    EXPECT_FALSE(paramCommonEvent.CheckBlacklist("other.bundle", 2u));
    DTEST_LOG << TAG << " ParamCommonEvent_CheckBlacklist_001 end" << std::endl;
}

} // namespace DistributedSchedule
} // namespace OHOS


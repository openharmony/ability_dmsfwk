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

#include <algorithm>
#include <common_event_support.h>

#define private public
#include "mission/param/param_common_event.h"
#undef private

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

/**
 * @tc.name: ParamCommonEvent_OnReceiveEvent_002
 * @tc.desc: test OnReceiveEvent handle registered action
 * @tc.type: FUNC
 */
HWTEST_F(ParamCommonEventTest, ParamCommonEvent_OnReceiveEvent_002, TestSize.Level1)
{
    DTEST_LOG << TAG << " ParamCommonEvent_OnReceiveEvent_002 start" << std::endl;
    ParamCommonEvent paramCommonEvent;
    bool called = false;
    paramCommonEvent.eventHandles_["test.action.HANDLE"] = [&called](const AAFwk::Want &want) {
        (void)want;
        called = true;
    };

    AAFwk::Want want;
    want.SetAction("test.action.HANDLE");
    paramCommonEvent.OnReceiveEvent(want);
    EXPECT_TRUE(called);
    DTEST_LOG << TAG << " ParamCommonEvent_OnReceiveEvent_002 end" << std::endl;
}

/**
 * @tc.name: ParamCommonEvent_OnReceiveEvent_003
 * @tc.desc: test OnReceiveEvent with built-in action path
 * @tc.type: FUNC
 */
HWTEST_F(ParamCommonEventTest, ParamCommonEvent_OnReceiveEvent_003, TestSize.Level1)
{
    DTEST_LOG << TAG << " ParamCommonEvent_OnReceiveEvent_003 start" << std::endl;
    ParamCommonEvent paramCommonEvent;
    AAFwk::Want want;
    want.SetAction("usual.event.DUE_SA_CFG_UPDATED");
    EXPECT_NO_FATAL_FAILURE(paramCommonEvent.OnReceiveEvent(want));
    DTEST_LOG << TAG << " ParamCommonEvent_OnReceiveEvent_003 end" << std::endl;
}

/**
 * @tc.name: ParamCommonEvent_UpdateBlacklist_001
 * @tc.desc: test UpdateBlacklist with file not exist path
 * @tc.type: FUNC
 */
HWTEST_F(ParamCommonEventTest, ParamCommonEvent_UpdateBlacklist_001, TestSize.Level1)
{
    DTEST_LOG << TAG << " ParamCommonEvent_UpdateBlacklist_001 start" << std::endl;
    ParamCommonEvent paramCommonEvent;
    EXPECT_FALSE(paramCommonEvent.UpdateBlacklist());
    DTEST_LOG << TAG << " ParamCommonEvent_UpdateBlacklist_001 end" << std::endl;
}

/**
 * @tc.name: ParamCommonEvent_UpdateBlacklistInner_003
 * @tc.desc: test UpdateBlacklistInner continue branches for invalid bundle content
 * @tc.type: FUNC
 */
HWTEST_F(ParamCommonEventTest, ParamCommonEvent_UpdateBlacklistInner_003, TestSize.Level1)
{
    DTEST_LOG << TAG << " ParamCommonEvent_UpdateBlacklistInner_003 start" << std::endl;
    ParamCommonEvent paramCommonEvent;
    cJSON *root = cJSON_CreateObject();
    ASSERT_NE(root, nullptr);

    cJSON_AddItemToObject(root, "bundle_not_object", cJSON_CreateNumber(123));

    cJSON *bundleNoVersion = cJSON_CreateObject();
    ASSERT_NE(bundleNoVersion, nullptr);
    cJSON_AddItemToObject(root, "bundle_no_version", bundleNoVersion);

    cJSON *bundleVersionNotArray = cJSON_CreateObject();
    ASSERT_NE(bundleVersionNotArray, nullptr);
    cJSON_AddItemToObject(root, "bundle_version_not_array", bundleVersionNotArray);
    cJSON_AddStringToObject(bundleVersionNotArray, "versionCode", "1-3");

    EXPECT_TRUE(paramCommonEvent.UpdateBlacklistInner(root));
    EXPECT_TRUE(paramCommonEvent.blackListMap_.empty());

    cJSON_Delete(root);
    DTEST_LOG << TAG << " ParamCommonEvent_UpdateBlacklistInner_003 end" << std::endl;
}

/**
 * @tc.name: ParamCommonEvent_UpdateBlacklistInner_004
 * @tc.desc: test UpdateBlacklistInner parse branches of version rules
 * @tc.type: FUNC
 */
HWTEST_F(ParamCommonEventTest, ParamCommonEvent_UpdateBlacklistInner_004, TestSize.Level1)
{
    DTEST_LOG << TAG << " ParamCommonEvent_UpdateBlacklistInner_004 start" << std::endl;
    ParamCommonEvent paramCommonEvent;

    cJSON *root = cJSON_CreateObject();
    ASSERT_NE(root, nullptr);
    cJSON *bundleItem = cJSON_CreateObject();
    ASSERT_NE(bundleItem, nullptr);
    cJSON_AddItemToObject(root, TEST_BUNDLE_NAME.c_str(), bundleItem);

    cJSON *versionArray = cJSON_CreateArray();
    ASSERT_NE(versionArray, nullptr);
    cJSON_AddItemToObject(bundleItem, "versionCode", versionArray);

    cJSON_AddItemToArray(versionArray, cJSON_CreateString(" 7 "));
    cJSON_AddItemToArray(versionArray, cJSON_CreateString("10-8"));
    cJSON_AddItemToArray(versionArray, cJSON_CreateString("2-4"));
    cJSON_AddItemToArray(versionArray, cJSON_CreateString("1-"));
    cJSON_AddItemToArray(versionArray, cJSON_CreateString("-3"));
    cJSON_AddItemToArray(versionArray, cJSON_CreateString("42949672960"));
    cJSON_AddItemToArray(versionArray, cJSON_CreateString("   "));
    cJSON_AddItemToArray(versionArray, cJSON_CreateNumber(100));

    EXPECT_TRUE(paramCommonEvent.UpdateBlacklistInner(root));
    auto iter = paramCommonEvent.blackListMap_.find(TEST_BUNDLE_NAME);
    ASSERT_NE(iter, paramCommonEvent.blackListMap_.end());
    EXPECT_EQ(iter->second.size(), 3u);

    auto containRange = [&iter](uint32_t start, uint32_t end) {
        return std::find(iter->second.begin(), iter->second.end(), std::make_pair(start, end)) != iter->second.end();
    };
    EXPECT_TRUE(containRange(7u, 7u));
    EXPECT_TRUE(containRange(8u, 10u));
    EXPECT_TRUE(containRange(2u, 4u));

    cJSON_Delete(root);
    DTEST_LOG << TAG << " ParamCommonEvent_UpdateBlacklistInner_004 end" << std::endl;
}

/**
 * @tc.name: ParamCommonEvent_UpdateBlacklistInner_005
 * @tc.desc: test UpdateBlacklistInner with only invalid version rules
 * @tc.type: FUNC
 */
HWTEST_F(ParamCommonEventTest, ParamCommonEvent_UpdateBlacklistInner_005, TestSize.Level1)
{
    DTEST_LOG << TAG << " ParamCommonEvent_UpdateBlacklistInner_005 start" << std::endl;
    ParamCommonEvent paramCommonEvent;

    cJSON *root = cJSON_CreateObject();
    ASSERT_NE(root, nullptr);
    cJSON *bundleItem = cJSON_CreateObject();
    ASSERT_NE(bundleItem, nullptr);
    cJSON_AddItemToObject(root, TEST_BUNDLE_NAME.c_str(), bundleItem);

    cJSON *versionArray = cJSON_CreateArray();
    ASSERT_NE(versionArray, nullptr);
    cJSON_AddItemToObject(bundleItem, "versionCode", versionArray);
    cJSON_AddItemToArray(versionArray, cJSON_CreateString("abc"));
    cJSON_AddItemToArray(versionArray, cJSON_CreateString("1-"));
    cJSON_AddItemToArray(versionArray, cJSON_CreateString("-2"));

    EXPECT_TRUE(paramCommonEvent.UpdateBlacklistInner(root));
    EXPECT_TRUE(paramCommonEvent.blackListMap_.empty());

    cJSON_Delete(root);
    DTEST_LOG << TAG << " ParamCommonEvent_UpdateBlacklistInner_005 end" << std::endl;
}

/**
 * @tc.name: ParamCommonEvent_SubscriberEvent_001
 * @tc.desc: test SubscriberEvent return directly when subscriber already exists
 * @tc.type: FUNC
 */
HWTEST_F(ParamCommonEventTest, ParamCommonEvent_SubscriberEvent_001, TestSize.Level1)
{
    DTEST_LOG << TAG << " ParamCommonEvent_SubscriberEvent_001 start" << std::endl;
    ParamCommonEvent paramCommonEvent;

    EventFwk::MatchingSkills matchingSkills;
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    paramCommonEvent.subscriber_ =
        std::make_shared<ParamCommonEvent::ParamCommonEventSubscriber>(subscribeInfo, paramCommonEvent);

    EXPECT_NO_FATAL_FAILURE(paramCommonEvent.SubscriberEvent());
    EXPECT_NE(paramCommonEvent.subscriber_, nullptr);
    DTEST_LOG << TAG << " ParamCommonEvent_SubscriberEvent_001 end" << std::endl;
}

/**
 * @tc.name: ParamCommonEvent_UnSubscriberEvent_001
 * @tc.desc: test UnSubscriberEvent clear map and release subscriber
 * @tc.type: FUNC
 */
HWTEST_F(ParamCommonEventTest, ParamCommonEvent_UnSubscriberEvent_001, TestSize.Level1)
{
    DTEST_LOG << TAG << " ParamCommonEvent_UnSubscriberEvent_001 start" << std::endl;
    ParamCommonEvent paramCommonEvent;
    paramCommonEvent.eventHandles_["test.action"] = [](const AAFwk::Want &want) {
        (void)want;
    };
    paramCommonEvent.handleEventFunc_["test.action"] = &ParamCommonEvent::HandleParamUpdate;

    EventFwk::MatchingSkills matchingSkills;
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    paramCommonEvent.subscriber_ =
        std::make_shared<ParamCommonEvent::ParamCommonEventSubscriber>(subscribeInfo, paramCommonEvent);

    EXPECT_NO_FATAL_FAILURE(paramCommonEvent.UnSubscriberEvent());
    EXPECT_TRUE(paramCommonEvent.eventHandles_.empty());
    EXPECT_TRUE(paramCommonEvent.handleEventFunc_.empty());
    EXPECT_EQ(paramCommonEvent.subscriber_, nullptr);
    DTEST_LOG << TAG << " ParamCommonEvent_UnSubscriberEvent_001 end" << std::endl;
}

} // namespace DistributedSchedule
} // namespace OHOS


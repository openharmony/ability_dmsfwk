/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "svc_distributed_connection_test.h"
#include "common_event_manager.h"
#include "device_manager.h"
#include "notification_bundle_option.h"
#include "notification_constant.h"
#include "notification_helper.h"
#include "notification_request.h"
#include "want_agent_helper.h"
#include "want_agent_info.h"
#include "cJSON.h"

#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace {
bool g_subscribeCommonEvent;
std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> g_wantAgent;
std::shared_ptr<OHOS::Notification::NotificationActionButton> g_actionButton;
int32_t g_deviceName;
cJSON *json = nullptr;
cJSON *resJson = nullptr;
cJSON *key = nullptr;
cJSON *value = nullptr;
const int32_t INVAILD_RET = 5;
const int32_t ERR_OK = 0;
} // namespace

cJSON* cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string)
{
    return resJson;
}

cJSON* cJSON_Parse(const char *value)
{
    return json;
}

namespace OHOS::EventFwk {
bool CommonEventManager::SubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber> &subscriber)
{
    return g_subscribeCommonEvent;
}
} // namespace OHOS::EventFwk

namespace OHOS::AbilityRuntime {
std::shared_ptr<WantAgent::WantAgent> WantAgent::WantAgentHelper::GetWantAgent(const WantAgentInfo &paramsInfo,
    int32_t userId, int32_t uid)
{
    return g_wantAgent;
}
} // namespace OHOS::AbilityRuntime

namespace OHOS::Notification {
std::shared_ptr<NotificationActionButton> NotificationActionButton::Create(
    const std::shared_ptr<Media::PixelMap> &icon, const std::string &title,
    const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> &wantAgent,
    const std::shared_ptr<AAFwk::WantParams> &extras, NotificationConstant::SemanticActionButton semanticActionButton,
    bool autoCreatedReplies, const std::vector<std::shared_ptr<NotificationUserInput>> &mimeTypeOnlyInputs,
    const std::shared_ptr<NotificationUserInput> &userInput, bool isContextual)
{
    return g_actionButton;
}
} // namespace OHOS::Notification

namespace OHOS::DistributedHardware {
int32_t DeviceManager::GetDeviceName(const std::string &pkgName, const std::string &networkId,
    std::string &deviceName)
{
    return g_deviceName;
}
}

namespace OHOS {
namespace DistributedSchedule {
void SvcDistributedConnectionTest::SetUpTestCase()
{
    disconnectedCon_ = sptr(new SvcDistributedConnection("com.example.dms_extension"));
    DTEST_LOG << "SvcDistributedConnectionTest::SetUpTestCase" << std::endl;
}

void SvcDistributedConnectionTest::TearDownTestCase()
{
    disconnectedCon_ = nullptr;
    DTEST_LOG << "SvcDistributedConnectionTest::TearDownTestCase" << std::endl;
}

void SvcDistributedConnectionTest::TearDown()
{
    DTEST_LOG << "SvcDistributedConnectionTest::TearDown" << std::endl;
}

void SvcDistributedConnectionTest::SetUp()
{
    DTEST_LOG << "SvcDistributedConnectionTest::SetUp" << std::endl;
}

/**
 * @tc.name: OnAbilityConnectDone_001
 * @tc.desc: OnAbilityConnectDone
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, OnAbilityConnectDone_001, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest OnAbilityConnectDone_001 begin" << std::endl;
    int resultCode = 0;
    AppExecFwk::ElementName element;
    EXPECT_NO_FATAL_FAILURE(disconnectedCon_->OnAbilityConnectDone(element, nullptr, resultCode));
    DTEST_LOG << "SvcDistributedConnectionTest OnAbilityConnectDone_001 remoteObject is nullptr " << std::endl;
}

/**
 * @tc.name: OnAbilityConnectDone_002
 * @tc.desc: OnAbilityConnectDone
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, OnAbilityConnectDone_002, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest OnAbilityConnectDone_001 begin" << std::endl;
    int resultCode = 0;
    AppExecFwk::ElementName element;
    EXPECT_TRUE(disconnectedCon_ != nullptr);
    sptr<IRemoteObject> remoteObject;

    string bundleName = "com.example.dms_extension";
    element.SetBundleName(bundleName);
    disconnectedCon_->OnAbilityConnectDone(element, remoteObject, resultCode);
    EXPECT_NO_FATAL_FAILURE(disconnectedCon_->OnAbilityConnectDone(element, remoteObject, resultCode));
    DTEST_LOG << "SvcDistributedConnectionTest OnAbilityConnectDone_002 end" << std::endl;
}

/**
 * @tc.name: OnAbilityDisconnectDone_001
 * @tc.desc: OnAbilityDisconnectDone
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, OnAbilityDisconnectDone_001, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest OnAbilityDisconnectDone_001 begin" << std::endl;

    AppExecFwk::ElementName element;
    string bundleName = "";
    element.SetBundleName(bundleName);
    int resultCode = 1;

    EXPECT_TRUE(disconnectedCon_ != nullptr);
    disconnectedCon_->isConnectCalled_ = false;
    disconnectedCon_->OnAbilityDisconnectDone(element, resultCode);
    EXPECT_NO_FATAL_FAILURE(disconnectedCon_->OnAbilityDisconnectDone(element, resultCode));
    bool ret = disconnectedCon_->IsExtAbilityConnected();
    EXPECT_FALSE(ret);

    disconnectedCon_->isConnectCalled_ = true;
    bundleName = "com.example.dms_extension";
    element.SetBundleName(bundleName);
    disconnectedCon_->OnAbilityDisconnectDone(element, resultCode);
    EXPECT_NO_FATAL_FAILURE(disconnectedCon_->OnAbilityDisconnectDone(element, resultCode));
    ret = disconnectedCon_->IsExtAbilityConnected();
    EXPECT_FALSE(ret);

    DTEST_LOG << "SvcDistributedConnectionTest OnAbilityDisconnectDone_001 end" << std::endl;
}

/**
 * @tc.name: GetDistributedExtProxy_001
 * @tc.desc: GetDistributedExtProxy
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, GetDistributedExtProxy_001, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest GetDistributedExtProxy_001 begin" << std::endl;
    EXPECT_TRUE(disconnectedCon_ != nullptr);
    auto proxy = disconnectedCon_->GetDistributedExtProxy();
    EXPECT_EQ(proxy, nullptr);
    DTEST_LOG << "SvcDistributedConnectionTest GetDistributedExtProxy_001 end" << std::endl;
}

/**
 * @tc.name: UpdateResourceMap_001
 * @tc.desc: Input Parameter is empty
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, UpdateResourceMap_001, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest UpdateResourceMap_001 begin" << std::endl;
    std::string resourcePath = "";
    UpdateResourceMap(resourcePath);
    {
        std::lock_guard<std::mutex> lock(g_resourceMutex);
        EXPECT_EQ(g_resourceMap.size(), 0);
    }
    DTEST_LOG << "SvcDistributedConnectionTest UpdateResourceMap_001 end" << std::endl;
}

/**
 * @tc.name: UpdateResourceMap_002
 * @tc.desc: resJson is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, UpdateResourceMap_002, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest UpdateResourceMap_002 begin" << std::endl;
    std::string resourcePath = "system/etc/dmsfwk/resources/cn_ZH/element/string.json";

    cJSON *jsonObject = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObject, "key1", "value1");
    cJSON_AddNumberToObject(jsonObject, "key2", 123);
    EXPECT_TRUE(disconnectedCon_ != nullptr);

    json = jsonObject;
    UpdateResourceMap(resourcePath);
    {
        std::lock_guard<std::mutex> lock(g_resourceMutex);
        EXPECT_EQ(g_resourceMap.size(), 0);
    }
    json = nullptr;

    DTEST_LOG << "SvcDistributedConnectionTest UpdateResourceMap_002 end" << std::endl;
}

/**
 * @tc.name: UpdateResourceMap_003
 * @tc.desc: resJson size > MAX_RES_VEC_LEN
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, UpdateResourceMap_003, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest UpdateResourceMap_003 begin" << std::endl;
    std::string resourcePath = "system/etc/dmsfwk/resources/cn_ZH/element/string.json";

    EXPECT_TRUE(disconnectedCon_ != nullptr);
    cJSON *jsonObject = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObject, "key1", "value1");
    cJSON_AddNumberToObject(jsonObject, "key2", 123);
    EXPECT_TRUE(disconnectedCon_ != nullptr);
    cJSON *stringArray = cJSON_CreateArray();
    for (int i = 1; i <= 101; ++i) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "name", ("key" + std::to_string(i)).c_str());
        cJSON_AddStringToObject(item, "value", ("value" + std::to_string(i)).c_str());
        cJSON_AddItemToArray(stringArray, item);
    }

    json = jsonObject;
    resJson = stringArray;
    UpdateResourceMap(resourcePath);
    {
        std::lock_guard<std::mutex> lock(g_resourceMutex);
        EXPECT_EQ(g_resourceMap.size(), 0);
    }
    json = nullptr;
    resJson = nullptr;

    DTEST_LOG << "SvcDistributedConnectionTest UpdateResourceMap_003 end" << std::endl;
}

/**
 * @tc.name: UpdateResourceMap_004
 * @tc.desc: UpdateResourceMap
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, UpdateResourceMap_004, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest UpdateResourceMap_004 begin" << std::endl;
    std::string resourcePath = "system/etc/dmsfwk/resources/cn_ZH/element/string.json";
    cJSON *jsonObject = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObject, "key1", "value1");
    cJSON_AddNumberToObject(jsonObject, "key2", 123);
    cJSON *value = cJSON_CreateObject();
    value->type = cJSON_String;
    value->valuestring = strdup("zh_CN");

    json = jsonObject;
    resJson = value;
    UpdateResourceMap(resourcePath);
    {
        std::lock_guard<std::mutex> lock(g_resourceMutex);
        EXPECT_EQ(g_resourceMap.size(), 0);
    }
    json = nullptr;
    resJson = nullptr;

    DTEST_LOG << "SvcDistributedConnectionTest UpdateResourceMap_004 end" << std::endl;
}

/**
 * @tc.name: GetLanguageFilePath_001
 * @tc.desc: json is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, GetLanguageFilePath_001, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest GetLanguageFilePath_001 begin" << std::endl;
    std::string sysLanguage = "zh-Hant";
    std::string sysRegion = "TW";
    std::string result = GetLanguageFilePath(sysLanguage, sysRegion);
    EXPECT_EQ(result, "zh_CN");

    DTEST_LOG << "SvcDistributedConnectionTest GetLanguageFilePath_001 end" << std::endl;
}

/**
 * @tc.name: GetLanguageFilePath_002
 * @tc.desc: resJson is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, GetLanguageFilePath_002, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest GetLanguageFilePath_002 begin" << std::endl;
    std::string sysLanguage = "zh-Hant";
    std::string sysRegion = "TW";
    cJSON *jsonObject = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObject, "key1", "value1");
    cJSON_AddNumberToObject(jsonObject, "key2", 123);

    json = jsonObject;
    std::string result = GetLanguageFilePath(sysLanguage, sysRegion);
    EXPECT_EQ(result, "zh_CN");
    json = nullptr;

    DTEST_LOG << "SvcDistributedConnectionTest GetLanguageFilePath_002 end" << std::endl;
}

/**
 * @tc.name: GetLanguageFilePath_003
 * @tc.desc: resJson is not array
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, GetLanguageFilePath_003, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest GetLanguageFilePath_003 begin" << std::endl;
    std::string sysLanguage = "zh-Hant";
    std::string sysRegion = "TW";
    cJSON *jsonObject = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObject, "key1", "value1");
    cJSON_AddNumberToObject(jsonObject, "key2", 123);
    cJSON *value = cJSON_CreateObject();
    value->type = cJSON_String;
    value->valuestring = strdup("zh_CN");

    json = jsonObject;
    resJson = value;
    std::string result = GetLanguageFilePath(sysLanguage, sysRegion);
    EXPECT_EQ(result, "zh_CN");
    json = nullptr;
    resJson = nullptr;

    DTEST_LOG << "SvcDistributedConnectionTest GetLanguageFilePath_003 end" << std::endl;
}

/**
 * @tc.name: GetLanguageFilePath_004
 * @tc.desc: langguage is zh_TW
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, GetLanguageFilePath_004, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest GetLanguageFilePath_004 begin" << std::endl;
    std::string sysLanguage = "zh-Hant";
    std::string sysRegion = "TW";
    cJSON *jsonObject = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObject, "key1", "value1");
    cJSON_AddNumberToObject(jsonObject, "key2", 123);
    cJSON *value = cJSON_CreateArray();
    cJSON *arrayItem1 = cJSON_CreateString("zh_CN");
    cJSON *arrayItem2 = cJSON_CreateString("en_US");
    cJSON_AddItemToArray(value, arrayItem1);
    cJSON_AddItemToArray(value, arrayItem2);

    json = jsonObject;
    resJson = value;
    std::string result = GetLanguageFilePath(sysLanguage, sysRegion);
    EXPECT_EQ(result, "zh_TW");
    json = nullptr;
    resJson = nullptr;

    DTEST_LOG << "SvcDistributedConnectionTest GetLanguageFilePath_004 end" << std::endl;
}

/**
 * @tc.name: GetLanguageFilePath_005
 * @tc.desc: GetLanguageFilePath
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, GetLanguageFilePath_005, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest GetLanguageFilePath_005 begin" << std::endl;
    std::string sysLanguage = "zh-Hans";
    std::string sysRegion = "CN";
    cJSON *jsonObject = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObject, "key1", "value1");
    cJSON_AddNumberToObject(jsonObject, "key2", 123);
    cJSON *value = cJSON_CreateArray();
    cJSON *arrayItem1 = cJSON_CreateString("zh_CN");
    cJSON *arrayItem2 = cJSON_CreateString("en_US");
    cJSON_AddItemToArray(value, arrayItem1);
    cJSON_AddItemToArray(value, arrayItem2);

    json = jsonObject;
    resJson = value;
    std::string result = GetLanguageFilePath(sysLanguage, sysRegion);
    EXPECT_EQ(result, "zh_CN");
    json = nullptr;
    resJson = nullptr;

    DTEST_LOG << "SvcDistributedConnectionTest GetLanguageFilePath_005 end" << std::endl;
}

/**
 * @tc.name: UpdateResourceMapByLanguage_001
 * @tc.desc: UpdateResourceMapByLanguage
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, UpdateResourceMapByLanguage_001, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest UpdateResourceMapByLanguage_001 begin" << std::endl;
    g_sysLanguage = "";
    g_sysRegion = "";
    UpdateResourceMapByLanguage();
    EXPECT_EQ(g_sysLanguage, "zh-Hans");

    DTEST_LOG << "SvcDistributedConnectionTest UpdateResourceMapByLanguage_001 end" << std::endl;
}

/**
 * @tc.name: UpdateResourceMapByLanguage_002
 * @tc.desc: UpdateResourceMapByLanguage
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, UpdateResourceMapByLanguage_002, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest UpdateResourceMapByLanguage_002 begin" << std::endl;
    g_sysLanguage = "zh-Hans";
    g_sysRegion = "CN";
    EXPECT_NO_FATAL_FAILURE(UpdateResourceMapByLanguage());

    DTEST_LOG << "SvcDistributedConnectionTest UpdateResourceMapByLanguage_002 end" << std::endl;
}

/**
 * @tc.name: EndTaskFunction_001
 * @tc.desc: EndTaskFunction
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, EndTaskFunction_001, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest EndTaskFunction_001 begin" << std::endl;
    EXPECT_TRUE(disconnectedCon_ != nullptr);
    disconnectedCon_->isConnected_.store(false);
    disconnectedCon_->EndTaskFunction();
    EXPECT_EQ(disconnectedCon_->isConnected_.load(), false);

    DTEST_LOG << "SvcDistributedConnectionTest EndTaskFunction_001 end" << std::endl;
}

/**
 * @tc.name: EndTaskFunction_002
 * @tc.desc: EndTaskFunction
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, EndTaskFunction_002, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest EndTaskFunction_002 begin" << std::endl;
    EXPECT_TRUE(disconnectedCon_ != nullptr);
    disconnectedCon_->isConnected_.store(true);
    disconnectedCon_->EndTaskFunction();
    EXPECT_EQ(disconnectedCon_->isConnectCalled_.load(), false);

    DTEST_LOG << "SvcDistributedConnectionTest EndTaskFunction_002 end" << std::endl;
}

/**
 * @tc.name: RegisterEventListener_001
 * @tc.desc: RegisterEventListener
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, RegisterEventListener_001, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest RegisterEventListener_001 begin" << std::endl;
    EXPECT_TRUE(disconnectedCon_ != nullptr);
    g_subscribeCommonEvent = true;
    disconnectedCon_->RegisterEventListener();
    EXPECT_NO_FATAL_FAILURE(disconnectedCon_->RegisterEventListener());

    DTEST_LOG << "SvcDistributedConnectionTest RegisterEventListener_001 end" << std::endl;
}

/**
 * @tc.name: RegisterEventListener_002
 * @tc.desc: RegisterEventListener
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, RegisterEventListener_002, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest RegisterEventListener_002 begin" << std::endl;
    EXPECT_TRUE(disconnectedCon_ != nullptr);
    g_subscribeCommonEvent = false;
    disconnectedCon_->RegisterEventListener();
    EXPECT_NO_FATAL_FAILURE(disconnectedCon_->RegisterEventListener());

    DTEST_LOG << "SvcDistributedConnectionTest RegisterEventListener_002 end" << std::endl;
}

/**
 * @tc.name: SetEndTaskButton_001
 * @tc.desc: wantAgent is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, SetEndTaskButton_001, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest SetEndTaskButton_001 begin" << std::endl;
    EXPECT_TRUE(disconnectedCon_ != nullptr);
    Notification::NotificationRequest request;
    g_wantAgent = nullptr;
    SetEndTaskButton(request);
    EXPECT_NO_FATAL_FAILURE(SetEndTaskButton(request));

    DTEST_LOG << "SvcDistributedConnectionTest SetEndTaskButton_001 end" << std::endl;
}

/**
 * @tc.name: SetEndTaskButton_002
 * @tc.desc: actionButton is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, SetEndTaskButton_002, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest SetEndTaskButton_002 begin" << std::endl;
    EXPECT_TRUE(disconnectedCon_ != nullptr);
    Notification::NotificationRequest request;
    auto pendingWant = std::make_shared<AbilityRuntime::WantAgent::PendingWant>();
    g_wantAgent = std::make_shared<AbilityRuntime::WantAgent::WantAgent>(pendingWant);
    g_actionButton = nullptr;

    SetEndTaskButton(request);
    EXPECT_NO_FATAL_FAILURE(SetEndTaskButton(request));

    DTEST_LOG << "SvcDistributedConnectionTest SetEndTaskButton_002 end" << std::endl;
}

/**
 * @tc.name: SetEndTaskButton_003
 * @tc.desc: SetEndTaskButton
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, SetEndTaskButton_003, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest SetEndTaskButton_003 begin" << std::endl;
    EXPECT_TRUE(disconnectedCon_ != nullptr);
    Notification::NotificationRequest request;
    auto pendingWant = std::make_shared<AbilityRuntime::WantAgent::PendingWant>();
    g_wantAgent = std::make_shared<AbilityRuntime::WantAgent::WantAgent>(pendingWant);
    g_actionButton = std::make_shared<Notification::NotificationActionButton>();

    SetEndTaskButton(request);
    EXPECT_NO_FATAL_FAILURE(SetEndTaskButton(request));

    DTEST_LOG << "SvcDistributedConnectionTest SetEndTaskButton_003 end" << std::endl;
}

/**
 * @tc.name: PublishDExtensionNotification_001
 * @tc.desc: Get device name failed
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, PublishDExtensionNotification_001, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest PublishDExtensionNotification_001 begin" << std::endl;
    EXPECT_TRUE(disconnectedCon_ != nullptr);
    std::string deviceId = "deviceId";
    std::string bundleName = "com.example.dms_extension";
    int32_t userId = 0;
    std::string networkId = "networkId";
    AppExecFwk::BundleResourceInfo bundleResourceInfo;
    g_deviceName = INVAILD_RET;

    disconnectedCon_->PublishDExtensionNotification(deviceId, bundleName, userId, networkId, bundleResourceInfo);
    EXPECT_NO_FATAL_FAILURE(
        disconnectedCon_->PublishDExtensionNotification(deviceId, bundleName, userId, networkId, bundleResourceInfo));

    DTEST_LOG << "SvcDistributedConnectionTest PublishDExtensionNotification_001 end" << std::endl;
}

/**
 * @tc.name: PublishDExtensionNotification_002
 * @tc.desc: PublishDExtensionNotification
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, PublishDExtensionNotification_002, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest PublishDExtensionNotification_002 begin" << std::endl;
    EXPECT_TRUE(disconnectedCon_ != nullptr);
    std::string deviceId = "deviceId";
    std::string bundleName = "com.example.dms_extension";
    int32_t userId = 0;
    std::string networkId = "networkId";
    AppExecFwk::BundleResourceInfo bundleResourceInfo;
    g_deviceName = ERR_OK;

    disconnectedCon_->PublishDExtensionNotification(deviceId, bundleName, userId, networkId, bundleResourceInfo);
    EXPECT_NO_FATAL_FAILURE(
        disconnectedCon_->PublishDExtensionNotification(deviceId, bundleName, userId, networkId, bundleResourceInfo));

    DTEST_LOG << "SvcDistributedConnectionTest PublishDExtensionNotification_002 end" << std::endl;
}
}
}

/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "ability_connect_callback_interface.h"
#include "ability_connect_callback_stub.h"
#include "device_manager.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "ability_connection_wrapper_stub.h"
#include "distributed_sched_test_util.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "parcel_helper.h"
#include "test_log.h"

#define private public
#define protected public
#include "distributed_sched_service.h"
#undef private
#undef protected

namespace OHOS {
namespace DistributedSchedule {
using namespace AAFwk;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedHardware;

namespace {
const std::string TAG = "DistributedSchedConnectTest";
const std::u16string CONNECTION_CALLBACK_INTERFACE_TOKEN = u"ohos.abilityshell.DistributedConnection";
constexpr int32_t STDOUT_FD = 1;
constexpr int32_t REQUEST_CODE_ERR = 305;
constexpr int32_t ERROR_CONNECT_CODE = 1000;
}

class AbilityConnectCallbackTest : public AAFwk::AbilityConnectionStub {
public:
    AbilityConnectCallbackTest() = default;
    ~AbilityConnectCallbackTest() = default;

    void OnAbilityConnectDone(const AppExecFwk::ElementName& element,
        const sptr<IRemoteObject>& remoteObject, int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName& element,
        int32_t resultCode) override;
};

class AbilityConnectionWrapperStubTest : public AAFwk::AbilityConnectionStub {
public:
    explicit AbilityConnectionWrapperStubTest(sptr<IRemoteObject> connection) : distributedConnection_(connection) {}
    ~AbilityConnectionWrapperStubTest() = default;

    void OnAbilityConnectDone(const AppExecFwk::ElementName& element,
        const sptr<IRemoteObject>& remoteObject, int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName& element,
        int32_t resultCode) override;

private:
    sptr<IRemoteObject> distributedConnection_;
};

class DistributedSchedConnectTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    void AddSession(const sptr<IRemoteObject>& connect, const std::string& localDeviceId,
        const std::string& remoteDeviceId, const AAFwk::Want& want) const;
    void RemoveSession(const sptr<IRemoteObject>& connect) const;

    void AddConnectInfo(const sptr<IRemoteObject>& connect, const std::string& localDeviceId,
        const std::string& remoteDeviceId) const;
    void RemoveConnectInfo(const sptr<IRemoteObject>& connect) const;

    void AddConnectCount(int32_t uid) const;
    void DecreaseConnectCount(int32_t uid) const;
    sptr<IDistributedSched> GetDms();

    class DeviceInitCallBack : public DmInitCallback {
        void OnRemoteDied() override;
    };
};

void AbilityConnectCallbackTest::OnAbilityConnectDone(const AppExecFwk::ElementName& element,
    const sptr<IRemoteObject>& remoteObject, int32_t resultCode)
{
}

void AbilityConnectCallbackTest::OnAbilityDisconnectDone(const AppExecFwk::ElementName& element,
    int32_t resultCode)
{
}

void AbilityConnectionWrapperStubTest::OnAbilityConnectDone(const AppExecFwk::ElementName& element,
    const sptr<IRemoteObject>& remoteObject, int32_t resultCode)
{
}

void AbilityConnectionWrapperStubTest::OnAbilityDisconnectDone(const AppExecFwk::ElementName& element,
    int32_t resultCode)
{
}

void DistributedSchedConnectTest::SetUpTestCase()
{
    if (!DistributedSchedUtil::LoadDistributedSchedService()) {
        DTEST_LOG << "DistributedSchedConnectTest::SetUpTestCase LoadDistributedSchedService failed" << std::endl;
    }
    const std::string pkgName = "DBinderBus_" + std::to_string(getprocpid());
    std::shared_ptr<DmInitCallback> initCallback_ = std::make_shared<DeviceInitCallBack>();
    DeviceManager::GetInstance().InitDeviceManager(pkgName, initCallback_);
}

void DistributedSchedConnectTest::TearDownTestCase()
{
}

void DistributedSchedConnectTest::SetUp()
{
    DistributedSchedUtil::MockPermission();
}

void DistributedSchedConnectTest::TearDown()
{
}

void DistributedSchedConnectTest::DeviceInitCallBack::OnRemoteDied()
{
}

void DistributedSchedConnectTest::AddSession(const sptr<IRemoteObject>& connect,
    const std::string& localDeviceId, const std::string& remoteDeviceId, const AAFwk::Want& want) const
{
    if (connect == nullptr) {
        return;
    }

    std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().distributedLock_);
    CallerInfo callerInfo;
    callerInfo.uid = IPCSkeleton::GetCallingUid();
    callerInfo.pid = IPCSkeleton::GetCallingRealPid();
    callerInfo.sourceDeviceId = localDeviceId;
    callerInfo.callerType = CALLER_TYPE_HARMONY;
    DistributedSchedService::GetInstance().RemoteConnectAbilityMappingLocked(connect, localDeviceId,
        remoteDeviceId, want.GetElement(), callerInfo, TargetComponent::HARMONY_COMPONENT);
}

void DistributedSchedConnectTest::RemoveSession(const sptr<IRemoteObject>& connect) const
{
    if (connect == nullptr) {
        return;
    }

    std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().distributedLock_);
    DistributedSchedService::GetInstance().distributedConnectAbilityMap_.erase(connect);
}

void DistributedSchedConnectTest::AddConnectInfo(const sptr<IRemoteObject>& connect,
    const std::string& localDeviceId, const std::string& remoteDeviceId) const
{
    if (connect == nullptr) {
        return;
    }

    std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().distributedLock_);
    CallerInfo callerInfo;
    callerInfo.uid = IPCSkeleton::GetCallingUid();
    callerInfo.pid = IPCSkeleton::GetCallingRealPid();
    callerInfo.sourceDeviceId = localDeviceId;
    callerInfo.callerType = CALLER_TYPE_HARMONY;

    sptr<IRemoteObject> callbackWrapper = new AbilityConnectionWrapperStubTest(connect);
    ConnectInfo connectInfo {callerInfo, callbackWrapper};
    DistributedSchedService::GetInstance().connectAbilityMap_.emplace(connect, connectInfo);
}

void DistributedSchedConnectTest::RemoveConnectInfo(const sptr<IRemoteObject>& connect) const
{
    if (connect == nullptr) {
        return;
    }

    std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().distributedLock_);
    DistributedSchedService::GetInstance().connectAbilityMap_.erase(connect);
}

void DistributedSchedConnectTest::AddConnectCount(int32_t uid) const
{
    if (uid < 0) {
        return;
    }

    auto& trackingUidMap = DistributedSchedService::GetInstance().trackingUidMap_;
    ++trackingUidMap[uid];
}

void DistributedSchedConnectTest::DecreaseConnectCount(int32_t uid) const
{
    if (uid < 0) {
        return;
    }

    DistributedSchedService::GetInstance().DecreaseConnectLocked(uid);
}

sptr<IDistributedSched> DistributedSchedConnectTest::GetDms()
{
    auto sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sm == nullptr) {
        DTEST_LOG << "DistributedSchedConnectTest sm is nullptr" << std::endl;
        return nullptr;
    }
    auto distributedObject = sm->GetSystemAbility(DISTRIBUTED_SCHED_SA_ID);
    if (distributedObject == nullptr) {
        DTEST_LOG << "distributedObject sm is nullptr" << std::endl;
        return nullptr;
    }
    return iface_cast<IDistributedSched>(distributedObject);
}

/**
 * @tc.name: DumpConnectInfo_001
 * @tc.desc: dump connect ability info by call Dump
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, DumpConnectInfo_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest DumpConnectInfo_001 start " << std::endl;
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        DTEST_LOG << "DistributedSchedServiceTest DumpConnectInfo_001 samgr null" << std::endl;
    } else {
        DTEST_LOG << "DistributedSchedServiceTest DumpConnectInfo_001 available" << std::endl;
    }

    auto dms = samgr->GetSystemAbility(DISTRIBUTED_SCHED_SA_ID);
    if (dms == nullptr) {
        DTEST_LOG << "dms is nullptr" << std::endl;
        return;
    }
    std::vector<std::u16string> args;
    args.push_back(u"-connect");
    int32_t result = dms->Dump(STDOUT_FD, args);
    DTEST_LOG << "DistributedSchedServiceTest DumpConnectInfo_001 dump result: " << result << std::endl;
}

/**
 * @tc.name: DumpConnectInfo_002
 * @tc.desc: dump connect ability info by call DumpConnectInfo
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, DumpConnectInfo_002, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedServiceTest DumpConnectInfo_002 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");

    /**
     * @tc.steps: step1. add one session
     */
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    AddSession(connect, "123_local_device_id", "123_remote_device_id", want);
    /**
     * @tc.steps: step2. and then dump connection info
     * @tc.expected: step2. can find the newly-added connect session
     */
    std::string dumpInfo;
    DistributedSchedService::GetInstance().DumpConnectInfo(dumpInfo);
    DTEST_LOG << "DistributedSchedServiceTest DumpConnectInfo_002 dumpInfo " << dumpInfo << std::endl;
    std::string::size_type pos = dumpInfo.find("123_remote_device_id");
    EXPECT_NE(pos, std::string::npos);

    RemoveSession(connect);
}

/**
 * @tc.name: ProcessConnectDied001
 * @tc.desc: process connect died
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, ProcessConnectDied001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest ProcessConnectDied001 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");
    auto& connectionMap = DistributedSchedService::GetInstance().distributedConnectAbilityMap_;
    auto& distributedLock = DistributedSchedService::GetInstance().distributedLock_;

    /**
     * @tc.steps: step1. add one session and check the map
     * @tc.expected: step1. can find the newly-added connect session
     */
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    AddSession(connect, "123_local_device_id", "123_remote_device_id", want);
    {
        std::lock_guard<std::mutex> autoLock(distributedLock);
        EXPECT_EQ(connectionMap.size(), static_cast<size_t>(1));
    }

    /**
     * @tc.steps: step2. process connect died and then check the map
     * @tc.expected: step2. the connect session is removed
     */
    DistributedSchedService::GetInstance().ProcessConnectDied(connect);
    {
        std::lock_guard<std::mutex> autoLock(distributedLock);
        EXPECT_EQ(connectionMap.size(), static_cast<size_t>(0));
    }

    RemoveSession(connect);
}

/**
 * @tc.name: ProcessConnectDied002
 * @tc.desc: process connect died which is not exist
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, ProcessConnectDied002, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedServiceTest ProcessConnectDied002 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");
    auto& connectionMap = DistributedSchedService::GetInstance().distributedConnectAbilityMap_;
    auto& distributedLock = DistributedSchedService::GetInstance().distributedLock_;

    /**
     * @tc.steps: step1. add one session
     * @tc.expected: step1. can find the newly-added connect session
     */
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    AddSession(connect, "123_local_device_id", "123_remote_device_id", want);
    {
        std::lock_guard<std::mutex> autoLock(distributedLock);
        EXPECT_EQ(connectionMap.size(), static_cast<size_t>(1));
    }

    /**
     * @tc.steps: step2. process connect died which is not exist
     * @tc.expected: step2. still can find the newly-added connect session
     */
    DistributedSchedService::GetInstance().ProcessConnectDied(new AbilityConnectCallbackTest());
    {
        std::lock_guard<std::mutex> autoLock(distributedLock);
        EXPECT_EQ(connectionMap.size(), static_cast<size_t>(1));
    }

    RemoveSession(connect);
}

/**
 * @tc.name: ProcessConnectDied003
 * @tc.desc: process connect died and check the trackingUidMap_
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, ProcessConnectDied003, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest ProcessConnectDied003 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    AddSession(connect, "123_local_device_id", "123_remote_device_id", want);

    auto& trackingUidMap = DistributedSchedService::GetInstance().trackingUidMap_;
    /**
     * @tc.steps: step1. Increase connect count
     * @tc.expected: step1. connect count increase one
     */

    int32_t uid = IPCSkeleton::GetCallingUid();
    uint32_t oldCount = trackingUidMap[uid];
    AddConnectCount(uid);
    EXPECT_EQ(trackingUidMap[uid] - oldCount, static_cast<uint32_t>(1));

    /**
     * @tc.steps: step2. process connect died and then check the trackingUidMap_
     * @tc.expected: step2. the connect count is decrease
     */
    DistributedSchedService::GetInstance().ProcessConnectDied(connect);
    auto iter = trackingUidMap.find(uid);
    if (iter != trackingUidMap.end()) {
        EXPECT_EQ(trackingUidMap[uid], oldCount);
    }

    RemoveConnectInfo(connect);
}

/**
 * @tc.name: ProcessConnectDied004
 * @tc.desc: process connect died and check the connectAbilityMap_
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, ProcessConnectDied004, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest ProcessConnectDied004 start" << std::endl;
    auto& connectAbilityMap = DistributedSchedService::GetInstance().connectAbilityMap_;
    auto& distributedLock = DistributedSchedService::GetInstance().distributedLock_;

    /**
     * @tc.steps: step1. add one connectInfo
     * @tc.expected: step1. can find the newly-added connectInfo
     */
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    AddConnectInfo(connect, "123_local_device_id", "123_remote_device_id");
    {
        std::lock_guard<std::mutex> autoLock(distributedLock);
        EXPECT_EQ(connectAbilityMap.size(), static_cast<size_t>(1));
    }

    /**
     * @tc.steps: step2. process connect died and then check the connectAbilityMap_
     * @tc.expected: step2. the connectInfo is removed
     */
    DistributedSchedService::GetInstance().DisconnectAbilityFromRemote(connect,
        IPCSkeleton::GetCallingUid(), "123_local_device_id");
    {
        std::lock_guard<std::mutex> autoLock(distributedLock);
        EXPECT_EQ(connectAbilityMap.size(), static_cast<size_t>(0));
    }

    RemoveConnectInfo(connect);
}

/**
 * @tc.name: ProcessDeviceOffline001
 * @tc.desc: process device offline with only one connection
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, ProcessDeviceOffline001, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedServiceTest ProcessDeviceOffline001 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");
    auto& connectionMap = DistributedSchedService::GetInstance().distributedConnectAbilityMap_;
    auto& distributedLock = DistributedSchedService::GetInstance().distributedLock_;

    /**
     * @tc.steps: step1. add one session
     */
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    AddSession(connect, "123_local_device_id", "123_remote_device_id", want);
    /**
     * @tc.steps: step2. process device offline and check the map
     * @tc.expected: step2. the connect session is removed
     */
    DistributedSchedService::GetInstance().ProcessDeviceOffline("123_remote_device_id");
    {
        std::lock_guard<std::mutex> autoLock(distributedLock);
        EXPECT_EQ(connectionMap.size(), static_cast<size_t>(0));
    }

    RemoveSession(connect);
}

/**
 * @tc.name: ProcessDeviceOffline002
 * @tc.desc: process device offline with multiple connections
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, ProcessDeviceOffline002, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedServiceTest ProcessDeviceOffline002 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");
    auto& connectionMap = DistributedSchedService::GetInstance().distributedConnectAbilityMap_;
    auto& distributedLock = DistributedSchedService::GetInstance().distributedLock_;

    /**
     * @tc.steps: step1. add one session
     * @tc.expected: step1. can find the two newly-added connect sessions
     */
    sptr<AbilityConnectCallbackTest> connect1 = new AbilityConnectCallbackTest();
    AddSession(connect1, "123_local_device_id", "123_remote_device_id", want);
    sptr<AbilityConnectCallbackTest> connect2 = new AbilityConnectCallbackTest();
    AddSession(connect2, "123_local_device_id", "123_remote_device_id", want);
    {
        std::lock_guard<std::mutex> autoLock(distributedLock);
        EXPECT_EQ(connectionMap.size(), static_cast<size_t>(2));
    }

    /**
     * @tc.steps: step2. process device offline
     * @tc.expected: step2. the connect sessions are removed
     */
    DistributedSchedService::GetInstance().ProcessDeviceOffline("123_remote_device_id");
    {
        std::lock_guard<std::mutex> autoLock(distributedLock);
        EXPECT_EQ(connectionMap.size(), static_cast<size_t>(0));
    }

    RemoveSession(connect1);
    RemoveSession(connect2);
}

/**
 * @tc.name: ProcessDeviceOffline003
 * @tc.desc: process device offline with multiple online devices
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, ProcessDeviceOffline003, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedServiceTest ProcessDeviceOffline003 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");
    auto& connectionMap = DistributedSchedService::GetInstance().distributedConnectAbilityMap_;
    auto& distributedLock = DistributedSchedService::GetInstance().distributedLock_;

    /**
     * @tc.steps: step1. add one session
     */
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    AddSession(connect, "123_local_device_id", "123_remote_device_id", want);
    /**
     * @tc.steps: step2. process other device offline and check the map
     * @tc.expected: step2. still can find the newly-added connect session
     */
    DistributedSchedService::GetInstance().ProcessDeviceOffline("456_remote_device_id");
    {
        std::lock_guard<std::mutex> autoLock(distributedLock);
        auto iter = connectionMap.find(connect);
        EXPECT_NE(iter, connectionMap.end());
        EXPECT_EQ(connectionMap.size(), static_cast<size_t>(1));
    }

    RemoveSession(connect);
}

/**
 * @tc.name: ProcessDeviceOffline004
 * @tc.desc: process device offline and check the trackingUidMap_
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, ProcessDeviceOffline004, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest ProcessDeviceOffline004 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    AddSession(connect, "123_local_device_id", "123_remote_device_id", want);

    auto& trackingUidMap = DistributedSchedService::GetInstance().trackingUidMap_;
    /**
     * @tc.steps: step1. Increase connect count
     * @tc.expected: step1. connect count increase one
     */
    int32_t uid = IPCSkeleton::GetCallingUid();
    uint32_t oldCount = trackingUidMap[uid];
    AddConnectCount(uid);
    EXPECT_EQ(trackingUidMap[uid] - oldCount, static_cast<uint32_t>(1));

    /**
     * @tc.steps: step2. process device offline and then check the trackingUidMap_
     * @tc.expected: step2. the connect count is decrease
     */
    DistributedSchedService::GetInstance().ProcessDeviceOffline("123_remote_device_id");
    auto iter = trackingUidMap.find(uid);
    if (iter != trackingUidMap.end()) {
        EXPECT_EQ(trackingUidMap[uid], oldCount);
    }

    RemoveConnectInfo(connect);
}

/**
 * @tc.name: ProcessDeviceOffline005
 * @tc.desc: process device offline and check the connectAbilityMap_
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, ProcessDeviceOffline005, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest ProcessDeviceOffline005 start" << std::endl;
    auto& connectAbilityMap = DistributedSchedService::GetInstance().connectAbilityMap_;
    auto& distributedLock = DistributedSchedService::GetInstance().distributedLock_;

    /**
     * @tc.steps: step1. add one connectInfo
     * @tc.expected: step1. can find the newly-added connectInfo
     */
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    AddConnectInfo(connect, "123_local_device_id", "123_remote_device_id");
    {
        std::lock_guard<std::mutex> autoLock(distributedLock);
        EXPECT_EQ(connectAbilityMap.size(), static_cast<size_t>(1));
    }

    /**
     * @tc.steps: step2. process device offline and then check the connectAbilityMap_
     * @tc.expected: step2. the connectInfo is removed
     */
    DistributedSchedService::GetInstance().ProcessDeviceOffline("123_local_device_id");
    {
        std::lock_guard<std::mutex> autoLock(distributedLock);
        EXPECT_EQ(connectAbilityMap.size(), static_cast<size_t>(0));
    }

    RemoveConnectInfo(connect);
}

/**
 * @tc.name: DisconnectRemoteAbility001
 * @tc.desc: disconnect remote ability
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, DisconnectRemoteAbility001, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedServiceTest DisconnectRemoteAbility001 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");
    auto& connectionMap = DistributedSchedService::GetInstance().distributedConnectAbilityMap_;
    auto& distributedLock = DistributedSchedService::GetInstance().distributedLock_;

    /**
     * @tc.steps: step1. add one session
     */
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    AddSession(connect, "123_local_device_id", "123_remote_device_id", want);
    /**
     * @tc.steps: step2. disconnect the ability and check the map
     * @tc.expected: step2. the connect session is removed
     */
    DistributedSchedService::GetInstance().DisconnectRemoteAbility(connect, 0, 0);
    {
        std::lock_guard<std::mutex> autoLock(distributedLock);
        EXPECT_EQ(connectionMap.size(), static_cast<size_t>(0));
    }

    RemoveSession(connect);
}

/**
 * @tc.name: DisconnectRemoteAbility002
 * @tc.desc: disconnect remote ability and check the trackingUidMap_
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, DisconnectRemoteAbility002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest DisconnectRemoteAbility002 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    AddSession(connect, "123_local_device_id", "123_remote_device_id", want);

    auto& trackingUidMap = DistributedSchedService::GetInstance().trackingUidMap_;
    /**
     * @tc.steps: step1. Increase connect count
     * @tc.expected: step1. connect count increase one
     */
    int32_t uid = IPCSkeleton::GetCallingUid();
    uint32_t oldCount = trackingUidMap[uid];
    AddConnectCount(uid);
    uint32_t newCount = trackingUidMap[uid];
    EXPECT_EQ(newCount - oldCount, static_cast<uint32_t>(1));

    /**
     * @tc.steps: step2. disconnect remote ability and then check the trackingUidMap_
     * @tc.expected: step2. the connect count is decrease
     */
    DistributedSchedService::GetInstance().DisconnectRemoteAbility(connect, 0, 0);
    auto iter = trackingUidMap.find(uid);
    if (iter != trackingUidMap.end()) {
        EXPECT_EQ(trackingUidMap[uid], oldCount);
    }

    RemoveConnectInfo(connect);
}

/**
 * @tc.name: DisconnectRemoteAbility003
 * @tc.desc: disconnect remote ability whith error callback
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, DisconnectRemoteAbility003, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedServiceTest DisconnectRemoteAbility003 start" << std::endl;
    int32_t ret = DistributedSchedService::GetInstance().DisconnectRemoteAbility(nullptr, 0, 0);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest DisconnectRemoteAbility003 end" << std::endl;
}

/**
 * @tc.name: ConnectRemoteAbility
 * @tc.desc: connect remote ability whith error uid and pid
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ConnectRemoteAbility001, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedServiceTest ConnectRemoteAbility001 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("123_remote_device_id", "ohos.demo.bundleName", "abilityName");
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    int32_t ret = DistributedSchedService::GetInstance().ConnectRemoteAbility(want, connect, -1, -1, -1);
    EXPECT_EQ(ret, BIND_ABILITY_UID_INVALID_ERR);
    DTEST_LOG << "DistributedSchedServiceTest ConnectRemoteAbility001 end" << std::endl;
}

/**
 * @tc.name: ConnectRemoteAbility
 * @tc.desc: connect remote ability whith empty deviceId.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ConnectRemoteAbility002, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedServiceTest ConnectRemoteAbility002 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    int32_t ret = DistributedSchedService::GetInstance().ConnectRemoteAbility(want, connect, -1, -1, -1);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest ConnectRemoteAbility002 end" << std::endl;
}

/**
 * @tc.name: ConnectAbilityFromRemote
 * @tc.desc: connect remote ability whith fake deviceId.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ConnectAbilityFromRemote001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedConnectTest ConnectAbilityFromRemote001 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("123_remote_device_id", "ohos.demo.bundleName", "abilityName");
    AppExecFwk::AbilityInfo abilityInfo;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    int32_t ret = DistributedSchedService::GetInstance().ConnectAbilityFromRemote(want,
        abilityInfo, connect, callerInfo, accountInfo);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedConnectTest ConnectAbilityFromRemote001 end" << std::endl;
}

/**
 * @tc.name: ConnectAbilityFromRemote
 * @tc.desc: connect remote ability whith error callback.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ConnectAbilityFromRemote002, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedConnectTest ConnectAbilityFromRemote002 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("123_remote_device_id", "ohos.demo.bundleName", "abilityName");
    AppExecFwk::AbilityInfo abilityInfo;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    int32_t ret = DistributedSchedService::GetInstance().ConnectAbilityFromRemote(want,
        abilityInfo, nullptr, callerInfo, accountInfo);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedConnectTest ConnectAbilityFromRemote002 end" << std::endl;
}

/**
 * @tc.name: ConnectAbilityFromRemote
 * @tc.desc: connect remote ability whith error param
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ConnectAbilityFromRemote003, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedConnectTest ConnectAbilityFromRemote003 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    AppExecFwk::AbilityInfo abilityInfo;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    int32_t ret = DistributedSchedService::GetInstance().ConnectAbilityFromRemote(want,
        abilityInfo, connect, callerInfo, accountInfo);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedConnectTest ConnectAbilityFromRemote003 end" << std::endl;
}

/**
 * @tc.name: ConnectAbilityFromRemote
 * @tc.desc: connect remote ability whith null callback
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ConnectAbilityFromRemote004, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedConnectTest ConnectAbilityFromRemote004 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");
    AppExecFwk::AbilityInfo abilityInfo;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    int32_t ret = DistributedSchedService::GetInstance().ConnectAbilityFromRemote(want,
        abilityInfo, nullptr, callerInfo, accountInfo);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedConnectTest ConnectAbilityFromRemote004 end" << std::endl;
}

/**
 * @tc.name: DisconnectEachRemoteAbilityLocked
 * @tc.desc: disconnect remote ability.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, DisconnectEachRemoteAbilityLocked001, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedConnectTest DisconnectEachRemoteAbilityLocked001 start" << std::endl;
    int32_t ret = DistributedSchedService::GetInstance().DisconnectEachRemoteAbilityLocked("", "", nullptr);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedConnectTest DisconnectEachRemoteAbilityLocked001 end" << std::endl;
}

/**
 * @tc.name: DisconnectEachRemoteAbilityLocked
 * @tc.desc: disconnect remote ability.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, DisconnectEachRemoteAbilityLocked002, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedConnectTest DisconnectEachRemoteAbilityLocked002 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    int32_t ret = DistributedSchedService::GetInstance().DisconnectEachRemoteAbilityLocked("", "", connect);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedConnectTest DisconnectEachRemoteAbilityLocked002 end" << std::endl;
}

/**
 * @tc.name: DisconnectEachRemoteAbilityLocked
 * @tc.desc: disconnect remote ability.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, DisconnectEachRemoteAbilityLocked003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedConnectTest DisconnectEachRemoteAbilityLocked003 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    int32_t ret = DistributedSchedService::GetInstance().DisconnectEachRemoteAbilityLocked(
        "123_remote_device_id", "123_remote_device_id", connect);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedConnectTest DisconnectEachRemoteAbilityLocked003 end" << std::endl;
}

/**
 * @tc.name: DisconnectEachRemoteAbilityLocked
 * @tc.desc: disconnect remote ability.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, DisconnectEachRemoteAbilityLocked004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedConnectTest DisconnectEachRemoteAbilityLocked004 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    std::string deviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(deviceId);
    int32_t ret = DistributedSchedService::GetInstance().DisconnectEachRemoteAbilityLocked(
        deviceId, deviceId, connect);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedConnectTest DisconnectEachRemoteAbilityLocked004 end" << std::endl;
}

/**
 * @tc.name: DisconnectRemoteAbility
 * @tc.desc: disconnect remote ability.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, DisconnectRemoteAbility004, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedConnectTest DisconnectRemoteAbility004 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    int32_t ret = DistributedSchedService::GetInstance().DisconnectRemoteAbility(connect, 0, 0);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedConnectTest DisconnectRemoteAbility004 end" << std::endl;
}

/**
 * @tc.name: DisconnectRemoteAbility
 * @tc.desc: disconnect remote ability.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, DisconnectRemoteAbility005, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedConnectTest DisconnectRemoteAbility005 start" << std::endl;
    /**
     * @tc.steps: step1. call RemoveCallerComponent
     */
    DTEST_LOG << "DistributedSchedServiceTest RemoveCallerComponent001 start" << std::endl;
    OHOS::AAFwk::Want want;
    std::string localDeviceId = "123_local_device_id";
    std::string remoteDeviceId = "123_remote_device_id";
    want.SetElementName(remoteDeviceId, "ohos.demo.bundleName", "abilityName");
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    CallerInfo callerInfo;
    callerInfo.uid = IPCSkeleton::GetCallingUid();
    callerInfo.pid = IPCSkeleton::GetCallingRealPid();
    callerInfo.sourceDeviceId = localDeviceId;
    callerInfo.callerType = CALLER_TYPE_HARMONY;
    DistributedSchedService::GetInstance().SaveCallerComponent(want, connect, callerInfo);
    DistributedSchedService::GetInstance().RemoveCallerComponent(connect);
    DTEST_LOG << "DistributedSchedServiceTest RemoveCallerComponent001 end" << std::endl;

    int32_t ret = DistributedSchedService::GetInstance().DisconnectRemoteAbility(nullptr, 0, 0);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedConnectTest DisconnectRemoteAbility005 end" << std::endl;
}

/**
 * @tc.name: DisconnectAbilityFromRemote
 * @tc.desc: disconnect ability from remote.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, DisconnectAbilityFromRemote001, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedConnectTest DisconnectAbilityFromRemote001 start" << std::endl;
    /**
     * @tc.steps: step1. call RemoveCallerComponent
     */
    DTEST_LOG << "DistributedSchedServiceTest SaveCallerComponent002 start" << std::endl;
    std::string localDeviceId = "123_local_device_id";
    std::string remoteDeviceId = "123_remote_device_id";
    OHOS::AAFwk::Want want1;
    want1.SetElementName(remoteDeviceId, "ohos.demo.bundleName1", "abilityName1");
    OHOS::AAFwk::Want want2;
    want2.SetElementName(remoteDeviceId, "ohos.demo.bundleName2", "abilityName2");
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    CallerInfo callerInfo;
    callerInfo.uid = IPCSkeleton::GetCallingUid();
    callerInfo.pid = IPCSkeleton::GetCallingRealPid();
    callerInfo.sourceDeviceId = localDeviceId;
    callerInfo.callerType = CALLER_TYPE_HARMONY;
    DistributedSchedService::GetInstance().SaveCallerComponent(want1, connect, callerInfo);
    DistributedSchedService::GetInstance().SaveCallerComponent(want2, connect, callerInfo);
    DTEST_LOG << "DistributedSchedServiceTest SaveCallerComponent002 end" << std::endl;

    int32_t ret = DistributedSchedService::GetInstance().DisconnectAbilityFromRemote(nullptr, 0, "");
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedConnectTest DisconnectAbilityFromRemote001 end" << std::endl;
}

/**
 * @tc.name: DisconnectAbilityFromRemote
 * @tc.desc: disconnect ability from remote.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, DisconnectAbilityFromRemote002, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedConnectTest DisconnectAbilityFromRemote002 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    int32_t ret = DistributedSchedService::GetInstance().DisconnectAbilityFromRemote(connect, 0, "");
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedConnectTest DisconnectAbilityFromRemote002 end" << std::endl;
}

/**
 * @tc.name: DisconnectAbilityFromRemote
 * @tc.desc: disconnect ability from remote.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, DisconnectAbilityFromRemote003, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedConnectTest DisconnectAbilityFromRemote003 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    std::string deviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(deviceId);
    int32_t ret = DistributedSchedService::GetInstance().DisconnectAbilityFromRemote(connect, 0, deviceId);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedConnectTest DisconnectAbilityFromRemote003 end" << std::endl;
}

/**
 * @tc.name: DisconnectAbilityFromRemote
 * @tc.desc: disconnect ability from remote.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, DisconnectAbilityFromRemote004, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedConnectTest DisconnectAbilityFromRemote004 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    /**
     * @tc.steps: step1. call SaveCallerComponent
     */
    DTEST_LOG << "DistributedSchedServiceTest SaveCallerComponent001 start" << std::endl;
    OHOS::AAFwk::Want want;
    std::string localDeviceId = "123_local_device_id";
    std::string remoteDeviceId = "123_remote_device_id";
    want.SetElementName(remoteDeviceId, "ohos.demo.bundleName", "abilityName");
    CallerInfo callerInfo;
    callerInfo.uid = IPCSkeleton::GetCallingUid();
    callerInfo.pid = IPCSkeleton::GetCallingRealPid();
    callerInfo.sourceDeviceId = localDeviceId;
    callerInfo.callerType = CALLER_TYPE_HARMONY;
    DistributedSchedService::GetInstance().SaveCallerComponent(want, connect, callerInfo);
    DTEST_LOG << "DistributedSchedServiceTest SaveCallerComponent001 end" << std::endl;

    int32_t ret = DistributedSchedService::GetInstance().DisconnectAbilityFromRemote(
        connect, 0, "123_remote_device_id");
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedConnectTest DisconnectAbilityFromRemote004 end" << std::endl;
}

/**
 * @tc.name: ProcessDeviceOffline
 * @tc.desc: device offline, clear the connect info using fake deviceId.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ProcessDeviceOffline006, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedConnectTest ProcessDeviceOffline006 start" << std::endl;
    DistributedSchedService::GetInstance().ProcessDeviceOffline("123_remote_device_id");
    DTEST_LOG << "DistributedSchedConnectTest ProcessDeviceOffline006 end" << std::endl;
}

/**
 * @tc.name: ProcessDeviceOffline
 * @tc.desc: device offline, clear connect info using empty deviceId.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ProcessDeviceOffline007, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedConnectTest ProcessDeviceOffline007 start" << std::endl;
    DistributedSchedService::GetInstance().ProcessDeviceOffline("");
    DTEST_LOG << "DistributedSchedConnectTest ProcessDeviceOffline007 end" << std::endl;
}

/**
 * @tc.name: ProcessDeviceOffline
 * @tc.desc: device offline, clear connect info using local deviceId.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ProcessDeviceOffline008, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedConnectTest ProcessDeviceOffline008 start" << std::endl;
    std::string deviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(deviceId);
    DistributedSchedService::GetInstance().ProcessDeviceOffline(deviceId);
    DTEST_LOG << "DistributedSchedConnectTest ProcessDeviceOffline008 end" << std::endl;
}

/**
 * @tc.name: NotifyApp
 * @tc.desc: notify app to dealwith the offline message.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, NotifyApp001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedConnectTest NotifyApp001 start" << std::endl;
    AppExecFwk::ElementName element;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    /**
     * @tc.steps: step1. call ProcessCalleeDied
     */
    DTEST_LOG << "DistributedSchedServiceTest ProcessCalleeDied002 start" << std::endl;
    sptr<IRemoteObject> callbackWrapper = new AbilityConnectionWrapperStubTest(connect);
    CallerInfo callerInfo;
    ConnectInfo connectInfo {callerInfo, callbackWrapper};
    DistributedSchedService::GetInstance().calleeMap_.emplace(connect, connectInfo);
    DistributedSchedService::GetInstance().ProcessCalleeDied(connect);
    DTEST_LOG << "DistributedSchedServiceTest ProcessCalleeDied002 end" << std::endl;
    
    int32_t ret = DistributedSchedService::GetInstance().NotifyApp(connect, element, 0);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedConnectTest NotifyApp001 end" << std::endl;
}

/**
 * @tc.name: NotifyApp
 * @tc.desc: notify app to dealwith the offline message.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, NotifyApp002, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedConnectTest NotifyApp002 start" << std::endl;
    AppExecFwk::ElementName element;
    /**
     * @tc.steps: step1. call ProcessCalleeDied
     */
    DTEST_LOG << "DistributedSchedServiceTest ProcessCalleeDied001 start" << std::endl;
    DistributedSchedService::GetInstance().ProcessCalleeDied(nullptr);
    DTEST_LOG << "DistributedSchedServiceTest ProcessCalleeDied001 end" << std::endl;

    int32_t ret = DistributedSchedService::GetInstance().NotifyApp(nullptr, element, 0);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedConnectTest NotifyApp002 end" << std::endl;
}

/**
 * @tc.name: ProcessConnectDied
 * @tc.desc: dealwith the app died message.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ProcessConnectDied005, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedConnectTest ProcessConnectDied005 start" << std::endl;
    DistributedSchedService::GetInstance().ProcessConnectDied(nullptr);
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    DistributedSchedService::GetInstance().ProcessConnectDied(connect);
    DTEST_LOG << "DistributedSchedConnectTest ProcessConnectDied005 end" << std::endl;
}

/**
 * @tc.name: NotifyProcessDied001
 * @tc.desc: notify process died message to remote.
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, NotifyProcessDied001, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedConnectTest NotifyProcessDied001 start" << std::endl;
    TargetComponent targetComponent {TargetComponent::HARMONY_COMPONENT};
    CallerInfo callerInfo;
    DistributedSchedService::GetInstance().NotifyProcessDied("", callerInfo, targetComponent);
    DistributedSchedService::GetInstance().NotifyProcessDied("123_remote_device_id", callerInfo, targetComponent);
    DTEST_LOG << "DistributedSchedConnectTest NotifyProcessDied001 end" << std::endl;
}

/**
 * @tc.name: ProxyCallDisconnectRemoteAbility001
 * @tc.desc: call dms proxy DisconnectRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ProxyCallDisconnectRemoteAbility001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallDisconnectRemoteAbility001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    /**
     * @tc.steps: step1. call HandleLocalCallerDied
     */
    DTEST_LOG << "DistributedSchedServiceTest HandleLocalCallerDied002 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    DistributedSchedService::GetInstance().RemoveCallerComponent(connect);
    DistributedSchedService::GetInstance().HandleLocalCallerDied(connect);
    DTEST_LOG << "DistributedSchedServiceTest HandleLocalCallerDied002 end" << std::endl;

    int32_t ret = proxy->DisconnectRemoteAbility(nullptr, 0, 0);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallDisconnectRemoteAbility001 end" << std::endl;
}

/**
 * @tc.name: ProxyCallDisconnectRemoteAbility002
 * @tc.desc: call dms proxy DisconnectRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ProxyCallDisconnectRemoteAbility002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallDisconnectRemoteAbility002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    /**
     * @tc.steps: step1. call HandleLocalCallerDied
     */
    DTEST_LOG << "DistributedSchedServiceTest HandleLocalCallerDied001 start" << std::endl;
    OHOS::AAFwk::Want want;
    std::string localDeviceId = "123_local_device_id";
    std::string remoteDeviceId = "123_remote_device_id";
    want.SetElementName(remoteDeviceId, "ohos.demo.bundleName", "abilityName");
    CallerInfo callerInfo;
    callerInfo.uid = IPCSkeleton::GetCallingUid();
    callerInfo.pid = IPCSkeleton::GetCallingRealPid();
    callerInfo.sourceDeviceId = localDeviceId;
    callerInfo.callerType = CALLER_TYPE_HARMONY;
    DistributedSchedService::GetInstance().SaveCallerComponent(want, connect, callerInfo);
    DistributedSchedService::GetInstance().HandleLocalCallerDied(connect);
    DTEST_LOG << "DistributedSchedServiceTest HandleLocalCallerDied001 end" << std::endl;

    int32_t ret = proxy->DisconnectRemoteAbility(connect, 0, 0);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallDisconnectRemoteAbility002 end" << std::endl;
}

/**
 * @tc.name: ProxyCallConnectRemoteAbility001
 * @tc.desc: call dms proxy ConnectRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ProxyCallConnectRemoteAbility001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallConnectRemoteAbility001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    OHOS::AAFwk::Want want;
    want.SetElementName("123_remote_device_id", "ohos.demo.bundleName", "abilityName");
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    /**
     * @tc.steps: step1. call GetUidLocked
     */
    DTEST_LOG << "DistributedSchedConnectTest GetUidLocked001 start" << std::endl;
    std::list<ConnectAbilitySession> sessionsList;
    DistributedSchedService::GetInstance().GetUidLocked(sessionsList);
    DTEST_LOG << "DistributedSchedConnectTest GetUidLocked001 end" << std::endl;

    int32_t ret = proxy->ConnectRemoteAbility(want, connect, 0, 0, 0);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallConnectRemoteAbility001 end" << std::endl;
}

/**
 * @tc.name: ProxyCallConnectRemoteAbility002
 * @tc.desc: call dms proxy ConnectRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ProxyCallConnectRemoteAbility002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallConnectRemoteAbility002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    OHOS::AAFwk::Want want;
    want.SetElementName("123_remote_device_id", "ohos.demo.bundleName", "abilityName");
    /**
     * @tc.steps: step1. call DecreaseConnectLocked
     */
    DTEST_LOG << "DistributedSchedConnectTest DecreaseConnectLocked002 start" << std::endl;
    int32_t uid = 1000;
    AddConnectCount(uid);
    DistributedSchedService::GetInstance().DecreaseConnectLocked(uid);
    DTEST_LOG << "DistributedSchedConnectTest DecreaseConnectLocked002 end" << std::endl;

    int32_t ret = proxy->ConnectRemoteAbility(want, nullptr, 0, 0, 0);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallConnectRemoteAbility002 end" << std::endl;
}

/**
 * @tc.name: ProxyCallConnectAbilityFromRemote001
 * @tc.desc: call dms proxy ConnectAbilityFromRemote
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ProxyCallConnectAbilityFromRemote001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallConnectAbilityFromRemote001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    OHOS::AAFwk::Want want;
    want.SetElementName("123_remote_device_id", "ohos.demo.bundleName", "abilityName");
    AppExecFwk::AbilityInfo abilityInfo;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    /**
     * @tc.steps: step1. call DecreaseConnectLocked
     */
    DTEST_LOG << "DistributedSchedConnectTest DecreaseConnectLocked001 start" << std::endl;
    int32_t uid = -1;
    DistributedSchedService::GetInstance().DecreaseConnectLocked(uid);
    DTEST_LOG << "DistributedSchedConnectTest DecreaseConnectLocked001 end" << std::endl;

    int32_t ret = proxy->ConnectAbilityFromRemote(want, abilityInfo,
        connect, callerInfo, accountInfo);
    EXPECT_EQ(ret, REQUEST_CODE_ERR);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallConnectAbilityFromRemote001 end" << std::endl;
}

/**
 * @tc.name: ProxyCallConnectAbilityFromRemote002
 * @tc.desc: call dms proxy ConnectAbilityFromRemote
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ProxyCallConnectAbilityFromRemote002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallConnectAbilityFromRemote002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    OHOS::AAFwk::Want want;
    want.SetElementName("123_remote_device_id", "ohos.demo.bundleName", "abilityName");
    AppExecFwk::AbilityInfo abilityInfo;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    /**
     * @tc.steps: step1. call CheckDistributedConnectLocked
     */
    DTEST_LOG << "DistributedSchedConnectTest CheckDistributedConnectLocked002 start" << std::endl;
    int32_t uid = IPCSkeleton::GetCallingUid();
    callerInfo.uid = uid;
    DistributedSchedService::GetInstance().CheckDistributedConnectLocked(callerInfo);
    DTEST_LOG << "DistributedSchedConnectTest CheckDistributedConnectLocked002 end" << std::endl;

    int32_t ret = proxy->ConnectAbilityFromRemote(want, abilityInfo,
        nullptr, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallConnectAbilityFromRemote002 end" << std::endl;
}

/**
 * @tc.name: ProxyCallDisconnectAbilityFromRemote001
 * @tc.desc: call dms proxy DisconnectAbilityFromRemote
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ProxyCallDisconnectAbilityFromRemote001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallDisconnectAbilityFromRemote001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    /**
     * @tc.steps: step1. call CheckDistributedConnectLocked
     */
    DTEST_LOG << "DistributedSchedConnectTest CheckDistributedConnectLocked001 start" << std::endl;
    int32_t uid = IPCSkeleton::GetCallingUid();
    CallerInfo callerInfo;
    callerInfo.uid = uid;
    AddConnectCount(uid);
    DistributedSchedService::GetInstance().CheckDistributedConnectLocked(callerInfo);
    DTEST_LOG << "DistributedSchedConnectTest CheckDistributedConnectLocked001 end" << std::endl;

    int32_t ret = proxy->DisconnectAbilityFromRemote(connect, 0, "");
    EXPECT_EQ(ret, REQUEST_CODE_ERR);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallDisconnectAbilityFromRemote001 end" << std::endl;
}

/**
 * @tc.name: ProxyCallDisconnectAbilityFromRemote002
 * @tc.desc: call dms proxy DisconnectAbilityFromRemote
 * @tc.type: FUNC
 * @tc.require: I5OOKG
 */
HWTEST_F(DistributedSchedConnectTest, ProxyCallDisconnectAbilityFromRemote002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallDisconnectAbilityFromRemote002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    /**
     * @tc.steps: step1. call RemoteConnectAbilityMappingLocked
     */
    DTEST_LOG << "DistributedSchedConnectTest CheckDistributedConnectLocked001 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    std::string localDeviceId = "123_local_device_id";
    std::string remoteDeviceId = "123_remote_device_id";
    CallerInfo callerInfo;
    AddSession(connect, localDeviceId, remoteDeviceId, want);
    DistributedSchedService::GetInstance().RemoteConnectAbilityMappingLocked(connect, localDeviceId,
        remoteDeviceId, want.GetElement(), callerInfo, TargetComponent::HARMONY_COMPONENT);
    DTEST_LOG << "DistributedSchedConnectTest RemoteConnectAbilityMappingLocked001 end" << std::endl;
    
    int32_t ret = proxy->DisconnectAbilityFromRemote(nullptr, 0, "");
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallDisconnectAbilityFromRemote002 end" << std::endl;
}

/**
 * @tc.name: ConnectRemoteAbility003
 * @tc.desc: call ConnectRemoteAbility
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, ConnectRemoteAbility003, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedServiceTest ConnectRemoteAbility003 start" << std::endl;
    std::string remoteDeviceId = "remoteDeviceId";
    OHOS::AAFwk::Want want;
    want.SetElementName(remoteDeviceId, "ohos.demo.bundleName", "abilityName");
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t pid = IPCSkeleton::GetCallingRealPid();
    int32_t accessToken = IPCSkeleton::GetCallingTokenID();
    int32_t ret = DistributedSchedService::GetInstance().ConnectRemoteAbility(want, connect, uid, pid, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest ConnectRemoteAbility003 end" << std::endl;
}

/**
 * @tc.name: TryConnectRemoteAbility001
 * @tc.desc: call TryConnectRemoteAbility
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, TryConnectRemoteAbility001, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedServiceTest TryConnectRemoteAbility001 start" << std::endl;
    std::string remoteDeviceId = "remoteDeviceId";
    OHOS::AAFwk::Want want;
    want.SetElementName(remoteDeviceId, "ohos.demo.bundleName", "abilityName");
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    CallerInfo callerInfo;
    int32_t ret = DistributedSchedService::GetInstance().TryConnectRemoteAbility(want, connect, callerInfo);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest TryConnectRemoteAbility001 end" << std::endl;
}

/**
 * @tc.name: ProcessCallerDied001
 * @tc.desc: call ProcessCallerDied
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, ProcessCallerDied001, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedServiceTest ProcessCallerDied001 start" << std::endl;
    int32_t deviceType = IDistributedSched::CALLER;
    DistributedSchedService::GetInstance().ProcessCallerDied(nullptr, deviceType);
    DTEST_LOG << "DistributedSchedServiceTest ProcessCallerDied001 end" << std::endl;
}

/**
 * @tc.name: ProcessCallerDied002
 * @tc.desc: call ProcessCallerDied
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, ProcessCallerDied002, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedServiceTest ProcessCallerDied002 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    int32_t deviceType = IDistributedSched::CALLER;
    DistributedSchedService::GetInstance().ProcessCallerDied(connect, deviceType);
    DTEST_LOG << "DistributedSchedServiceTest ProcessCallerDied002 end" << std::endl;
}

/**
 * @tc.name: ProcessCallerDied003
 * @tc.desc: call ProcessCallerDied
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, ProcessCallerDied003, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedServiceTest ProcessCallerDied003 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    int32_t deviceType = IDistributedSched::CALLEE;
    CallerInfo callerInfo;
    sptr<IRemoteObject> callbackWrapper = new AbilityConnectionWrapperStubTest(connect);
    ConnectInfo connectInfo {callerInfo, callbackWrapper};
    DistributedSchedService::GetInstance().calleeMap_.emplace(connect, connectInfo);
    DistributedSchedService::GetInstance().ProcessCallerDied(connect, deviceType);
    DTEST_LOG << "DistributedSchedServiceTest ProcessCallerDied003 end" << std::endl;
}

/**
 * @tc.name: AbilityConnectionWrapperStub001
 * @tc.desc: receive connect message
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, AbilityConnectionWrapperStub001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub001 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    ASSERT_NE(connect, nullptr);
    sptr<AbilityConnectionWrapperStub> connectStub = new AbilityConnectionWrapperStub(connect);
    ASSERT_NE(connectStub, nullptr);
    MessageParcel data;
    if (!data.WriteInterfaceToken(CONNECTION_CALLBACK_INTERFACE_TOKEN)) {
        return;
    }
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::ElementName element;
    PARCEL_WRITE_HELPER_NORET(data, Parcelable, &element);
    PARCEL_WRITE_HELPER_NORET(data, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(data, Int32, 1);
    int32_t result = connectStub->OnRemoteRequest(IAbilityConnection::ON_ABILITY_CONNECT_DONE, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub001 end" << std::endl;
}

/**
 * @tc.name: AbilityConnectionWrapperStub002
 * @tc.desc: receive oncall message
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, AbilityConnectionWrapperStub002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub002 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    ASSERT_NE(connect, nullptr);
    sptr<AbilityConnectionWrapperStub> connectStub = new AbilityConnectionWrapperStub(connect, "localDeviceId");
    ASSERT_NE(connectStub, nullptr);
    MessageParcel data;
    if (!data.WriteInterfaceToken(CONNECTION_CALLBACK_INTERFACE_TOKEN)) {
        return;
    }
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::ElementName element;
    PARCEL_WRITE_HELPER_NORET(data, Parcelable, &element);
    PARCEL_WRITE_HELPER_NORET(data, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(data, Int32, 1);
    int32_t result = connectStub->OnRemoteRequest(IAbilityConnection::ON_ABILITY_CONNECT_DONE, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub002 end" << std::endl;
}

/**
 * @tc.name: AbilityConnectionWrapperStub003
 * @tc.desc: receive disconnect message
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, AbilityConnectionWrapperStub003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub003 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    ASSERT_NE(connect, nullptr);
    sptr<AbilityConnectionWrapperStub> connectStub = new AbilityConnectionWrapperStub(connect);
    ASSERT_NE(connectStub, nullptr);
    MessageParcel data;
    if (!data.WriteInterfaceToken(CONNECTION_CALLBACK_INTERFACE_TOKEN)) {
        return;
    }
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::ElementName element;
    PARCEL_WRITE_HELPER_NORET(data, Parcelable, &element);
    PARCEL_WRITE_HELPER_NORET(data, Int32, 1);
    int32_t result = connectStub->OnRemoteRequest(IAbilityConnection::ON_ABILITY_DISCONNECT_DONE, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub003 end" << std::endl;
}

/**
 * @tc.name: AbilityConnectionWrapperStub004
 * @tc.desc: receive oncall disconnect message
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, AbilityConnectionWrapperStub004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub004 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    ASSERT_NE(connect, nullptr);
    sptr<AbilityConnectionWrapperStub> connectStub = new AbilityConnectionWrapperStub(connect, "localDeviceId");
    ASSERT_NE(connectStub, nullptr);
    MessageParcel data;
    if (!data.WriteInterfaceToken(CONNECTION_CALLBACK_INTERFACE_TOKEN)) {
        return;
    }
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::ElementName element;
    PARCEL_WRITE_HELPER_NORET(data, Parcelable, &element);
    PARCEL_WRITE_HELPER_NORET(data, Int32, 1);
    int32_t result = connectStub->OnRemoteRequest(IAbilityConnection::ON_ABILITY_DISCONNECT_DONE, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub004 end" << std::endl;
}

/**
 * @tc.name: AbilityConnectionWrapperStub005
 * @tc.desc: receive error connect message
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, AbilityConnectionWrapperStub005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub005 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    ASSERT_NE(connect, nullptr);
    sptr<AbilityConnectionWrapperStub> connectStub = new AbilityConnectionWrapperStub(connect, "localDeviceId");
    ASSERT_NE(connectStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    // no interface token
    AppExecFwk::ElementName element;
    PARCEL_WRITE_HELPER_NORET(data, Parcelable, &element);
    PARCEL_WRITE_HELPER_NORET(data, Int32, 1);
    int32_t result = connectStub->OnRemoteRequest(IAbilityConnection::ON_ABILITY_DISCONNECT_DONE, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_STATE);
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub005 end" << std::endl;
}

/**
 * @tc.name: AbilityConnectionWrapperStub006
 * @tc.desc: receive error connect message
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, AbilityConnectionWrapperStub006, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub006 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    ASSERT_NE(connect, nullptr);
    sptr<AbilityConnectionWrapperStub> connectStub = new AbilityConnectionWrapperStub(connect, "localDeviceId");
    ASSERT_NE(connectStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(CONNECTION_CALLBACK_INTERFACE_TOKEN)) {
        return;
    }
    // no element
    int32_t result = connectStub->OnRemoteRequest(IAbilityConnection::ON_ABILITY_DISCONNECT_DONE, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub006 end" << std::endl;
}

/**
 * @tc.name: AbilityConnectionWrapperStub007
 * @tc.desc: receive disconnect message
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, AbilityConnectionWrapperStub007, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub007 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    ASSERT_NE(connect, nullptr);
    sptr<AbilityConnectionWrapperStub> connectStub = new AbilityConnectionWrapperStub(connect, "localDeviceId");
    ASSERT_NE(connectStub, nullptr);
    MessageParcel data;
    if (!data.WriteInterfaceToken(CONNECTION_CALLBACK_INTERFACE_TOKEN)) {
        return;
    }
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::ElementName element;
    PARCEL_WRITE_HELPER_NORET(data, Parcelable, &element);
    PARCEL_WRITE_HELPER_NORET(data, Int32, 1);
    // using error code
    int32_t result = connectStub->OnRemoteRequest(ERROR_CONNECT_CODE, data, reply, option);
    EXPECT_NE(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub007 end" << std::endl;
}

/**
 * @tc.name: AbilityConnectionWrapperStub008
 * @tc.desc: receive error connect message
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedConnectTest, AbilityConnectionWrapperStub008, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub008 start" << std::endl;
    sptr<AbilityConnectCallbackTest> connect = new AbilityConnectCallbackTest();
    ASSERT_NE(connect, nullptr);
    sptr<AbilityConnectionWrapperStub> connectStub = new AbilityConnectionWrapperStub(connect, "localDeviceId");
    ASSERT_NE(connectStub, nullptr);
    MessageParcel data;
    if (!data.WriteInterfaceToken(CONNECTION_CALLBACK_INTERFACE_TOKEN)) {
        return;
    }
    MessageParcel reply;
    MessageOption option;
    // no remoteObject
    AppExecFwk::ElementName element;
    PARCEL_WRITE_HELPER_NORET(data, Parcelable, &element);
    PARCEL_WRITE_HELPER_NORET(data, Int32, 1);
    int32_t result = connectStub->OnRemoteRequest(IAbilityConnection::ON_ABILITY_CONNECT_DONE, data, reply, option);
    EXPECT_NE(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedServiceTest AbilityConnectionWrapperStub008 end" << std::endl;
}
}
}

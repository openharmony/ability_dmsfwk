/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "ability_connect_callback_stub.h"
#include "device_manager.h"
#include "distributed_sched_service.h"
#include "distributed_sched_util.h"
#include "dtbschedmgr_device_info_storage.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "test_log.h"
#undef private
#undef protected

namespace OHOS {
namespace DistributedSchedule {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedHardware;

namespace {
constexpr int32_t STDOUT_FD = 1;
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
    const std::string pkgName = "DBinderBus_" + std::to_string(getpid());
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
    callerInfo.pid = IPCSkeleton::GetCallingPid();
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
    callerInfo.pid = IPCSkeleton::GetCallingPid();
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
}
}

/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "distributed_sched_util.h"

#include <future>

#include "accesstoken_kit.h"
#include "bundle_installer_interface.h"
#include "dtbschedmgr_log.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "nativetoken_kit.h"
#include "nocopyable.h"
#include "status_receiver_host.h"
#include "status_receiver_interface.h"
#include "system_ability_definition.h"
#include "token_setproc.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace AppExecFwk;
namespace {
const std::string TAG = "DistributedSchedUtil";
const std::string HAP_FILE_PATH = "/data/test/resource/dmsfwk/resource/bmsThirdBundle.hap";
const char* DISTSCHED_PROCESS_NAME = "distributedsched";
constexpr int32_t DMS_LOAD_SA_TIMEOUT_MS = 10000;
constexpr int32_t USER_ID = 100;
constexpr int32_t PERMS_NUM = 4;
constexpr int32_t FAILED_RETURN = -1;
}

class StatusReceiverImpl : public StatusReceiverHost {
public:
    StatusReceiverImpl();
    ~StatusReceiverImpl() override;
    void OnStatusNotify(const int progress) override;
    void OnFinished(const int32_t resultCode, const std::string &resultMsg) override;

private:
    mutable std::promise<std::string> resultMsgSignal_;
    int iProgress_ = 0;

    DISALLOW_COPY_AND_MOVE(StatusReceiverImpl);
};

StatusReceiverImpl::StatusReceiverImpl()
{
    HILOGI("create status receiver instance");
}

StatusReceiverImpl::~StatusReceiverImpl()
{
    HILOGI("destroy status receiver instance");
}

void StatusReceiverImpl::OnStatusNotify(const int progress)
{
    iProgress_ = progress;
    HILOGI("OnStatusNotify progress:%{public}d", progress);
}

void StatusReceiverImpl::OnFinished(const int32_t resultCode, const std::string &resultMsg)
{
    HILOGI("on finished result is %{public}d, %{public}s", resultCode, resultMsg.c_str());
    resultMsgSignal_.set_value(resultMsg);
}

sptr<IRemoteObject> DistributedSchedUtil::remote_ = nullptr;
std::mutex DistributedSchedUtil::remoteMutex_;
std::condition_variable DistributedSchedUtil::remoteConVar_;

void DistributedSchedUtil::MockPermission()
{
    static const char *PERMS[] = {
        "ohos.permission.ABILITY_BACKGROUND_COMMUNICATION",
        "ohos.permission.ACCESS_SERVICE_DM",
        "ohos.permission.DISTRIBUTED_DATASYNC",
        "ohos.permission.RUNNING_STATE_OBSERVER"
        
    };
    MockProcessAndPermission(DISTSCHED_PROCESS_NAME, PERMS, PERMS_NUM);
}

void DistributedSchedUtil::MockBundlePermission()
{
    static const char *PERMS[] = {
        "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED"
    };
    MockProcessAndPermission("DistributedSchedPermissionTest", PERMS, sizeof(PERMS) / sizeof(PERMS[0]));
}

void DistributedSchedUtil::MockManageMissions()
{
    static const char *perms[] = {
        "ohos.permission.MANAGE_MISSIONS"
    };
    MockProcessAndPermission("DistributedSchedPermissionTest", perms, sizeof(perms) / sizeof(perms[0]));
}

void DistributedSchedUtil::MockProcess(const char* processName)
{
    MockProcessAndPermission(processName);
}

sptr<AppExecFwk::IBundleMgr> DistributedSchedUtil::GetBundleManager()
{
    sptr<ISystemAbilityManager> samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        return nullptr;
    }
    sptr<IRemoteObject> bmsProxy = samgrProxy->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bmsProxy == nullptr) {
        HILOGE("failed to get bms from samgr");
        return nullptr;
    }
    return iface_cast<AppExecFwk::IBundleMgr>(bmsProxy);
}

int32_t DistributedSchedUtil::InstallThirdPartyHap()
{
    auto bms = GetBundleManager();
    if (bms == nullptr) {
        HILOGE("bms is null");
        return FAILED_RETURN;
    }
    auto installer = bms->GetBundleInstaller();
    if (!installer) {
        HILOGE("installer is null");
        return FAILED_RETURN;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USER_ID;
    sptr<StatusReceiverImpl> statusReceiver(new (std::nothrow) StatusReceiverImpl());
    if (!statusReceiver) {
        return FAILED_RETURN;
    }
    bool result = installer->Install(HAP_FILE_PATH, installParam, statusReceiver);
    if (!result) {
        return FAILED_RETURN;
    }
    return 0;
}

void DistributedSchedUtil::MockProcessAndPermission(const char* processName, const char *perms[], int32_t permsNum)
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permsNum,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = processName,
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

bool DistributedSchedUtil::LoadDistributedSchedService()
{
    std::unique_lock<std::mutex> lock(remoteMutex_);
    sptr<DistributedSchedLoadCallback> loadCallback = new DistributedSchedLoadCallback();
    if (loadCallback == nullptr) {
        HILOGE("loadCallback is nullptr");
        return false;
    }
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOGE("get samgr failed");
        return false;
    }
    int32_t ret = samgrProxy->LoadSystemAbility(DISTRIBUTED_SCHED_SA_ID, loadCallback);
    if (ret != ERR_OK) {
        HILOGE("load dms SA failed");
        return false;
    }
    auto waitStatus = remoteConVar_.wait_for(lock, std::chrono::milliseconds(DMS_LOAD_SA_TIMEOUT_MS),
        []() { return remote_ != nullptr; });
    if (!waitStatus) {
        HILOGE("dms SA load timeout");
        return false;
    }
    return true;
}

void DistributedSchedUtil::LoadSystemAbilitySuccessNotify(const sptr<IRemoteObject>& remoteObject)
{
    std::lock_guard<std::mutex> lock(remoteMutex_);
    remote_ = remoteObject;
    remoteConVar_.notify_one();
}

void DistributedSchedUtil::LoadSystemAbilityFailNotify()
{
    std::lock_guard<std::mutex> lock(remoteMutex_);
    remote_ = nullptr;
}

void DistributedSchedLoadCallback::OnLoadSystemAbilitySuccess(
    int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject)
{
    HILOGD("called.");
    DistributedSchedUtil::LoadSystemAbilitySuccessNotify(remoteObject);
}

void DistributedSchedLoadCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    HILOGD("called.");
    DistributedSchedUtil::LoadSystemAbilityFailNotify();
}
}
}
/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "distributed_sched_service.h"

#include <algorithm>
#include <cinttypes>
#include <dlfcn.h>
#include <unistd.h>

#include "ability_manager_client.h"
#include "ability_manager_errors.h"
#include "bool_wrapper.h"
#include "datetime_ex.h"
#include "element_name.h"
#include "file_ex.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "parameters.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#ifdef SUPPORT_DISTRIBUTEDCOMPONENT_TO_MEMMGR
#include "mem_mgr_client.h"
#endif
#ifdef EFFICIENCY_MANAGER_ENABLE
#include "res_type.h"
#include "res_sched_client.h"
#endif

#include "ability_connection_wrapper_stub.h"
#include "adapter/dnetwork_adapter.h"
#include "bundle/bundle_manager_internal.h"
#include "connect_death_recipient.h"
#include "datashare_manager.h"
#include "dfx/distributed_radar.h"
#include "dfx/distributed_sched_dumper.h"
#include "dfx/distributed_ue.h"
#include "dfx/dms_continue_time_dumper.h"
#include "distributed_sched_adapter.h"
#include "distributed_sched_permission.h"
#include "distributed_sched_utils.h"
#include "dms_callback_task.h"
#include "dms_constant.h"
#include "dms_free_install_callback.h"
#include "dms_token_callback.h"
#include "dms_version_manager.h"
#include "dsched_continue_manager.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "parcel_helper.h"
#include "switch_status_dependency.h"
#ifdef SUPPORT_COMMON_EVENT_SERVICE
#include "common_event_listener.h"
#endif
#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
#include "form_mgr_death_recipient.h"
#endif
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
#include "mission/distributed_bm_storage.h"
#include "mission/distributed_mission_info.h"
#include "mission/dms_continue_send_manager.h"
#include "mission/dms_continue_recv_manager.h"
#include "mission/distributed_sched_mission_manager.h"
#include "mission/dsched_sync_e2e.h"
#include "mission/wifi_state_listener.h"
#endif

namespace OHOS {
namespace DistributedSchedule {
using namespace AAFwk;
using namespace AccountSA;
using namespace AppExecFwk;
using namespace Constants;
using namespace DistributedHardware;

namespace {
const std::string TAG = "DistributedSchedService";
const std::string DMS_SRC_NETWORK_ID = "dmsSrcNetworkId";
const int DEFAULT_REQUEST_CODE = -1;
const std::u16string CONNECTION_CALLBACK_INTERFACE_TOKEN = u"ohos.abilityshell.DistributedConnection";
const std::u16string COMPONENT_CHANGE_INTERFACE_TOKEN = u"ohos.rms.DistributedComponent";
const std::u16string ABILITY_MANAGER_SERVICE_TOKEN = u"ohos.aafwk.AbilityManager";
const std::u16string ATOMIC_SERVICE_STATUS_CALLBACK_TOKEN = u"ohos.IAtomicServiceStatusCallback";
const std::string BUNDLE_NAME_KEY = "bundleName";
const std::string VERSION_CODE_KEY = "version";
const std::string PID_KEY = "pid";
const std::string UID_KEY = "uid";
const std::string COMPONENT_TYPE_KEY = "componentType";
const std::string DEVICE_TYPE_KEY = "deviceType";
const std::string CHANGE_TYPE_KEY = "changeType";
const std::string DMS_HIPLAY_ACTION = "ohos.ability.action.deviceSelect";
const std::string DMS_VERSION_ID = "dmsVersion";
const std::string DMS_UID_SPEC_BUNDLE_NAME = "dmsCallerUidBundleName";
const std::string DMS_CONNECT_TOKEN = "connectToken";
const std::string DMS_MISSION_ID = "dmsMissionId";
const std::string SUPPORT_CONTINUE_PAGE_STACK_KEY = "ohos.extra.param.key.supportContinuePageStack";
const std::string SUPPORT_CONTINUE_SOURCE_EXIT_KEY = "ohos.extra.param.key.supportContinueSourceExit";
const std::string SUPPORT_CONTINUE_MODULE_NAME_UPDATE_KEY = "ohos.extra.param.key.supportContinueModuleNameUpdate";
const std::string DSCHED_EVENT_KEY = "IDSchedEventListener";
const std::string DMSDURATION_SAVETIME = "ohos.dschedule.SaveDataTime";
const std::string DMS_CONTINUE_SESSION_ID = "ohos.dms.continueSessionId";
const std::string DMS_PERSISTENT_ID = "ohos.dms.persistentId";
const std::string PKG_NAME = "DBinderBus_Dms_" + std::to_string(getprocpid());
const std::string BOOT_COMPLETED_EVENT = "usual.event.BOOT_COMPLETED";
constexpr int32_t DEFAULT_DMS_MISSION_ID = -1;
constexpr int32_t DEFAULT_DMS_CONNECT_TOKEN = -1;
constexpr int32_t BIND_CONNECT_RETRY_TIMES = 3;
constexpr int32_t BIND_CONNECT_TIMEOUT = 500; // 500ms
constexpr int32_t MAX_DISTRIBUTED_CONNECT_NUM = 600;
constexpr int32_t INVALID_CALLER_UID = -1;
constexpr int32_t IASS_CALLBACK_ON_REMOTE_FREE_INSTALL_DONE = 1;
constexpr int32_t DISTRIBUTED_COMPONENT_ADD = 1;
constexpr int32_t DISTRIBUTED_COMPONENT_REMOVE = 2;
constexpr int32_t START_PERMISSION = 0;
constexpr int32_t CALL_PERMISSION = 1;
constexpr int32_t SEND_RESULT_PERMISSION = 2;
constexpr int64_t CONTINUATION_TIMEOUT = 20000; // 20s
// BundleDistributedManager set timeout to 3s, so we set 1s longer
constexpr int64_t CHECK_REMOTE_INSTALL_ABILITY = 40000;
constexpr int32_t MAX_TOKEN_NUM = 100000000;
constexpr uint32_t MAX_MODULENAME_LEN = 2048;
constexpr int32_t DMSDURATION_BEGINTIME = 0;
constexpr int32_t DMSDURATION_ENDTIME = 1;
constexpr int32_t DMSDURATION_TOTALTIME = 2;
constexpr int32_t DMSDURATION_DSTTOSRCRPCTIME = 3;
constexpr int32_t DMSDURATION_SRCTODSTRPCTIME = 5;
constexpr int32_t DMSDURATION_STARTABILITY = 6;
constexpr int32_t HID_HAP = 10000; /* first hap user */
constexpr int32_t WINDOW_MANAGER_SERVICE_ID = 4606;
static const std::string CONTINUE_SWITCH_STATUS_KEY = "Continue_Switch_Status";
}

IMPLEMENT_SINGLE_INSTANCE(DistributedSchedService);
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(&DistributedSchedService::GetInstance());

DistributedSchedService::DistributedSchedService() : SystemAbility(DISTRIBUTED_SCHED_SA_ID, true)
{
}

void DistributedSchedService::OnStart(const SystemAbilityOnDemandReason &startReason)
{
    HILOGI("OnStart reason %{public}s, reasonId_:%{public}d", startReason.GetName().c_str(), startReason.GetId());
#ifdef DMS_SERVICE_DISABLE
    HILOGI("DMS service disabled, exiting.");
    _exit(0);
#endif
    HILOGI("Dms service OnStart enter.");
    if (!Init()) {
        HILOGE("failed to init DistributedSchedService");
        return;
    }
    FuncContinuationCallback continuationCallback = [this] (int32_t missionId) {
        HILOGW("continuationCallback timeout.");
        NotifyContinuationCallbackResult(missionId, CONTINUE_ABILITY_TIMEOUT_ERR);
    };

    DmsCallbackTaskInitCallbackFunc freeCallback = [this] (int64_t taskId) {
        HILOGW("DmsCallbackTaskInitCallbackFunc timeout, taskId:%{public}" PRId64 ".", taskId);
        NotifyCompleteFreeInstallFromRemote(taskId, AAFwk::FREE_INSTALL_TIMEOUT);
    };
    dschedContinuation_ = std::make_shared<DSchedContinuation>();
    collaborateCbMgr_ = std::make_shared<DSchedCollaborationCallbackMgr>();
    dmsCallbackTask_ = std::make_shared<DmsCallbackTask>();
    dschedContinuation_->Init(continuationCallback);
    collaborateCbMgr_->Init();
    dmsCallbackTask_->Init(freeCallback);

#ifdef DMSFWK_INTERACTIVE_ADAPTER
    HILOGI("Get dms interactive adapter proxy enter.");
    int32_t ret = GetDmsInteractiveAdapterProxy();
    if (ret != ERR_OK) {
        HILOGE("Get remote dms interactive adapter proxy fail, ret %{public}d.", ret);
    }
#endif

    HILOGI("OnStart dms service success.");
    Publish(this);
    HandleBootStart(startReason);
}

void DistributedSchedService::OnStop(const SystemAbilityOnDemandReason &stopReason)
{
    HILOGI("OnStart reason %{public}s, reasonId_:%{public}d", stopReason.GetName().c_str(), stopReason.GetId());
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    DMSContinueSendMgr::GetInstance().UnInit();
    DMSContinueRecvMgr::GetInstance().UnInit();
    RemoveSystemAbilityListener(WINDOW_MANAGER_SERVICE_ID);
    DistributedSchedAdapter::GetInstance().UnRegisterMissionListener(missionFocusedListener_);
#endif

#ifdef DMSFWK_INTERACTIVE_ADAPTER
    dlclose(dllHandle_);
    dllHandle_ = nullptr;
#endif
    HILOGI("OnStop dms service end");
}

void DistributedSchedService::OnActive(const SystemAbilityOnDemandReason &activeReason)
{
    HILOGI("OnStart reason %{public}s, reasonId_:%{public}d", activeReason.GetName().c_str(), activeReason.GetId());
    OnStart(activeReason);
}

void DistributedSchedService::HandleBootStart(const SystemAbilityOnDemandReason &startReason)
{
    std::vector<DistributedHardware::DmDeviceInfo> dmDeviceInfoList;
    int32_t errCode = DeviceManager::GetInstance().GetTrustedDeviceList(PKG_NAME, "", dmDeviceInfoList);
    if (errCode != ERR_OK) {
        HILOGE("Get device manager trusted device list fail, errCode %{public}d", errCode);
    }
    if (startReason.GetName() == BOOT_COMPLETED_EVENT && dmDeviceInfoList.empty()) {
        HILOGI("UnloadSystemAbility dms");
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            HILOGE("get samgr failed");
            return;
        }
        int32_t ret = samgrProxy->UnloadSystemAbility(DISTRIBUTED_SCHED_SA_ID);
        if (ret != ERR_OK) {
            HILOGE("remove system ability failed");
            return;
        }
        HILOGI("UnloadSystemAbility dms ok");
    }
}

int32_t DistributedSchedService::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    std::vector<std::string> argsInStr8;
    for (const auto& arg : args) {
        argsInStr8.emplace_back(Str16ToStr8(arg));
    }
    std::string result;
    DistributedSchedDumper::Dump(argsInStr8, result);

    if (!SaveStringToFd(fd, result)) {
        HILOGE("save to fd failed");
        return DMS_WRITE_FILE_FAILED_ERR;
    }
    return ERR_OK;
}

void DistributedSchedService::DeviceOnlineNotify(const std::string& networkId)
{
    DistributedSchedAdapter::GetInstance().DeviceOnline(networkId);
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    DistributedSchedMissionManager::GetInstance().DeviceOnlineNotify(networkId);
    if (!DMSContinueRecvMgr::GetInstance().CheckRegSoftbusListener() &&
        DistributedHardware::DeviceManager::GetInstance().IsSameAccount(networkId)) {
        HILOGI("DMSContinueRecvMgr need init");
        DMSContinueRecvMgr::GetInstance().Init();
    }
#endif
}

void DistributedSchedService::DeviceOfflineNotify(const std::string& networkId)
{
    DistributedSchedAdapter::GetInstance().DeviceOffline(networkId);
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    DMSContinueRecvMgr::GetInstance().NotifyDeviceOffline(networkId);
    DistributedSchedMissionManager::GetInstance().DeviceOfflineNotify(networkId);
#endif
}

bool DistributedSchedService::Init()
{
    HILOGD("ready to init.");
    InitDeviceCfg();
    DmsContinueTime::GetInstance().Init();
    DnetworkAdapter::GetInstance()->Init();
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().Init()) {
        HILOGW("DtbschedmgrDeviceInfoStorage init failed.");
    }
    InitDataShareManager();

#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    if (!AddSystemAbilityListener(WINDOW_MANAGER_SERVICE_ID)) {
        HILOGE("Add System Ability Listener failed!");
    }
    DistributedSchedMissionManager::GetInstance().Init();
    DistributedSchedMissionManager::GetInstance().InitDataStorage();
    InitCommonEventListener();
    InitWifiStateListener();
    DMSContinueSendMgr::GetInstance().Init();
    DMSContinueRecvMgr::GetInstance().Init();
#endif
    DistributedSchedAdapter::GetInstance().Init();
    if (SwitchStatusDependency::GetInstance().IsContinueSwitchOn()) {
        DSchedContinueManager::GetInstance().Init();
    }
    connectDeathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new ConnectDeathRecipient());
    callerDeathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new CallerDeathRecipient());
    callerDeathRecipientForLocalDevice_ = sptr<IRemoteObject::DeathRecipient>(
        new CallerDeathRecipient(IDistributedSched::CALLER));
    if (componentChangeHandler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create("DmsComponentChange");
        componentChangeHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    return true;
}

void DistributedSchedService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    HILOGI("OnAddSystemAbility systemAbilityId:%{public}d added!", systemAbilityId);
    missionFocusedListener_ = sptr<DistributedMissionFocusedListener>(new DistributedMissionFocusedListener());
    int32_t ret = DistributedSchedAdapter::GetInstance().RegisterMissionListener(missionFocusedListener_);
    if (ret != ERR_OK) {
        HILOGE("get RegisterMissionListener failed, ret: %{public}d", ret);
    }
}

void DistributedSchedService::InitDataShareManager()
{
    DataShareManager::ObserverCallback observerCallback = [this]() {
        bool IsContinueSwitchOn = SwitchStatusDependency::GetInstance().IsContinueSwitchOn();
        int32_t missionId = GetCurrentMissionId();
        if (missionId <= 0) {
            HILOGW("GetCurrentMissionId failed, init end. ret: %{public}d", missionId);
            return;
        }
        DmsUE::GetInstance().ChangedSwitchState(IsContinueSwitchOn, ERR_OK);
        if (IsContinueSwitchOn) {
            DMSContinueSendMgr::GetInstance().NotifyMissionFocused(missionId, FocusedReason::INIT);
            DSchedContinueManager::GetInstance().Init();
        } else {
            DMSContinueSendMgr::GetInstance().NotifyMissionUnfocused(missionId, UnfocusedReason::NORMAL);
            DMSContinueRecvMgr::GetInstance().OnContinueSwitchOff();
            DSchedContinueManager::GetInstance().UnInit();
        };
    };
    dataShareManager_.RegisterObserver(CONTINUE_SWITCH_STATUS_KEY, observerCallback);
    DmsUE::GetInstance().OriginalSwitchState(SwitchStatusDependency::GetInstance().IsContinueSwitchOn(), ERR_OK);
    HILOGI("Init data share manager, register observer end.");
}

void DistributedSchedService::InitCommonEventListener()
{
    HILOGI("InitCommonEventListener called");
#ifdef SUPPORT_COMMON_EVENT_SERVICE
    DmsBmStorage::GetInstance();
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto applyMonitor = std::make_shared<CommonEventListener>(subscribeInfo);
    EventFwk::CommonEventManager::SubscribeCommonEvent(applyMonitor);
    DmsBmStorage::GetInstance()->UpdateDistributedData();
    if (DmsKvSyncE2E::GetInstance()->CheckDeviceCfg()) {
        DmsKvSyncE2E::GetInstance()->PushAndPullData();
    }
#endif
}

void DistributedSchedService::InitWifiStateListener()
{
    HILOGI("InitWifiStateListener called");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_POWER_STATE);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto wifiStateListener = std::make_shared<WifiStateListener>(subscribeInfo);
    wifiStateListener->InitWifiState();
    bool ret = EventFwk::CommonEventManager::SubscribeCommonEvent(wifiStateListener);
    if (!ret) {
        HILOGE("SubscribeCommonEvent wifiStateListener failed!");
    }
}

void DistributedSchedService::InitDeviceCfg()
{
    HILOGI("called");
    DmsKvSyncE2E::GetInstance()->SetDeviceCfg();
}

void DistributedSchedService::DurationStart(const std::string srcDeviceId, const std::string dstDeviceId)
{
    DmsContinueTime::GetInstance().Init();
    std::string strBeginTime = DmsContinueTime::GetInstance().GetCurrentTime();
    DmsContinueTime::GetInstance().SetDurationStrTime(DMSDURATION_BEGINTIME, strBeginTime);
    DmsContinueTime::GetInstance().SetNetWorkId(srcDeviceId, dstDeviceId);
}

#ifdef DMSFWK_INTERACTIVE_ADAPTER
bool DistributedSchedService::CheckRemoteOsType(const std::string& netwokId)
{
    auto devInfo = DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceInfoById(netwokId);
    if (devInfo == nullptr) {
        HILOGE("GetDeviceInfoById failed, netwokId: %{public}s.", GetAnonymStr(netwokId).c_str());
        return false;
    }

    HILOGI("Remote device OsType %{public}d, netwokId: %{public}s.", devInfo->GetDeviceOSType(),
        GetAnonymStr(netwokId).c_str());
    return (devInfo->GetDeviceOSType() == Constants::HO_OS_TYPE_EX);
}

int32_t DistributedSchedService::GetDmsInteractiveAdapterProxy()
{
    HILOGI("Get remote dms interactive adapter proxy.");
    std::lock_guard<std::mutex> autoLock(dmsAdapetrLock_);
#if (defined(__aarch64__) || defined(__x86_64__))
    char resolvedPath[100] = "/system/lib64/libdms_interactive_adapter.z.so";
#else
    char resolvedPath[100] = "/system/lib/libdms_interactive_adapter.z.so";
#endif
    int32_t (*GetDmsInteractiveAdapter)(const sptr<IRemoteObject> &callerToken,
        IDmsInteractiveAdapter &dmsAdpHandle) = nullptr;

    dllHandle_ = dlopen(resolvedPath, RTLD_LAZY);
    if (dllHandle_ == nullptr) {
        HILOGE("Open dms interactive adapter shared object fail, resolvedPath [%{public}s].", resolvedPath);
        return NOT_FIND_SERVICE_REGISTRY;
    }

    int32_t ret = ERR_OK;
    do {
        GetDmsInteractiveAdapter = reinterpret_cast<int32_t (*)(const sptr<IRemoteObject> &callerToken,
            IDmsInteractiveAdapter &dmsAdpHandle)>(dlsym(dllHandle_, "GetDmsInteractiveAdapter"));
        if (GetDmsInteractiveAdapter == nullptr) {
            HILOGE("Link the GetDmsInteractiveAdapter symbol in dms interactive adapter fail.");
            ret = NOT_FIND_SERVICE_REGISTRY;
            break;
        }

        int32_t ret = GetDmsInteractiveAdapter(this, dmsAdapetr_);
        if (ret != ERR_OK) {
            HILOGE("Init remote dms interactive adapter proxy fail, ret %{public}d.", ret);
            ret = INVALID_PARAMETERS_ERR;
            break;
        }
        HILOGI("Init remote dms interactive adapter proxy success.");
        ret = ERR_OK;
    } while (false);

    if (ret != ERR_OK) {
        HILOGE("Get remote dms interactive adapter proxy fail, dlclose handle.");
        dlclose(dllHandle_);
        dllHandle_ = nullptr;
    }
    return ret;
}

int32_t DistributedSchedService::StartRemoteAbilityAdapter(const OHOS::AAFwk::Want& want,
    int32_t callerUid, int32_t requestCode, uint32_t accessToken)
{
    std::lock_guard<std::mutex> autoLock(dmsAdapetrLock_);
    if (dmsAdapetr_.StartRemoteAbilityAdapter == nullptr) {
        HILOGE("Dms interactive start remote ability adapter handle is null.");
        return INVALID_PARAMETERS_ERR;
    }

    int32_t ret = dmsAdapetr_.StartRemoteAbilityAdapter(want, callerUid, requestCode, accessToken);
    if (ret != ERR_OK) {
        HILOGE("Dms interactive adapter start remote ability adapter fail, ret %{public}d.", ret);
    }
    return ret;
}

int32_t DistributedSchedService::ConnectRemoteAbilityAdapter(const OHOS::AAFwk::Want& want,
    const sptr<IRemoteObject>& connect, int32_t callerUid, int32_t callerPid, uint32_t accessToken)
{
    std::lock_guard<std::mutex> autoLock(dmsAdapetrLock_);
    if (dmsAdapetr_.ConnectRemoteAbilityAdapter == nullptr) {
        HILOGE("Dms interactive connect remote ability adapter handle is null.");
        return INVALID_PARAMETERS_ERR;
    }

    int32_t ret = dmsAdapetr_.ConnectRemoteAbilityAdapter(want, connect, callerUid, callerPid, accessToken);
    if (ret != ERR_OK) {
        HILOGE("Dms interactive adapter connect remote ability adapter fail, ret %{public}d.", ret);
    }
    return ret;
}

int32_t DistributedSchedService::DisconnectRemoteAbilityAdapter(const sptr<IRemoteObject>& connect, int32_t callerUid,
    uint32_t accessToken)
{
    std::lock_guard<std::mutex> autoLock(dmsAdapetrLock_);
    if (dmsAdapetr_.DisconnectRemoteAbilityAdapter == nullptr) {
        HILOGE("Dms interactive disconnect remote ability adapter handle is null.");
        return INVALID_PARAMETERS_ERR;
    }

    int32_t ret = dmsAdapetr_.DisconnectRemoteAbilityAdapter(connect, callerUid, accessToken);
    if (ret != ERR_OK) {
        HILOGE("Dms interactive adapter disconnect remote ability adapter fail, ret %{public}d.", ret);
    }
    return ret;
}

int32_t DistributedSchedService::StartAbilityFromRemoteAdapter(MessageParcel& data, MessageParcel& reply)
{
    std::lock_guard<std::mutex> autoLock(dmsAdapetrLock_);
    if (dmsAdapetr_.StartAbilityFromRemoteAdapter == nullptr) {
        HILOGE("Dms interactive start ability from remote adapter handle is null.");
        return INVALID_PARAMETERS_ERR;
    }

    int32_t ret = dmsAdapetr_.StartAbilityFromRemoteAdapter(data, reply);
    if (ret != ERR_OK) {
        HILOGE("Dms interactive adapter start ability from remote adapter fail, ret %{public}d.", ret);
    }
    return ret;
}

int32_t DistributedSchedService::StopAbilityFromRemoteAdapter(MessageParcel& data, MessageParcel& reply)
{
    std::lock_guard<std::mutex> autoLock(dmsAdapetrLock_);
    if (dmsAdapetr_.StopAbilityFromRemoteAdapter == nullptr) {
        HILOGE("Dms interactive stop ability from remote adapter handle is null.");
        return INVALID_PARAMETERS_ERR;
    }

    int32_t ret = dmsAdapetr_.StopAbilityFromRemoteAdapter(data, reply);
    if (ret != ERR_OK) {
        HILOGE("Dms interactive adapter stop ability from remote adapter fail, ret %{public}d.", ret);
    }
    return ret;
}

int32_t DistributedSchedService::ConnectAbilityFromRemoteAdapter(MessageParcel& data, MessageParcel& reply)
{
    std::lock_guard<std::mutex> autoLock(dmsAdapetrLock_);
    if (dmsAdapetr_.ConnectAbilityFromRemoteAdapter == nullptr) {
        HILOGE("Dms interactive connect ability from remote adapter handle is null.");
        return INVALID_PARAMETERS_ERR;
    }

    int32_t ret = dmsAdapetr_.ConnectAbilityFromRemoteAdapter(data, reply);
    if (ret != ERR_OK) {
        HILOGE("Dms interactive adapter connect ability from remote adapter fail, ret %{public}d.", ret);
    }
    return ret;
}

int32_t DistributedSchedService::DisconnectAbilityFromRemoteAdapter(MessageParcel& data, MessageParcel& reply)
{
    std::lock_guard<std::mutex> autoLock(dmsAdapetrLock_);
    if (dmsAdapetr_.DisconnectAbilityFromRemoteAdapter == nullptr) {
        HILOGE("Dms interactive disconnect ability from remote adapter handle is null.");
        return INVALID_PARAMETERS_ERR;
    }

    int32_t ret = dmsAdapetr_.DisconnectAbilityFromRemoteAdapter(data, reply);
    if (ret != ERR_OK) {
        HILOGE("Dms interactive adapter disconnect ability from remote adapter fail, ret %{public}d.", ret);
    }
    return ret;
}

int32_t DistributedSchedService::NotifyAbilityLifecycleChangedFromRemoteAdapter(MessageParcel& data,
    MessageParcel& reply)
{
    std::lock_guard<std::mutex> autoLock(dmsAdapetrLock_);
    if (dmsAdapetr_.NotifyAbilityLifecycleChangedFromRemoteAdapter == nullptr) {
        HILOGE("Dms interactive disconnect ability from remote adapter handle is null.");
        return INVALID_PARAMETERS_ERR;
    }

    int32_t ret = dmsAdapetr_.NotifyAbilityLifecycleChangedFromRemoteAdapter(data, reply);
    if (ret != ERR_OK) {
        HILOGE("Dms interactive adapter disconnect ability from remote adapter fail, ret %{public}d.", ret);
    }
    return ret;
}

void DistributedSchedService::OnDeviceOnlineEx(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    std::lock_guard<std::mutex> autoLock(dmsAdapetrLock_);
    if (dmsAdapetr_.OnDeviceOnlineEx == nullptr) {
        HILOGE("Dms interactive on device online extention handle is null.");
        return;
    }

    dmsAdapetr_.OnDeviceOnlineEx(deviceInfo);
}

void DistributedSchedService::OnDeviceOfflineEx(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    std::lock_guard<std::mutex> autoLock(dmsAdapetrLock_);
    if (dmsAdapetr_.OnDeviceOfflineEx == nullptr) {
        HILOGE("Dms interactive on device online extention handle is null.");
        return;
    }

    dmsAdapetr_.OnDeviceOfflineEx(deviceInfo);
}

void DistributedSchedService::OnDeviceInfoChangedEx(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo)
{
    std::lock_guard<std::mutex> autoLock(dmsAdapetrLock_);
    if (dmsAdapetr_.OnDeviceInfoChangedEx == nullptr) {
        HILOGE("Dms interactive on device online extention handle is null.");
        return;
    }

    dmsAdapetr_.OnDeviceInfoChangedEx(deviceInfo);
}
#endif // DMSFWK_INTERACTIVE_ADAPTER

int32_t DistributedSchedService::GetCallerInfo(const std::string &localDeviceId, int32_t callerUid,
    uint32_t accessToken, CallerInfo &callerInfo)
{
    callerInfo.sourceDeviceId = localDeviceId;
    callerInfo.uid = callerUid;
    callerInfo.accessToken = accessToken;
    if (!BundleManagerInternal::GetCallerAppIdFromBms(callerInfo.uid, callerInfo.callerAppId)) {
        HILOGE("GetCallerAppIdFromBms failed");
        return INVALID_PARAMETERS_ERR;
    }
    if (!BundleManagerInternal::GetBundleNameListFromBms(callerInfo.uid, callerInfo.bundleNames)) {
        HILOGE("GetBundleNameListFromBms failed");
        return INVALID_PARAMETERS_ERR;
    }
    callerInfo.extraInfoJson[DMS_VERSION_ID] = DMS_VERSION;
    return ERR_OK;
}

int32_t DistributedSchedService::StartRemoteAbility(const OHOS::AAFwk::Want& want,
    int32_t callerUid, int32_t requestCode, uint32_t accessToken)
{
    std::string localDeviceId;
    std::string deviceId = want.GetElement().GetDeviceID();
    if (!GetLocalDeviceId(localDeviceId) || !CheckDeviceId(localDeviceId, deviceId)) {
        HILOGE("check deviceId failed");
        return INVALID_PARAMETERS_ERR;
    }
#ifdef DMSFWK_INTERACTIVE_ADAPTER
    if (CheckRemoteOsType(deviceId)) {
        return StartRemoteAbilityAdapter(want, callerUid, requestCode, accessToken);
    }
#endif // DMSFWK_INTERACTIVE_ADAPTER

    sptr<IDistributedSched> remoteDms = GetRemoteDms(deviceId);
    if (remoteDms == nullptr) {
        HILOGE("get remoteDms failed");
        return INVALID_PARAMETERS_ERR;
    }

    CallerInfo callerInfo;
    int32_t ret = GetCallerInfo(localDeviceId, callerUid, accessToken, callerInfo);
    if (ret != ERR_OK) {
        HILOGE("Get local device caller info fail, ret: %{public}d.", ret);
        return ret;
    }
    AccountInfo accountInfo;
    ret = DistributedSchedPermission::GetInstance().GetAccountInfo(deviceId, callerInfo, accountInfo);
    if (ret != ERR_OK) {
        HILOGE("GetAccountInfo fail, ret: %{public}d.", ret);
        return ret;
    }
    AAFwk::Want* newWant = const_cast<Want*>(&want);
    newWant->SetParam(DMS_SRC_NETWORK_ID, localDeviceId);
    AppExecFwk::AbilityInfo abilityInfo;

    HILOGI("[PerformanceTest] StartRemoteAbility transact begin");
    if (!DmsContinueTime::GetInstance().GetPull()) {
        int64_t begin = GetTickCount();
        DmsContinueTime::GetInstance().SetDurationBegin(DMSDURATION_SRCTODSTRPCTIME, begin);
    }
    int32_t result = remoteDms->StartAbilityFromRemote(*newWant, abilityInfo, requestCode, callerInfo, accountInfo);
    if (!DmsContinueTime::GetInstance().GetPull()) {
        int64_t end = GetTickCount();
        DmsContinueTime::GetInstance().SetDurationBegin(DMSDURATION_STARTABILITY, end);
        DmsContinueTime::GetInstance().SetDurationEnd(DMSDURATION_SRCTODSTRPCTIME, end);
    }
    HILOGI("[PerformanceTest] StartRemoteAbility transact end");
    return result;
}

int32_t DistributedSchedService::StartAbilityFromRemote(const OHOS::AAFwk::Want& want,
    const OHOS::AppExecFwk::AbilityInfo& abilityInfo, int32_t requestCode,
    const CallerInfo& callerInfo, const AccountInfo& accountInfo)
{
    std::string localDeviceId;
    std::string timeInfo;
    std::string deviceId = want.GetElement().GetDeviceID();
    if (!GetLocalDeviceId(localDeviceId) ||
        !CheckDeviceIdFromRemote(localDeviceId, deviceId, callerInfo.sourceDeviceId)) {
        HILOGE("check deviceId failed");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    if (DmsContinueTime::GetInstance().GetPull()) {
        timeInfo = want.GetStringParam(DMSDURATION_SAVETIME);
        DmsContinueTime::GetInstance().ReadDurationInfo(timeInfo.c_str());
        DmsContinueTime::GetInstance().SetSrcBundleName(want.GetElement().GetBundleName());
        DmsContinueTime::GetInstance().SetSrcAbilityName(want.GetElement().GetAbilityName());
    }
    int32_t result = CheckTargetPermission(want, callerInfo, accountInfo, START_PERMISSION, true);
    if (result != ERR_OK) {
        HILOGE("CheckTargetPermission failed!!");
        return result;
    }

    return StartAbility(want, requestCode);
}

int32_t DistributedSchedService::SendResultFromRemote(OHOS::AAFwk::Want& want, int32_t requestCode,
    const CallerInfo& callerInfo, const AccountInfo& accountInfo, int32_t resultCode)
{
    std::string localDeviceId;
    std::string deviceId = want.GetStringParam(DMS_SRC_NETWORK_ID);
    want.RemoveParam(DMS_SRC_NETWORK_ID);
    if (!GetLocalDeviceId(localDeviceId) ||
        !CheckDeviceIdFromRemote(localDeviceId, deviceId, callerInfo.sourceDeviceId)) {
        HILOGE("check deviceId failed");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    if (want.GetElement().GetBundleName().empty() && want.GetElement().GetAbilityName().empty()) {
        HILOGW("Remote died abnormal");
        int32_t missionId = want.GetIntParam(DMS_MISSION_ID, DEFAULT_DMS_MISSION_ID);
        ErrCode ret = AAFwk::AbilityManagerClient::GetInstance()->Connect();
        if (ret != ERR_OK) {
            HILOGE("connect ability server failed %{public}d", ret);
            return ret;
        }
        MissionInfo missionInfo;
        ret = AAFwk::AbilityManagerClient::GetInstance()->GetMissionInfo("", missionId, missionInfo);
        if (ret != ERR_OK) {
            HILOGE("SendResult failed %{public}d", ret);
            return ret;
        }
        std::string bundleName = missionInfo.want.GetElement().GetBundleName();
        std::string abilityName = missionInfo.want.GetElement().GetAbilityName();
        HILOGD("bundlename: %{public}s, ability is %{public}s", bundleName.c_str(), abilityName.c_str());
        ElementName element{"", bundleName, abilityName};
        want.SetElement(element);
    }
    int32_t result = CheckTargetPermission(want, callerInfo, accountInfo, SEND_RESULT_PERMISSION, false);
    if (result != ERR_OK) {
        HILOGE("CheckTargetPermission failed!!");
        return result;
    }
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->Connect();
    if (err != ERR_OK) {
        HILOGE("connect ability server failed %{public}d", err);
        return err;
    }
    err = AAFwk::AbilityManagerClient::GetInstance()->SendResultToAbility(requestCode, resultCode, want);
    if (err != ERR_OK) {
        HILOGE("SendResult failed %{public}d", err);
    }
    return err;
}

void DistributedSchedService::RemoveContinuationTimeout(int32_t missionId)
{
    if (dschedContinuation_ == nullptr) {
        HILOGE("continuation object null!");
        return;
    }
    dschedContinuation_->RemoveTimeOut(missionId);
}

void DistributedSchedService::SetContinuationTimeout(int32_t missionId, int32_t timeout)
{
    if (dschedContinuation_ == nullptr) {
        HILOGE("continuation object null!");
        return;
    }
    dschedContinuation_->SetTimeOut(missionId, timeout);
}

std::string DistributedSchedService::GetContinuaitonDevice(int32_t missionId)
{
    if (dschedContinuation_ == nullptr) {
        HILOGE("continuation object null!");
        return "";
    }
    return dschedContinuation_->GetTargetDevice(missionId);
}

int32_t DistributedSchedService::ContinueLocalMissionDealFreeInstall(OHOS::AAFwk::Want& want, int32_t missionId,
    const std::string& dstDeviceId, const sptr<IRemoteObject>& callback)
{
    bool isFreeInstall = want.GetBoolParam("isFreeInstall", false);
    if (!isFreeInstall) {
        HILOGE("remote not installed but support freeInstall, try again with freeInstall flag");
        return CONTINUE_REMOTE_UNINSTALLED_SUPPORT_FREEINSTALL;
    }

    if (dschedContinuation_ == nullptr) {
        HILOGE("continuation object null!");
        return INVALID_PARAMETERS_ERR;
    }
    dschedContinuation_->PushCallback(missionId, callback, dstDeviceId, true);
    SetContinuationTimeout(missionId, CHECK_REMOTE_INSTALL_ABILITY);

    want.SetDeviceId(dstDeviceId);
    if (!BundleManagerInternal::CheckIfRemoteCanInstall(want, missionId)) {
        HILOGE("call CheckIfRemoteCanInstall failed");
        RemoveContinuationTimeout(missionId);
        dschedContinuation_->PopCallback(missionId);
        return INVALID_PARAMETERS_ERR;
    }
    return ERR_OK;
}

int32_t DistributedSchedService::ContinueLocalMission(const std::string& dstDeviceId, int32_t missionId,
    const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams)
{
    bool IsContinueSwitchOn = SwitchStatusDependency::GetInstance().IsContinueSwitchOn();
    if (!IsContinueSwitchOn) {
        HILOGE("ContinueSwitch status is off");
        return DMS_PERMISSION_DENIED;
    }
    if (dschedContinuation_ == nullptr) {
        HILOGE("continuation object null!");
        return INVALID_PARAMETERS_ERR;
    }
    if (dschedContinuation_->IsInContinuationProgress(missionId)) {
        HILOGE("ContinueLocalMission already in progress!");
        return CONTINUE_ALREADY_IN_PROGRESS;
    }
    DmsVersion thresholdDmsVersion = {3, 2, 0};
    if (DmsVersionManager::IsRemoteDmsVersionLower(dstDeviceId, thresholdDmsVersion)) {
        HILOGI("remote dms is low version");
        return ContinueAbilityWithTimeout(dstDeviceId, missionId, callback);
    }

    MissionInfo missionInfo;
    int32_t result = AbilityManagerClient::GetInstance()->GetMissionInfo("", missionId, missionInfo);
    if (result != ERR_OK) {
        HILOGE("get missionInfo failed");
        return NO_MISSION_INFO_FOR_MISSION_ID;
    }
    if (missionInfo.continueState != AAFwk::ContinueState::CONTINUESTATE_ACTIVE) {
        HILOGE("Mission continue state set to INACTIVE. Can't continue. Mission id: %{public}d", missionId);
        return INVALID_PARAMETERS_ERR;
    }
    std::string bundleName = missionInfo.want.GetBundle();
    if (!DmsKvSyncE2E::GetInstance()->CheckBundleContinueConfig(bundleName)) {
        HILOGI("App does not allow continue in config file, bundle name %{public}s, missionId: %{public}d",
            bundleName.c_str(), missionId);
        return REMOTE_DEVICE_BIND_ABILITY_ERR;
    }
    missionInfo.want.SetParams(wantParams);
    DistributedBundleInfo remoteBundleInfo;
    result = BundleManagerInternal::CheckRemoteBundleInfoForContinuation(dstDeviceId,
        bundleName, remoteBundleInfo);
    if (result == ERR_OK) {
        return ContinueAbilityWithTimeout(dstDeviceId, missionId, callback, remoteBundleInfo.versionCode);
    }
    if (result == CONTINUE_REMOTE_UNINSTALLED_UNSUPPORT_FREEINSTALL) {
        HILOGE("remote not installed and app not support free install");
        return result;
    }

    return ContinueLocalMissionDealFreeInstall(missionInfo.want, missionId, dstDeviceId, callback);
}

int32_t DistributedSchedService::ContinueAbilityWithTimeout(const std::string& dstDeviceId, int32_t missionId,
    const sptr<IRemoteObject>& callback, uint32_t remoteBundleVersion)
{
    if (dschedContinuation_ == nullptr) {
        HILOGE("continuation object null!");
        return INVALID_PARAMETERS_ERR;
    }
    bool isPushSucceed = dschedContinuation_->PushCallback(missionId, callback, dstDeviceId, false);
    if (!isPushSucceed) {
        HILOGE("Callback already in progress!");
        return CONTINUE_ALREADY_IN_PROGRESS;
    }
    SetContinuationTimeout(missionId, CONTINUATION_TIMEOUT);
    int64_t saveDataBegin = GetTickCount();
    DmsContinueTime::GetInstance().SetSaveDataDurationBegin(saveDataBegin);
    DmsRadar::GetInstance().SaveDataDmsContinue("ContinueAbility", ERR_OK);
    int32_t result = AbilityManagerClient::GetInstance()->ContinueAbility(dstDeviceId, missionId, remoteBundleVersion);
    HILOGI("result: %{public}d!", result);
    if (result == ERR_INVALID_VALUE) {
        return MISSION_FOR_CONTINUING_IS_NOT_ALIVE;
    }
    return result;
}

int32_t DistributedSchedService::ContinueRemoteMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
    int32_t missionId, const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams)
{
    if (!SwitchStatusDependency::GetInstance().IsContinueSwitchOn()) {
        HILOGE("ContinueSwitch status is off");
        return DMS_PERMISSION_DENIED;
    }
    sptr<IDistributedSched> remoteDms = GetRemoteDms(srcDeviceId);
    if (remoteDms == nullptr) {
        HILOGE("get remote dms null!");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    MissionInfo missionInfo;
    int32_t ret = AAFwk::AbilityManagerClient::GetInstance()->GetMissionInfo("", missionId, missionInfo);
    if (ret != ERR_OK) {
        HILOGE("GeGetMissionInfo failed %{public}d", ret);
        return ret;
    }
    std::string bundleName = missionInfo.want.GetElement().GetBundleName();
    std::string abilityName = missionInfo.want.GetElement().GetAbilityName();
    HILOGD("bundlename: %{public}s, ability is %{public}s", bundleName.c_str(), abilityName.c_str());
    DmsUE::GetInstance().TriggerDmsContinue(bundleName, abilityName, srcDeviceId, ERR_OK);

    std::string peerUdid = DtbschedmgrDeviceInfoStorage::GetInstance().GetUdidByNetworkId(srcDeviceId);
    DmsRadar::GetInstance().ClickIconDmsContinue("ContinueMission", ERR_OK, peerUdid, bundleName);

    int32_t result = remoteDms->ContinueMission(srcDeviceId, dstDeviceId, missionId, callback, wantParams);
    HILOGI("ContinueRemoteMission result: %{public}d!", result);
    return result;
}

int32_t DistributedSchedService::ContinueRemoteMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
    const std::string& bundleName, const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams)
{
    HILOGI("ContinueRemoteMission srcDeviceId: %{public}s. dstDeviceId: %{public}s. bundleName: %{public}s.",
        GetAnonymStr(srcDeviceId).c_str(), GetAnonymStr(dstDeviceId).c_str(), bundleName.c_str());
    if (DmsContinueTime::GetInstance().GetPull()) {
        int64_t begin = GetTickCount();
        DmsContinueTime::GetInstance().SetDurationBegin(DMSDURATION_DSTTOSRCRPCTIME, begin);
        DmsContinueTime::GetInstance().SetDurationBegin(DMSDURATION_TOTALTIME, begin);
    }

    sptr<IDistributedSched> remoteDms = GetRemoteDms(srcDeviceId);
    if (remoteDms == nullptr) {
        HILOGE("get remote dms null!");
        if (dschedContinuation_ == nullptr) {
            HILOGE("continuation object null!");
            return INVALID_PARAMETERS_ERR;
        }
        int32_t dSchedEventresult = dschedContinuation_->NotifyDSchedEventResult(INVALID_REMOTE_PARAMETERS_ERR);
        HILOGD("NotifyDSchedEventResult result:%{public}d", dSchedEventresult);
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    int32_t result = remoteDms->ContinueMission(srcDeviceId, dstDeviceId, bundleName, callback, wantParams);
    HILOGI("ContinueRemoteMission result: %{public}d!", result);
    if (DmsContinueTime::GetInstance().GetPull()) {
        int64_t end = GetTickCount();
        DmsContinueTime::GetInstance().SetDurationEnd(DMSDURATION_DSTTOSRCRPCTIME, end);
    }
    if (result != ERR_OK) {
        if (dschedContinuation_ == nullptr) {
            HILOGE("continuation object null!");
            return INVALID_PARAMETERS_ERR;
        }
        int32_t dSchedEventresult = dschedContinuation_->NotifyDSchedEventResult(result);
        HILOGD("NotifyDSchedEventResult result:%{public}d", dSchedEventresult);
    }
    return result;
}

int32_t DistributedSchedService::ContinueMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
    int32_t missionId, const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams)
{
    HILOGI("ContinueMission called");
    if (srcDeviceId.empty() || dstDeviceId.empty() || callback == nullptr) {
        HILOGE("srcDeviceId or dstDeviceId or callback is null!");
        return INVALID_PARAMETERS_ERR;
    }
    std::string localDevId;
    if (!GetLocalDeviceId(localDevId)) {
        HILOGE("get local deviceId failed!");
        return INVALID_PARAMETERS_ERR;
    }
    DurationStart(srcDeviceId, dstDeviceId);

    if (srcDeviceId == localDevId) {
        if (DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceInfoById(dstDeviceId) == nullptr) {
            HILOGE("GetDeviceInfoById failed, dstDeviceId: %{public}s.", GetAnonymStr(dstDeviceId).c_str());
            return INVALID_REMOTE_PARAMETERS_ERR;
        }
        return ContinueLocalMission(dstDeviceId, missionId, callback, wantParams);
    } else if (dstDeviceId == localDevId) {
        DmsContinueTime::GetInstance().SetPull(true);
        if (DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceInfoById(srcDeviceId) == nullptr) {
            HILOGE("GetDeviceInfoById failed, srcDeviceId: %{public}s.", GetAnonymStr(srcDeviceId).c_str());
            return INVALID_REMOTE_PARAMETERS_ERR;
        }
        return ContinueRemoteMission(srcDeviceId, dstDeviceId, missionId, callback, wantParams);
    } else {
        HILOGE("source or target device must be local!");
        return OPERATION_DEVICE_NOT_INITIATOR_OR_TARGET;
    }
}

int32_t DistributedSchedService::ProcessContinueLocalMission(const std::string& srcDeviceId,
    const std::string& dstDeviceId, const std::string& bundleName, const sptr<IRemoteObject>& callback,
    const OHOS::AAFwk::WantParams& wantParams)
{
    HILOGI("ProcessContinueLocalMission called.");
    if (DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceInfoById(dstDeviceId) == nullptr) {
        HILOGE("GetDeviceInfoById failed, dstDeviceId: %{public}s.", GetAnonymStr(dstDeviceId).c_str());
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    int32_t missionId = 1;
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    int32_t ret = DMSContinueSendMgr::GetInstance().GetMissionIdByBundleName(bundleName, missionId);
    if (ret != ERR_OK) {
        HILOGE("get missionId failed");
        return ret;
    }
#endif

    if (dschedContinuation_ == nullptr) {
        HILOGE("continuation object null!");
        return INVALID_PARAMETERS_ERR;
    }
    dschedContinuation_->continueEvent_.srcNetworkId_ = srcDeviceId;
    dschedContinuation_->continueEvent_.dstNetworkId_ = dstDeviceId;
    return ContinueLocalMission(dstDeviceId, missionId, callback, wantParams);
}

int32_t DistributedSchedService::ProcessContinueRemoteMission(const std::string& srcDeviceId,
    const std::string& dstDeviceId, const std::string& bundleName, const sptr<IRemoteObject>& callback,
    const OHOS::AAFwk::WantParams& wantParams)
{
    HILOGI("ProcessContinueRemoteMission start.");
    if (DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceInfoById(srcDeviceId) == nullptr) {
        HILOGE("GetDeviceInfoById failed, srcDeviceId: %{public}s.", GetAnonymStr(srcDeviceId).c_str());
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    if (dschedContinuation_ == nullptr) {
        HILOGE("continuation object null!");
        return INVALID_PARAMETERS_ERR;
    }
    dschedContinuation_->continueEvent_.srcNetworkId_ = dstDeviceId;
    dschedContinuation_->continueEvent_.dstNetworkId_ = srcDeviceId;
    HILOGI("ProcessContinueRemoteMission end.");
    return ContinueRemoteMission(srcDeviceId, dstDeviceId, bundleName, callback, wantParams);
}

int32_t DistributedSchedService::ContinueMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
    const std::string& bundleName, const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams)
{
    HILOGI("ContinueMission srcDeviceId: %{public}s. dstDeviceId: %{public}s. bundleName: %{public}s.",
        GetAnonymStr(srcDeviceId).c_str(), GetAnonymStr(dstDeviceId).c_str(), bundleName.c_str());
    if (srcDeviceId.empty() || dstDeviceId.empty() || callback == nullptr) {
        HILOGE("srcDeviceId or dstDeviceId or callback is null!");
        return INVALID_PARAMETERS_ERR;
    }
    std::string localDevId;
    if (!GetLocalDeviceId(localDevId)) {
        HILOGE("get local deviceId failed!");
        return INVALID_PARAMETERS_ERR;
    }
    DurationStart(srcDeviceId, dstDeviceId);

    if (srcDeviceId == localDevId) {
        return ProcessContinueLocalMission(srcDeviceId, dstDeviceId, bundleName, callback, wantParams);
    } else if (dstDeviceId == localDevId) {
        DmsContinueTime::GetInstance().SetPull(true);
        return ProcessContinueRemoteMission(srcDeviceId, dstDeviceId, bundleName, callback, wantParams);
    } else {
        HILOGE("source or target device must be local!");
        return OPERATION_DEVICE_NOT_INITIATOR_OR_TARGET;
    }
}

int32_t DistributedSchedService::SetWantForContinuation(AAFwk::Want& newWant, int32_t missionId)
{
    std::string devId;
    if (!GetLocalDeviceId(devId)) {
        HILOGE("StartContinuation get local deviceId failed!");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    newWant.SetParam("sessionId", missionId);
    newWant.SetParam("deviceId", devId);
    std::string strInfo = DmsContinueTime::GetInstance().WriteDurationInfo(
        DmsContinueTime::GetInstance().GetSaveDataDuration());
    newWant.SetParam(DMSDURATION_SAVETIME, strInfo);
    BundleInfo localBundleInfo;
    if (BundleManagerInternal::GetLocalBundleInfo(newWant.GetBundle(), localBundleInfo) != ERR_OK) {
        HILOGE("get local bundle info failed");
        return INVALID_PARAMETERS_ERR;
    }
    newWant.SetParam(VERSION_CODE_KEY, static_cast<int32_t>(localBundleInfo.versionCode));

    bool isPageStackContinue = newWant.GetBoolParam(SUPPORT_CONTINUE_PAGE_STACK_KEY, true);
    std::string moduleName = newWant.GetStringParam(SUPPORT_CONTINUE_MODULE_NAME_UPDATE_KEY);
    if (!isPageStackContinue && !moduleName.empty() && moduleName.length() <= MAX_MODULENAME_LEN) {
        HILOGD("set application moduleName = %{private}s!", moduleName.c_str());
        OHOS::AppExecFwk::ElementName element = newWant.GetElement();
        newWant.SetElementName(element.GetDeviceID(), element.GetBundleName(), element.GetAbilityName(), moduleName);
    }
    HILOGD("local version = %{public}u!", localBundleInfo.versionCode);
    return ERR_OK;
}

int32_t DistributedSchedService::DealDSchedEventResult(const OHOS::AAFwk::Want& want, int32_t status)
{
    if (dschedContinuation_ == nullptr) {
        HILOGE("continuation object null!");
        return INVALID_PARAMETERS_ERR;
    }
    DmsContinueTime::GetInstance().SetSrcBundleName(want.GetElement().GetBundleName());
    DmsContinueTime::GetInstance().SetSrcAbilityName(dschedContinuation_->continueEvent_.srcAbilityName_);
    if (status != ERR_OK) {
        HILOGD("want deviceId result:%{public}s", GetAnonymStr(want.GetElement().GetDeviceID()).c_str());
        std::string deviceId = want.GetElement().GetDeviceID();
        sptr<IDistributedSched> remoteDms = GetRemoteDms(deviceId);
        if (remoteDms == nullptr) {
            HILOGE("NotifyCompleteContinuation get remote dms null!");
            return INVALID_REMOTE_PARAMETERS_ERR;
        }
        int dSchedEventresult = remoteDms->NotifyDSchedEventResultFromRemote(DSCHED_EVENT_KEY, status);
        HILOGI("NotifyDSchedEventResultFromRemote result:%{public}d", dSchedEventresult);
    }
    return ERR_OK;
}

bool DistributedSchedService::GetIsFreeInstall(int32_t missionId)
{
    if (dschedContinuation_ == nullptr) {
        return false;
    }
    return dschedContinuation_->IsFreeInstall(missionId);
}

int32_t DistributedSchedService::StartContinuation(const OHOS::AAFwk::Want& want, int32_t missionId,
    int32_t callerUid, int32_t status, uint32_t accessToken)
{
    HILOGD("[PerformanceTest] StartContinuation begin");
    DealDSchedEventResult(want, status);
    if (status != ERR_OK) {
        HILOGE("continuation has been rejected, status: %{public}d", status);
        NotifyContinuationCallbackResult(missionId, status);
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    auto flags = want.GetFlags();
    if ((flags & AAFwk::Want::FLAG_ABILITY_CONTINUATION) == 0) {
        HILOGE("StartContinuation want continuation flags invalid!");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    HILOGD("StartContinuation: devId = %{private}s, bundleName = %{private}s, abilityName = %{private}s",
        GetAnonymStr(want.GetElement().GetDeviceID()).c_str(), want.GetElement().GetBundleName().c_str(),
        want.GetElement().GetAbilityName().c_str());
    if (dschedContinuation_ == nullptr) {
        HILOGE("StartContinuation continuation object null!");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    if (!dschedContinuation_->IsInContinuationProgress(missionId)) {
        dschedContinuation_->SetTimeOut(missionId, CONTINUATION_TIMEOUT);
    }
    AAFwk::Want newWant = want;
    int result = SetWantForContinuation(newWant, missionId);
    if (result != ERR_OK) {
        HILOGE("set new want failed");
        return result;
    }
    bool flag = GetIsFreeInstall(missionId);
    SetCleanMissionFlag(want, missionId);
    if (flag) {
        result = StartRemoteFreeInstall(newWant, callerUid, DEFAULT_REQUEST_CODE, accessToken, nullptr);
        if (result != ERR_OK) {
            HILOGE("continue free install failed, result = %{public}d", result);
            return result;
        }
    } else {
        result = StartRemoteAbility(newWant, callerUid, DEFAULT_REQUEST_CODE, accessToken);
        DmsRadar::GetInstance().SaveDataDmsRemoteWant("StartRemoteAbility", result);
        if (result != ERR_OK) {
            HILOGE("continue ability failed, errorCode = %{public}d", result);
            return result;
        }
    }
    HILOGD("[PerformanceTest] StartContinuation end");
    return result;
}

void DistributedSchedService::NotifyCompleteContinuation(const std::u16string& devId,
    int32_t sessionId, bool isSuccess)
{
    if (!isSuccess) {
        HILOGE("NotifyCompleteContinuation failed!");
    }
    if (sessionId <= 0) {
        HILOGE("NotifyCompleteContinuation sessionId invalid!");
        return;
    }
    std::string deviceId = Str16ToStr8(devId);
    sptr<IDistributedSched> remoteDms = GetRemoteDms(deviceId);
    if (remoteDms == nullptr) {
        HILOGE("NotifyCompleteContinuation get remote dms null!");
        return;
    }
    if (dschedContinuation_ == nullptr) {
        HILOGE("continuation object null!");
        return;
    }
    int dSchedEventResult = dschedContinuation_->NotifyDSchedEventResult(ERR_OK);
    HILOGD("NotifyDSchedEventResult result:%{public}d", dSchedEventResult);

    std::string dstInfo("");
    if (DmsContinueTime::GetInstance().GetPull()) {
        int64_t end = GetTickCount();
        std::string strEndTime = DmsContinueTime::GetInstance().GetCurrentTime();
        DmsContinueTime::GetInstance().SetDurationEnd(DMSDURATION_STARTABILITY, end);
        DmsContinueTime::GetInstance().SetDurationEnd(DMSDURATION_TOTALTIME, end);
        DmsContinueTime::GetInstance().SetDurationStrTime(DMSDURATION_ENDTIME, strEndTime);

        std::string bundleName = DmsContinueTime::GetInstance().GetDstInfo().bundleName;
        std::string abilityName = DmsContinueTime::GetInstance().GetDstInfo().abilityName;
        std::string srcNetworkId = dschedContinuation_->continueInfo_.srcNetworkId_;
        DmsUE::GetInstance().DmsContinueComplete(bundleName, abilityName, srcNetworkId, dSchedEventResult);

        DmsContinueTime::GetInstance().AppendInfo();
        DmsContinueTime::GetInstance().SetPull(false);
    } else {
        dstInfo = DmsContinueTime::GetInstance().WriteDstInfo(DmsContinueTime::GetInstance().GetDstInfo().bundleName,
            DmsContinueTime::GetInstance().GetDstInfo().abilityName);
    }

    remoteDms->NotifyContinuationResultFromRemote(sessionId, isSuccess, dstInfo);
    dschedContinuation_->continueInfo_.srcNetworkId_ = "";
    dschedContinuation_->continueInfo_.dstNetworkId_ = "";
    DmsRadar::GetInstance().ClickIconDmsRecvOver("NotifyContinuationResultFromRemote", dSchedEventResult);
}

int32_t DistributedSchedService::NotifyContinuationResultFromRemote(int32_t sessionId, bool isSuccess,
    const std::string dstInfo)
{
    if (sessionId <= 0) {
        HILOGE("NotifyContinuationResultFromRemote sessionId:%{public}d invalid!", sessionId);
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    if (dstInfo.length() != 0) {
        int64_t end = GetTickCount();
        DmsContinueTime::GetInstance().SetDurationEnd(DMSDURATION_STARTABILITY, end);
        std::string strEndTime = DmsContinueTime::GetInstance().GetCurrentTime();
        DmsContinueTime::GetInstance().SetDurationStrTime(DMSDURATION_ENDTIME, strEndTime);
        DmsContinueTime::GetInstance().ReadDstInfo(dstInfo.c_str());
        DmsContinueTime::GetInstance().AppendInfo();
    }

    int32_t missionId = sessionId;
    NotifyContinuationCallbackResult(missionId, isSuccess ? 0 : NOTIFYCOMPLETECONTINUATION_FAILED);
    if (dschedContinuation_ == nullptr) {
        HILOGW("continuation object null!");
        return ERR_OK;
    }
    dschedContinuation_->continueInfo_.srcNetworkId_ = "";
    dschedContinuation_->continueInfo_.dstNetworkId_ = "";
    return ERR_OK;
}

int32_t DistributedSchedService::NotifyDSchedEventResultFromRemote(const std::string type, int32_t dSchedEventResult)
{
    NotifyDSchedEventCallbackResult(dSchedEventResult);
    return ERR_OK;
}

#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
sptr<IFormMgr> DistributedSchedService::GetFormMgrProxy()
{
    HILOGD("GetFormMgrProxy begin.");
    std::lock_guard<std::mutex> lock(formMgrLock_);
    if (formMgrProxy_ != nullptr) {
        HILOGD("get fms proxy success.");
        return formMgrProxy_;
    }

    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        HILOGE("system ability manager is nullptr.");
        return nullptr;
    }

    auto remoteObj = systemAbilityMgr->GetSystemAbility(FORM_MGR_SERVICE_ID);
    if (remoteObj == nullptr) {
        HILOGE("failed to get form manager service");
        return nullptr;
    }

    formMgrDeathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new FormMgrDeathRecipient());
    if (formMgrDeathRecipient_ == nullptr) {
        HILOGE("failed to create FormMgrDeathRecipient!");
        return nullptr;
    }

    if ((remoteObj->IsProxyObject()) && (!remoteObj->AddDeathRecipient(formMgrDeathRecipient_))) {
        HILOGE("add death recipient to FormMgrService failed.");
        return nullptr;
    }

    formMgrProxy_ = iface_cast<IFormMgr>(remoteObj);
    return formMgrProxy_;
}

void DistributedSchedService::ProcessFormMgrDied(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(formMgrLock_);
    if (formMgrProxy_ == nullptr) {
        return;
    }

    auto serviceRemote = formMgrProxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(formMgrDeathRecipient_);
        formMgrProxy_ = nullptr;
    }
}
#endif

void DistributedSchedService::NotifyContinuationCallbackResult(int32_t missionId, int32_t resultCode)
{
    HILOGD("Continuation result is: %{public}d", resultCode);

    if (dschedContinuation_ == nullptr) {
        HILOGE("continuation object null!");
        return;
    }

    int32_t result = 0;
    if (dschedContinuation_->IsInContinuationProgress(missionId)) {
        if (resultCode == ERR_OK && dschedContinuation_->IsCleanMission(missionId)) {
            result = AbilityManagerClient::GetInstance()->CleanMission(missionId);
            HILOGD("clean mission result:%{public}d", result);
        }
        result = dschedContinuation_->NotifyMissionCenterResult(missionId, resultCode);
    } else {
        result = AbilityManagerClient::GetInstance()->NotifyContinuationResult(missionId, resultCode);
        dschedContinuation_->RemoveTimeOut(missionId);
    }
    HILOGD("NotifyContinuationCallbackResult result:%{public}d", result);
}

void DistributedSchedService::NotifyDSchedEventCallbackResult(int32_t resultCode)
{
    HILOGD("Continuation result is: %{public}d", resultCode);
    if (dschedContinuation_ == nullptr) {
        HILOGE("continuation object null!");
        return;
    }
    int dSchedEventresult = dschedContinuation_->NotifyDSchedEventResult(resultCode);
    HILOGD("NotifyDSchedEventResult result:%{public}d", dSchedEventresult);
}

void DistributedSchedService::NotifyDSchedEventCallbackResult(int32_t resultCode, const EventNotify& event)
{
    HILOGD("Continuation result is: %{public}d", resultCode);
    switch (event.dSchedEventType_) {
        case DMS_CONTINUE:
            NotifyContinuateEventResult(resultCode, event);
            break;
        case DMS_COLLABORATION:
            NotifyCollaborateEventResult(resultCode, event);
            break;
        default:
            HILOGE("Event does not carry specific operation type, eventType %{public}d.", event.dSchedEventType_);
            return;
    }
}

void DistributedSchedService::NotifyContinuateEventResult(int32_t resultCode, const EventNotify& event)
{
    if (dschedContinuation_ == nullptr) {
        HILOGE("continuation object null!");
        return;
    }
    dschedContinuation_->continueEvent_ = event;
    int dSchedEventresult = dschedContinuation_->NotifyDSchedEventResult(resultCode);
    HILOGD("NotifyDSchedEventResult result:%{public}d", dSchedEventresult);
    if (event.state_ == DMS_DSCHED_EVENT_FINISH || resultCode != ERR_OK) {
        dschedContinuation_->continueEvent_ = EventNotify();
    }
}

void DistributedSchedService::NotifyCollaborateEventResult(int32_t resultCode, const EventNotify& event)
{
    if (collaborateCbMgr_ == nullptr) {
        HILOGE("collaborate callback manager is null.");
        return;
    }
    int32_t collaborateEventRet = collaborateCbMgr_->NotifyDSchedEventResult(resultCode, event);
    HILOGD("NotifyDSchedEventResult result: %{public}d", collaborateEventRet);
}

void DistributedSchedService::NotifyCollaborateEventWithSessions(
    const std::list<ConnectAbilitySession> &sessionsList, DSchedEventState state, int32_t ret)
{
    for (const auto &session : sessionsList) {
        for (const auto &element : session.GetElementsList()) {
            EventNotify tempEvent;
            GetCurSrcCollaborateEvent(session.GetCallerInfo(), element, state, ret, tempEvent);
            NotifyDSchedEventCallbackResult(ret, tempEvent);
        }
    }
}

void DistributedSchedService::GetCurSrcCollaborateEvent(const CallerInfo &callerInfo,
    const AppExecFwk::ElementName &element, DSchedEventState state, int32_t ret, EventNotify &event)
{
    std::string callingBundleName;
    if (!BundleManagerInternal::GetSpecifyBundleNameFromBms(callerInfo.uid, callingBundleName)) {
        HILOGE("Get specify bundle name for from Bms fail, connect session caller uid %{public}d.", callerInfo.uid);
    }

    event.eventResult_ = ret;
    event.srcNetworkId_ = callerInfo.sourceDeviceId;
    event.dstNetworkId_ = element.GetDeviceID();
    event.srcBundleName_ = callingBundleName;
    event.srcModuleName_ = "";
    event.srcAbilityName_ = "";
    event.destBundleName_ = element.GetBundleName();
    event.destModuleName_ = element.GetModuleName();
    event.destAbilityName_ = element.GetAbilityName();
    event.dSchedEventType_ = DMS_COLLABORATION;
    event.state_ = state;
}

void DistributedSchedService::GetCurDestCollaborateEvent(const CallerInfo &callerInfo,
    const AppExecFwk::ElementName &element, DSchedEventState state, int32_t ret, EventNotify &event)
{
    std::string callerBundleName;
    if (callerInfo.extraInfoJson.find(DMS_UID_SPEC_BUNDLE_NAME) != callerInfo.extraInfoJson.end() &&
        callerInfo.extraInfoJson[DMS_UID_SPEC_BUNDLE_NAME].is_string()) {
        callerBundleName = callerInfo.extraInfoJson[DMS_UID_SPEC_BUNDLE_NAME];
    }

    event.eventResult_ = ret;
    event.srcNetworkId_ = callerInfo.sourceDeviceId;
    event.dstNetworkId_ = element.GetDeviceID();
    event.srcBundleName_ = callerBundleName;
    event.srcModuleName_ = "";
    event.srcAbilityName_ = "";
    event.destBundleName_ = element.GetBundleName();
    event.destModuleName_ = element.GetModuleName();
    event.destAbilityName_ = element.GetAbilityName();
    event.dSchedEventType_ = DMS_COLLABORATION;
    event.state_ = state;
}

void DistributedSchedService::RemoteConnectAbilityMappingLocked(const sptr<IRemoteObject>& connect,
    const std::string& localDeviceId, const std::string& remoteDeviceId, const AppExecFwk::ElementName& element,
    const CallerInfo& callerInfo, TargetComponent targetComponent)
{
    if (connect == nullptr) {
        return;
    }
    auto itConnect = distributedConnectAbilityMap_.find(connect);
    if (itConnect == distributedConnectAbilityMap_.end()) {
        // add uid's connect number
        uint32_t number = ++trackingUidMap_[callerInfo.uid];
        HILOGD("uid %{public}d has %{public}u connection(s), targetComponent: %{public}d.",
            callerInfo.uid, number, targetComponent);
        // new connect, add death recipient
        connect->AddDeathRecipient(connectDeathRecipient_);
        ReportDistributedComponentChange(callerInfo, DISTRIBUTED_COMPONENT_ADD, IDistributedSched::CONNECT,
            IDistributedSched::CALLER);
    }
    auto& sessionsList = distributedConnectAbilityMap_[connect];
    for (auto& session : sessionsList) {
        if (remoteDeviceId == session.GetDestinationDeviceId()) {
            session.AddElement(element);
            // already added session for remote device
            return;
        }
    }
    // connect to another remote device, add a new session to list
    auto& session = sessionsList.emplace_back(localDeviceId, remoteDeviceId, callerInfo, targetComponent);
    session.AddElement(element);
    HILOGD("add connection success");
}

int32_t DistributedSchedService::CheckDistributedConnectLocked(const CallerInfo& callerInfo) const
{
    if (callerInfo.uid < 0) {
        HILOGE("uid %{public}d is invalid.", callerInfo.uid);
        return BIND_ABILITY_UID_INVALID_ERR;
    }
    auto it = trackingUidMap_.find(callerInfo.uid);
    if (it != trackingUidMap_.end() && it->second >= MAX_DISTRIBUTED_CONNECT_NUM) {
        HILOGE("uid %{public}d connected too much abilities, it maybe leak.", callerInfo.uid);
        return BIND_ABILITY_LEAK_ERR;
    }
    return ERR_OK;
}

void DistributedSchedService::DecreaseConnectLocked(int32_t uid)
{
    if (uid < 0) {
        HILOGE("DecreaseConnectLocked invalid uid %{public}d", uid);
        return;
    }
    auto it = trackingUidMap_.find(uid);
    if (it != trackingUidMap_.end()) {
        auto& conns = it->second;
        if (conns > 0) {
            conns--;
        }
        if (conns == 0) {
            HILOGD("DecreaseConnectLocked uid %{public}d connection(s) is 0", uid);
            trackingUidMap_.erase(it);
        }
    }
}

int32_t DistributedSchedService::GetUidLocked(const std::list<ConnectAbilitySession>& sessionsList)
{
    if (!sessionsList.empty()) {
        return sessionsList.front().GetCallerInfo().uid;
    }
    return INVALID_CALLER_UID;
}

int32_t DistributedSchedService::ConnectRemoteAbility(const OHOS::AAFwk::Want& want,
    const sptr<IRemoteObject>& connect, int32_t callerUid, int32_t callerPid, uint32_t accessToken)
{
    std::string localDeviceId;
    std::string remoteDeviceId = want.GetElement().GetDeviceID();
    if (!GetLocalDeviceId(localDeviceId) || !CheckDeviceId(localDeviceId, remoteDeviceId)) {
        HILOGE("ConnectRemoteAbility check deviceId failed");
        return INVALID_PARAMETERS_ERR;
    }

#ifdef DMSFWK_INTERACTIVE_ADAPTER
    if (CheckRemoteOsType(remoteDeviceId)) {
        return ConnectRemoteAbilityAdapter(want, connect, callerUid, callerPid, accessToken);
    }
#endif // DMSFWK_INTERACTIVE_ADAPTER

    CallerInfo callerInfo = { callerUid, callerPid, CALLER_TYPE_HARMONY, localDeviceId };
    callerInfo.accessToken = accessToken;
    {
        std::lock_guard<std::mutex> autoLock(distributedLock_);
        int32_t checkResult = CheckDistributedConnectLocked(callerInfo);
        if (checkResult != ERR_OK) {
            return checkResult;
        }
    }
    if (!BundleManagerInternal::GetCallerAppIdFromBms(callerInfo.uid, callerInfo.callerAppId)) {
        HILOGE("GetCallerAppIdFromBms failed");
        return INVALID_PARAMETERS_ERR;
    }
    if (!BundleManagerInternal::GetBundleNameListFromBms(callerInfo.uid, callerInfo.bundleNames)) {
        HILOGE("GetBundleNameListFromBms failed");
        return INVALID_PARAMETERS_ERR;
    }
    callerInfo.extraInfoJson[DMS_VERSION_ID] = DMS_VERSION;
    HILOGD("[PerformanceTest] ConnectRemoteAbility begin");
    int32_t result = TryConnectRemoteAbility(want, connect, callerInfo);
    if (result != ERR_OK) {
        HILOGE("ConnectRemoteAbility result is %{public}d", result);
    }
    HILOGD("[PerformanceTest] ConnectRemoteAbility end");
    return result;
}

int32_t DistributedSchedService::TryConnectRemoteAbility(const OHOS::AAFwk::Want& want,
    const sptr<IRemoteObject>& connect, const CallerInfo& callerInfo)
{
    AppExecFwk::AbilityInfo abilityInfo;
    AccountInfo accountInfo;
    std::string remoteDeviceId = want.GetElement().GetDeviceID();
    sptr<IDistributedSched> remoteDms = GetRemoteDms(remoteDeviceId);
    if (remoteDms == nullptr || connect == nullptr) {
        HILOGE("TryConnectRemoteAbility invalid parameters");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t ret = DistributedSchedPermission::GetInstance().GetAccountInfo(remoteDeviceId, callerInfo, accountInfo);
    if (ret != ERR_OK) {
        HILOGE("GetAccountInfo failed");
        return ret;
    }
    int32_t retryTimes = BIND_CONNECT_RETRY_TIMES;
    int32_t result = REMOTE_DEVICE_BIND_ABILITY_ERR;
    while (retryTimes--) {
        int64_t start = GetTickCount();
        HILOGD("[PerformanceTest] ConnectRemoteAbility begin");
        result = remoteDms->ConnectAbilityFromRemote(want, abilityInfo, connect, callerInfo, accountInfo);
        HILOGD("[PerformanceTest] ConnectRemoteAbility end");
        if (result == ERR_OK) {
            std::lock_guard<std::mutex> autoLock(distributedLock_);
            RemoteConnectAbilityMappingLocked(connect, callerInfo.sourceDeviceId, remoteDeviceId,
                want.GetElement(), callerInfo, TargetComponent::HARMONY_COMPONENT);
            break;
        }
        if (result == INVALID_REMOTE_PARAMETERS_ERR || result == REMOTE_DEVICE_BIND_ABILITY_ERR) {
            break;
        }
        int64_t elapsedTime = GetTickCount() - start;
        if (elapsedTime > BIND_CONNECT_TIMEOUT) {
            HILOGW("ConnectRemoteAbility timeout, elapsedTime is %{public}" PRId64 " ms", elapsedTime);
            break;
        }
    }
    return result;
}

void DistributedSchedService::ProcessCallerDied(const sptr<IRemoteObject>& connect, int32_t deviceType)
{
    if (connect == nullptr) {
        HILOGE("ProcessCallerDied connect is null");
        return;
    }
    HILOGI("Caller Died DeviceType : %{public}d", deviceType);
    if (deviceType == IDistributedSched::CALLER) {
        HandleLocalCallerDied(connect);
        return;
    }
    sptr<IRemoteObject> callbackWrapper = connect;
    CallerInfo callerInfo;
    AppExecFwk::ElementName element;
    EventNotify tempEvent;
    {
        std::lock_guard<std::mutex> autoLock(calleeLock_);
        auto itConnect = calleeMap_.find(connect);
        if (itConnect != calleeMap_.end()) {
            callbackWrapper = itConnect->second.callbackWrapper;
            element = itConnect->second.element;
            callerInfo = itConnect->second.callerInfo;
            ReportDistributedComponentChange(itConnect->second, DISTRIBUTED_COMPONENT_REMOVE,
                IDistributedSched::CALL, IDistributedSched::CALLEE);

            GetCurDestCollaborateEvent(callerInfo, element, DMS_DSCHED_EVENT_STOP, ERR_OK, tempEvent);
            NotifyDSchedEventCallbackResult(ERR_OK, tempEvent);
            calleeMap_.erase(itConnect);
        } else {
            HILOGW("ProcessCallerDied connect not found");
        }
    }
    UnregisterAppStateObserver(callbackWrapper);
    int32_t result = DistributedSchedAdapter::GetInstance().ReleaseAbility(callbackWrapper, element);
    if (result != ERR_OK) {
        HILOGW("ProcessCallerDied failed, error: %{public}d", result);
    }
    GetCurDestCollaborateEvent(callerInfo, element, DMS_DSCHED_EVENT_FINISH, result, tempEvent);
    NotifyDSchedEventCallbackResult(result, tempEvent);
}

void DistributedSchedService::HandleLocalCallerDied(const sptr<IRemoteObject>& connect)
{
    {
        std::lock_guard<std::mutex> autoLock(callerLock_);
        auto it = callerMap_.find(connect);
        if (it != callerMap_.end()) {
            std::list<ConnectAbilitySession> sessionsList = it->second;
            if (!sessionsList.empty()) {
                ReportDistributedComponentChange(sessionsList.front().GetCallerInfo(), DISTRIBUTED_COMPONENT_REMOVE,
                    IDistributedSched::CALL, IDistributedSched::CALLER);
            }
            NotifyCollaborateEventWithSessions(sessionsList, DMS_DSCHED_EVENT_FINISH, ERR_OK);
            callerMap_.erase(it);
            HILOGI("remove connection success");
        } else {
            HILOGW("HandleLocalCallerDied connect not found");
        }
    }
    {
        std::lock_guard<std::mutex> autoLock(callLock_);
        for (auto iter = callMap_.begin(); iter != callMap_.end(); iter++) {
            if (iter->first == connect) {
                callMap_.erase(iter);
                HILOGI("remove callMap_ connect success");
                break;
            }
        }
    }
}

void DistributedSchedService::ProcessCalleeDied(const sptr<IRemoteObject>& connect)
{
    if (connect == nullptr) {
        HILOGE("ProcessCalleeDied connect is null");
        return;
    }
    sptr<IRemoteObject> callbackWrapper;
    CallerInfo callerInfo;
    AppExecFwk::ElementName element;
    EventNotify tempEvent;
    {
        std::lock_guard<std::mutex> autoLock(calleeLock_);
        auto itConnect = calleeMap_.find(connect);
        if (itConnect != calleeMap_.end()) {
            ReportDistributedComponentChange(itConnect->second, DISTRIBUTED_COMPONENT_REMOVE,
                IDistributedSched::CALL, IDistributedSched::CALLEE);
            callbackWrapper = itConnect->second.callbackWrapper;
            callerInfo = itConnect->second.callerInfo;
            element = itConnect->second.element;
            calleeMap_.erase(itConnect);
        } else {
            HILOGW("ProcessCalleeDied connect not found");
            return;
        }
    }
    GetCurDestCollaborateEvent(callerInfo, element, DMS_DSCHED_EVENT_STOP, ERR_OK, tempEvent);
    NotifyDSchedEventCallbackResult(ERR_OK, tempEvent);

    UnregisterAppStateObserver(callbackWrapper);
    GetCurDestCollaborateEvent(callerInfo, element, DMS_DSCHED_EVENT_FINISH, ERR_OK, tempEvent);
    NotifyDSchedEventCallbackResult(ERR_OK, tempEvent);
}

void DistributedSchedService::ProcessCallResult(const sptr<IRemoteObject>& calleeConnect,
    const sptr<IRemoteObject>& callerConnect)
{
    sptr<IRemoteObject> token;
    AbilityManagerClient::GetInstance()->GetAbilityTokenByCalleeObj(calleeConnect, token);
    if (token == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> autoLock(observerLock_);
    for (auto iter = observerMap_.begin(); iter != observerMap_.end(); iter++) {
        if (iter->second.srcConnect == callerConnect) {
            iter->second.token = token;
            return;
        }
    }
    HILOGE("observerMap can not find callerConnect");
}

int32_t DistributedSchedService::TryStartRemoteAbilityByCall(const OHOS::AAFwk::Want& want,
    const sptr<IRemoteObject>& connect, const CallerInfo& callerInfo)
{
    std::string remoteDeviceId = want.GetElement().GetDeviceID();
    HILOGD("[PerformanceTest] TryStartRemoteAbilityByCall get remote DMS");
    sptr<IDistributedSched> remoteDms = GetRemoteDms(remoteDeviceId);
    if (remoteDms == nullptr) {
        HILOGE("TryStartRemoteAbilityByCall get remote DMS failed, remoteDeviceId: %{public}s",
            GetAnonymStr(remoteDeviceId).c_str());
        return INVALID_PARAMETERS_ERR;
    }
    HILOGD("[PerformanceTest] TryStartRemoteAbilityByCall RPC begin");
    AccountInfo accountInfo;
    int32_t ret = DistributedSchedPermission::GetInstance().GetAccountInfo(remoteDeviceId, callerInfo, accountInfo);
    if (ret != ERR_OK) {
        HILOGE("GetAccountInfo failed");
        return ret;
    }
    AAFwk::Want remoteWant = want;
    int32_t connectToken = SaveConnectToken(want, connect);
    remoteWant.SetParam(DMS_CONNECT_TOKEN, connectToken);
    HILOGD("connectToken is %{public}s", GetAnonymStr(std::to_string(connectToken)).c_str());
    int32_t result = remoteDms->StartAbilityByCallFromRemote(remoteWant, connect, callerInfo, accountInfo);
    HILOGD("[PerformanceTest] TryStartRemoteAbilityByCall RPC end");
    if (result == ERR_OK) {
        SaveCallerComponent(want, connect, callerInfo);
    } else {
        HILOGE("TryStartRemoteAbilityByCall failed, result : %{public}d", result);
    }
    return result;
}

void DistributedSchedService::SaveCallerComponent(const OHOS::AAFwk::Want& want,
    const sptr<IRemoteObject>& connect, const CallerInfo& callerInfo)
{
    if (connect == nullptr) {
        HILOGW("connect is nullptr");
        return;
    }
    std::lock_guard<std::mutex> autoLock(callerLock_);
    auto itConnect = callerMap_.find(connect);
    if (itConnect == callerMap_.end()) {
        connect->AddDeathRecipient(callerDeathRecipientForLocalDevice_);
        ReportDistributedComponentChange(callerInfo, DISTRIBUTED_COMPONENT_ADD, IDistributedSched::CALL,
            IDistributedSched::CALLER);
    }
    auto& sessionsList = callerMap_[connect];
    std::string remoteDeviceId = want.GetElement().GetDeviceID();
    for (auto& session : sessionsList) {
        if (remoteDeviceId == session.GetDestinationDeviceId()) {
            session.AddElement(want.GetElement());
            // already added session for remote device
            return;
        }
    }
    // connect to another remote device, add a new session to list
    auto& session = sessionsList.emplace_back(callerInfo.sourceDeviceId, remoteDeviceId, callerInfo);
    session.AddElement(want.GetElement());

    HILOGD("add connection success");
    EventNotify tempEvent;
    GetCurSrcCollaborateEvent(callerInfo, want.GetElement(), DMS_DSCHED_EVENT_PROCESSING, ERR_OK, tempEvent);
    NotifyDSchedEventCallbackResult(ERR_OK, tempEvent);
}

void DistributedSchedService::RemoveCallerComponent(const sptr<IRemoteObject>& connect)
{
    if (connect == nullptr) {
        HILOGW("connect is nullptr");
        return;
    }
    {
        std::lock_guard<std::mutex> autoLock(callerLock_);
        auto it = callerMap_.find(connect);
        if (it != callerMap_.end()) {
            connect->RemoveDeathRecipient(callerDeathRecipientForLocalDevice_);
            std::list<ConnectAbilitySession> sessionsList = it->second;
            if (!sessionsList.empty()) {
                ReportDistributedComponentChange(sessionsList.front().GetCallerInfo(), DISTRIBUTED_COMPONENT_REMOVE,
                    IDistributedSched::CALL, IDistributedSched::CALLER);
            }
            NotifyCollaborateEventWithSessions(sessionsList, DMS_DSCHED_EVENT_FINISH, ERR_OK);
            callerMap_.erase(it);
            HILOGI("remove connection success");
        } else {
            HILOGW("RemoveCallerComponent connect not found");
        }
    }
    {
        std::lock_guard<std::mutex> autoLock(callLock_);
        for (auto iter = callMap_.begin(); iter != callMap_.end(); iter++) {
            if (iter->first == connect) {
                callMap_.erase(iter);
                HILOGI("remove callMap_ connect success");
                break;
            }
        }
    }
}

void DistributedSchedService::ProcessCalleeOffline(const std::string& deviceId)
{
    {
        std::lock_guard<std::mutex> autoLock(callerLock_);
        for (auto iter = callerMap_.begin(); iter != callerMap_.end();) {
            std::list<ConnectAbilitySession>& sessionsList = iter->second;
            auto itSession = std::find_if(sessionsList.begin(), sessionsList.end(), [&deviceId](const auto& session) {
                return session.GetDestinationDeviceId() == deviceId;
            });
            CallerInfo callerInfo;
            if (itSession != sessionsList.end()) {
                callerInfo = itSession->GetCallerInfo();
                for (const auto &element : itSession->GetElementsList()) {
                    EventNotify tempEvent;
                    GetCurSrcCollaborateEvent(callerInfo, element, DMS_DSCHED_EVENT_FINISH, ERR_OK, tempEvent);
                    NotifyDSchedEventCallbackResult(ERR_OK, tempEvent);
                }
                sessionsList.erase(itSession);
            }

            if (sessionsList.empty()) {
                if (iter->first != nullptr) {
                    iter->first->RemoveDeathRecipient(callerDeathRecipientForLocalDevice_);
                }
                ReportDistributedComponentChange(callerInfo, DISTRIBUTED_COMPONENT_REMOVE,
                    IDistributedSched::CALL, IDistributedSched::CALLER);
                iter = callerMap_.erase(iter);
            } else {
                iter++;
            }
        }
    }
    {
        std::lock_guard<std::mutex> autoLock(callLock_);
        for (auto iter = callMap_.begin(); iter != callMap_.end();) {
            if (iter->second.remoteDeviceId == deviceId) {
                iter = callMap_.erase(iter);
                HILOGI("remove callMap_ connect success");
            } else {
                iter++;
            }
        }
    }
}

int32_t DistributedSchedService::SaveConnectToken(const OHOS::AAFwk::Want& want, const sptr<IRemoteObject>& connect)
{
    int32_t tToken = -1;
    {
        std::lock_guard<std::mutex> tokenLock(tokenMutex_);
        tToken = token_.load();
        if (++tToken > MAX_TOKEN_NUM) {
            tToken = 1;
        }
        token_.store(tToken);
    }
    {
        std::lock_guard<std::mutex> autoLock(callLock_);
        callMap_[connect] = {tToken, want.GetElement().GetDeviceID()};
        HILOGI("add connect success");
    }
    return tToken;
}

int32_t DistributedSchedService::StartRemoteAbilityByCall(const OHOS::AAFwk::Want& want,
    const sptr<IRemoteObject>& connect, int32_t callerUid, int32_t callerPid, uint32_t accessToken)
{
    if (connect == nullptr) {
        HILOGE("StartRemoteAbilityByCall connect is null");
        return INVALID_PARAMETERS_ERR;
    }
    std::string localDeviceId;
    std::string remoteDeviceId = want.GetElement().GetDeviceID();
    if (!GetLocalDeviceId(localDeviceId) || !CheckDeviceId(localDeviceId, remoteDeviceId)) {
        HILOGE("StartRemoteAbilityByCall check deviceId failed");
        return INVALID_PARAMETERS_ERR;
    }
    CallerInfo callerInfo = { callerUid, callerPid };
    callerInfo.sourceDeviceId = localDeviceId;
    callerInfo.accessToken = accessToken;
    if (!BundleManagerInternal::GetCallerAppIdFromBms(callerInfo.uid, callerInfo.callerAppId)) {
        HILOGE("GetCallerAppIdFromBms failed");
        return INVALID_PARAMETERS_ERR;
    }
    if (!BundleManagerInternal::GetBundleNameListFromBms(callerInfo.uid, callerInfo.bundleNames)) {
        HILOGE("GetBundleNameListFromBms failed");
        return INVALID_PARAMETERS_ERR;
    }
    callerInfo.extraInfoJson[DMS_VERSION_ID] = DMS_VERSION;
    std::string uidSpecBundleName;
    if (!BundleManagerInternal::GetSpecifyBundleNameFromBms(callerInfo.uid, uidSpecBundleName)) {
        HILOGE("Get specify bundle name for from Bms fail, connect session caller uid %{public}d.", callerInfo.uid);
    }
    callerInfo.extraInfoJson[DMS_UID_SPEC_BUNDLE_NAME] = uidSpecBundleName;

    EventNotify tempEvent;
    GetCurSrcCollaborateEvent(callerInfo, want.GetElement(), DMS_DSCHED_EVENT_START, ERR_OK, tempEvent);
    NotifyDSchedEventCallbackResult(ERR_OK, tempEvent);

    int32_t ret = TryStartRemoteAbilityByCall(want, connect, callerInfo);
    if (ret != ERR_OK) {
        {
            std::lock_guard<std::mutex> autoLock(callLock_);
            callMap_.erase(connect);
        }
        HILOGE("StartRemoteAbilityByCall result is %{public}d", ret);
    }
    return ret;
}

int32_t DistributedSchedService::ReleaseRemoteAbility(const sptr<IRemoteObject>& connect,
    const AppExecFwk::ElementName &element)
{
    if (connect == nullptr) {
        HILOGE("ReleaseRemoteAbility connect is null");
        return INVALID_PARAMETERS_ERR;
    }
    if (element.GetDeviceID().empty()) {
        HILOGE("ReleaseRemoteAbility remote deviceId empty");
        return INVALID_PARAMETERS_ERR;
    }
    sptr<IDistributedSched> remoteDms = GetRemoteDms(element.GetDeviceID());
    if (remoteDms == nullptr) {
        HILOGE("ReleaseRemoteAbility get remote dms failed, devId: %{public}s",
            GetAnonymStr(element.GetDeviceID()).c_str());
        return INVALID_PARAMETERS_ERR;
    }
    CallerInfo callerInfo;
    if (!GetLocalDeviceId(callerInfo.sourceDeviceId)) {
        HILOGE("ReleaseRemoteAbility get local deviceId failed");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t result = remoteDms->ReleaseAbilityFromRemote(connect, element, callerInfo);
    if (result == ERR_OK) {
        RemoveCallerComponent(connect);
    } else {
        HILOGE("ReleaseRemoteAbility result is %{public}d", result);
    }
    return result;
}

int32_t DistributedSchedService::StartAbilityByCallFromRemote(const OHOS::AAFwk::Want& want,
    const sptr<IRemoteObject>& connect, const CallerInfo& callerInfo, const AccountInfo& accountInfo)
{
    HILOGD("[PerformanceTest] DistributedSchedService StartAbilityByCallFromRemote begin");
    if (connect == nullptr) {
        HILOGE("StartAbilityByCallFromRemote connect is null");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    EventNotify tempEvent;
    GetCurDestCollaborateEvent(callerInfo, want.GetElement(), DMS_DSCHED_EVENT_START, ERR_OK, tempEvent);
    NotifyDSchedEventCallbackResult(ERR_OK, tempEvent);

    std::string localDeviceId;
    std::string destinationDeviceId = want.GetElement().GetDeviceID();
    if (!GetLocalDeviceId(localDeviceId) ||
        !CheckDeviceIdFromRemote(localDeviceId, destinationDeviceId, callerInfo.sourceDeviceId)) {
        HILOGE("StartAbilityByCallFromRemote check deviceId failed");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    int32_t result = CheckTargetPermission(want, callerInfo, accountInfo, CALL_PERMISSION, false);
    if (result != ERR_OK) {
        HILOGE("CheckTargetPermission failed!!");
        return result;
    }

    sptr<IRemoteObject> callbackWrapper;
    {
        std::lock_guard<std::mutex> autoLock(calleeLock_);
        auto itConnect = calleeMap_.find(connect);
        if (itConnect != calleeMap_.end()) {
            callbackWrapper = itConnect->second.callbackWrapper;
        } else {
            callbackWrapper = new AbilityConnectionWrapperStub(connect, localDeviceId);
        }
    }
    int32_t errCode = DistributedSchedAdapter::GetInstance().StartAbilityByCall(want, callbackWrapper, this);
    HILOGD("[PerformanceTest] StartAbilityByCallFromRemote end");
    if (errCode == ERR_OK) {
        {
            std::lock_guard<std::mutex> autoLock(calleeLock_);
            ConnectInfo connectInfo {callerInfo, callbackWrapper, want.GetElement()};
            ReportDistributedComponentChange(connectInfo, DISTRIBUTED_COMPONENT_ADD,
                IDistributedSched::CALL, IDistributedSched::CALLEE);
            calleeMap_.emplace(connect, connectInfo);
        }
        connect->AddDeathRecipient(callerDeathRecipient_);
        if (!RegisterAppStateObserver(want, callerInfo, connect, callbackWrapper)) {
            HILOGE("RegisterAppStateObserver failed");
        }
    }

    GetCurDestCollaborateEvent(callerInfo, want.GetElement(), DMS_DSCHED_EVENT_PROCESSING, ERR_OK, tempEvent);
    NotifyDSchedEventCallbackResult(ERR_OK, tempEvent);
    return errCode;
}

int32_t DistributedSchedService::ReleaseAbilityFromRemote(const sptr<IRemoteObject>& connect,
    const AppExecFwk::ElementName &element, const CallerInfo& callerInfo)
{
    if (connect == nullptr) {
        HILOGE("ReleaseAbilityFromRemote connect is null");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    EventNotify tempEvent;
    GetCurDestCollaborateEvent(callerInfo, element, DMS_DSCHED_EVENT_STOP, ERR_OK, tempEvent);
    NotifyDSchedEventCallbackResult(ERR_OK, tempEvent);

    HILOGD("[PerformanceTest] ReleaseAbilityFromRemote begin");
    std::string localDeviceId;
    if (!GetLocalDeviceId(localDeviceId) || localDeviceId.empty() ||
        callerInfo.sourceDeviceId.empty() || localDeviceId == callerInfo.sourceDeviceId) {
        HILOGE("ReleaseAbilityFromRemote check deviceId failed");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    sptr<IRemoteObject> callbackWrapper;
    {
        std::lock_guard<std::mutex> autoLock(calleeLock_);
        auto itConnect = calleeMap_.find(connect);
        if (itConnect == calleeMap_.end()) {
            HILOGE("ReleaseAbilityFromRemote callee not found");
            return INVALID_REMOTE_PARAMETERS_ERR;
        }
        callbackWrapper = itConnect->second.callbackWrapper;
        ReportDistributedComponentChange(itConnect->second, DISTRIBUTED_COMPONENT_REMOVE,
            IDistributedSched::CALL, IDistributedSched::CALLEE);
        calleeMap_.erase(itConnect);
        connect->RemoveDeathRecipient(callerDeathRecipient_);
    }
    UnregisterAppStateObserver(callbackWrapper);
    int32_t result = DistributedSchedAdapter::GetInstance().ReleaseAbility(callbackWrapper, element);
    HILOGD("[PerformanceTest] ReleaseAbilityFromRemote end");
    if (result != ERR_OK) {
        HILOGE("ReleaseAbilityFromRemote failed, error: %{public}d", result);
    }
    GetCurDestCollaborateEvent(callerInfo, element, DMS_DSCHED_EVENT_FINISH, result, tempEvent);
    NotifyDSchedEventCallbackResult(result, tempEvent);
    return result;
}

#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
int32_t DistributedSchedService::StartRemoteShareForm(const std::string& remoteDeviceId,
    const OHOS::AppExecFwk::FormShareInfo& formShareInfo)
{
    HILOGD("SHAREFORM:: func call");

    if (remoteDeviceId.empty()) {
        HILOGE("StartRemoteShareForm input params error");
        return INVALID_PARAMETERS_ERR;
    }

    sptr<IDistributedSched> remoteDms = GetRemoteDms(remoteDeviceId);
    if (remoteDms == nullptr) {
        HILOGE("StartRemoteShareForm get remote DMS failed, remoteDeviceId: %{public}s",
            GetAnonymStr(remoteDeviceId).c_str());
        return GET_REMOTE_DMS_FAIL;
    }
    std::string localDeviceId = "";
    GetLocalDeviceId(localDeviceId);
    OHOS::AppExecFwk::FormShareInfo formShareInfoCopy;
    formShareInfoCopy.formId = formShareInfo.formId;
    formShareInfoCopy.formName = formShareInfo.formName;
    formShareInfoCopy.bundleName = formShareInfo.bundleName;
    formShareInfoCopy.moduleName = formShareInfo.moduleName;
    formShareInfoCopy.abilityName = formShareInfo.abilityName;
    formShareInfoCopy.formTempFlag = formShareInfo.formTempFlag;
    formShareInfoCopy.dimensionId = formShareInfo.dimensionId;
    formShareInfoCopy.providerShareData = formShareInfo.providerShareData;
    formShareInfoCopy.deviceId = localDeviceId;
    int32_t result = remoteDms->StartShareFormFromRemote(remoteDeviceId, formShareInfoCopy);
    HILOGD("[PerformanceTest] StartRemoteShareForm RPC end");
    if (result != ERR_OK) {
        HILOGE("StartRemoteShareForm failed, result : %{public}d", result);
    }
    return result;
}

int32_t DistributedSchedService::StartShareFormFromRemote(
    const std::string& remoteDeviceId, const OHOS::AppExecFwk::FormShareInfo& formShareInfo)
{
    HILOGD("SHAREFORM:: func call begin");
    std::string localDeviceId = "";
    GetLocalDeviceId(localDeviceId);
    if (CheckDeviceId(localDeviceId, remoteDeviceId)) {
        HILOGE("localId is %{public}s != %{public}s", GetAnonymStr(localDeviceId).c_str(),
            GetAnonymStr(remoteDeviceId).c_str());
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    auto formMgr = GetFormMgrProxy();
    if (formMgr == nullptr) {
        HILOGE("get form mgr proxy failed.");
        return NOT_FIND_SERVICE_PROXY;
    }

    auto result = formMgr->RecvFormShareInfoFromRemote(formShareInfo);
    HILOGD("SHAREFORM:: func call end");
    return result;
}
#endif

int32_t DistributedSchedService::GetDistributedComponentList(std::vector<std::string>& distributedComponents)
{
    GetConnectComponentList(distributedComponents);
    GetCallComponentList(distributedComponents);
    return ERR_OK;
}

void DistributedSchedService::GetConnectComponentList(std::vector<std::string>& distributedComponents)
{
    {
        std::lock_guard<std::mutex> autoLock(distributedLock_);
        for (const auto& iter : distributedConnectAbilityMap_) {
            if (iter.second.empty()) {
                continue;
            }
            CallerInfo callerInfo = iter.second.front().GetCallerInfo();
            nlohmann::json componentInfoJson;
            componentInfoJson[PID_KEY] = callerInfo.pid;
            componentInfoJson[UID_KEY] = callerInfo.uid;
            componentInfoJson[BUNDLE_NAME_KEY] =
                callerInfo.bundleNames.empty() ? std::string() : callerInfo.bundleNames.front();
            componentInfoJson[COMPONENT_TYPE_KEY] = IDistributedSched::CONNECT;
            componentInfoJson[DEVICE_TYPE_KEY] = IDistributedSched::CALLER;
            std::string componentInfo = componentInfoJson.dump();
            distributedComponents.emplace_back(componentInfo);
        }
    }
    {
        std::lock_guard<std::mutex> autoLock(connectLock_);
        for (const auto& iter : connectAbilityMap_) {
            ConnectInfo connectInfo = iter.second;
            nlohmann::json componentInfoJson;
            componentInfoJson[UID_KEY] = BundleManagerInternal::GetUidFromBms(connectInfo.element.GetBundleName());
            componentInfoJson[BUNDLE_NAME_KEY] = connectInfo.element.GetBundleName();
            componentInfoJson[COMPONENT_TYPE_KEY] = IDistributedSched::CONNECT;
            componentInfoJson[DEVICE_TYPE_KEY] = IDistributedSched::CALLEE;
            std::string componentInfo = componentInfoJson.dump();
            distributedComponents.emplace_back(componentInfo);
        }
    }
}

void DistributedSchedService::GetCallComponentList(std::vector<std::string>& distributedComponents)
{
    {
        std::lock_guard<std::mutex> autoLock(callerLock_);
        for (const auto& iter : callerMap_) {
            if (iter.second.empty()) {
                continue;
            }
            CallerInfo callerInfo = iter.second.front().GetCallerInfo();
            nlohmann::json componentInfoJson;
            componentInfoJson[PID_KEY] = callerInfo.pid;
            componentInfoJson[UID_KEY] = callerInfo.uid;
            componentInfoJson[BUNDLE_NAME_KEY] =
                callerInfo.bundleNames.empty() ? std::string() : callerInfo.bundleNames.front();
            componentInfoJson[COMPONENT_TYPE_KEY] = IDistributedSched::CALL;
            componentInfoJson[DEVICE_TYPE_KEY] = IDistributedSched::CALLER;
            std::string componentInfo = componentInfoJson.dump();
            distributedComponents.emplace_back(componentInfo);
        }
    }
    {
        std::lock_guard<std::mutex> autoLock(calleeLock_);
        for (const auto& iter : calleeMap_) {
            ConnectInfo connectInfo = iter.second;
            nlohmann::json componentInfoJson;
            componentInfoJson[UID_KEY] = BundleManagerInternal::GetUidFromBms(connectInfo.element.GetBundleName());
            componentInfoJson[BUNDLE_NAME_KEY] = connectInfo.element.GetBundleName();
            componentInfoJson[COMPONENT_TYPE_KEY] = IDistributedSched::CALL;
            componentInfoJson[DEVICE_TYPE_KEY] = IDistributedSched::CALLEE;
            std::string componentInfo = componentInfoJson.dump();
            distributedComponents.emplace_back(componentInfo);
        }
    }
}

void DistributedSchedService::ReportDistributedComponentChange(const CallerInfo& callerInfo, int32_t changeType,
    int32_t componentType, int32_t deviceType)
{
#if defined(EFFICIENCY_MANAGER_ENABLE) || defined(SUPPORT_DISTRIBUTEDCOMPONENT_TO_MEMMGR)
    HILOGI("caller report");
    auto func = [this, callerInfo, changeType, componentType, deviceType]() {
#ifdef EFFICIENCY_MANAGER_ENABLE
        std::unordered_map<std::string, std::string> payload;
        payload[PID_KEY] = std::to_string(callerInfo.pid);
        payload[UID_KEY] = std::to_string(callerInfo.uid);
        payload[BUNDLE_NAME_KEY] =
            callerInfo.bundleNames.empty() ? std::string() : callerInfo.bundleNames.front();
        payload[COMPONENT_TYPE_KEY] = std::to_string(componentType);
        payload[DEVICE_TYPE_KEY] = std::to_string(deviceType);
        payload[CHANGE_TYPE_KEY] = std::to_string(changeType);
        uint32_t type = ResourceSchedule::ResType::RES_TYPE_REPORT_DISTRIBUTE_COMPONENT_CHANGE;
        ResourceSchedule::ResSchedClient::GetInstance().ReportData(type, 0, payload);
#endif
#ifdef SUPPORT_DISTRIBUTEDCOMPONENT_TO_MEMMGR
        Memory::MemMgrClient::GetInstance().NotifyDistDevStatus(callerInfo.pid, callerInfo.uid,
            callerInfo.bundleNames.empty() ? std::string() : callerInfo.bundleNames.front(),
            changeType == DISTRIBUTED_COMPONENT_ADD);
#endif
    };
    if (componentChangeHandler_ != nullptr) {
        componentChangeHandler_->PostTask(func);
        return;
    }
    HILOGE("HandleDistributedComponentChange handler postTask failed");
#endif
}

void DistributedSchedService::ReportDistributedComponentChange(const ConnectInfo& connectInfo, int32_t changeType,
    int32_t componentType, int32_t deviceType)
{
#ifdef EFFICIENCY_MANAGER_ENABLE
    HILOGI("callee report");
    auto func = [this, connectInfo, changeType, componentType, deviceType]() {
        std::unordered_map<std::string, std::string> payload;
        payload[UID_KEY] = std::to_string(BundleManagerInternal::GetUidFromBms(connectInfo.element.GetBundleName()));
        payload[BUNDLE_NAME_KEY] = connectInfo.element.GetBundleName();
        payload[COMPONENT_TYPE_KEY] = std::to_string(componentType);
        payload[DEVICE_TYPE_KEY] = std::to_string(deviceType);
        payload[CHANGE_TYPE_KEY] = std::to_string(changeType);
        uint32_t type = ResourceSchedule::ResType::RES_TYPE_REPORT_DISTRIBUTE_COMPONENT_CHANGE;
        ResourceSchedule::ResSchedClient::GetInstance().ReportData(type, 0, payload);
    };
    if (componentChangeHandler_ != nullptr) {
        componentChangeHandler_->PostTask(func);
        return;
    }
    HILOGE("HandleDistributedComponentChange handler postTask failed");
#endif
}

sptr<IDistributedSched> DistributedSchedService::GetRemoteDms(const std::string& remoteDeviceId)
{
    if (remoteDeviceId.empty()) {
        HILOGE("GetRemoteDms remoteDeviceId is empty");
        return nullptr;
    }
    HILOGD("GetRemoteDms connect deviceid is %s", GetAnonymStr(remoteDeviceId).c_str());
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        HILOGE("GetRemoteDms failed to connect to systemAbilityMgr!");
        return nullptr;
    }
    HILOGI("[PerformanceTest] GetRemoteDms begin");
    auto object = samgr->CheckSystemAbility(DISTRIBUTED_SCHED_SA_ID, remoteDeviceId);
    HILOGI("[PerformanceTest] GetRemoteDms end");
    if (object == nullptr) {
        HILOGE("GetRemoteDms failed to get remote DistributedSched %{private}s", GetAnonymStr(remoteDeviceId).c_str());
        return nullptr;
    }
    return iface_cast<IDistributedSched>(object);
}

bool DistributedSchedService::GetLocalDeviceId(std::string& localDeviceId)
{
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId)) {
        HILOGE("GetLocalDeviceId failed");
        return false;
    }
    return true;
}

bool DistributedSchedService::CheckDeviceId(const std::string& localDeviceId, const std::string& remoteDeviceId)
{
    // remoteDeviceId must not same with localDeviceId
    if (localDeviceId.empty() || remoteDeviceId.empty() || localDeviceId == remoteDeviceId) {
        HILOGE("check deviceId failed");
        return false;
    }
    return true;
}

bool DistributedSchedService::CheckDeviceIdFromRemote(const std::string& localDeviceId,
    const std::string& destinationDeviceId, const std::string& sourceDeviceId)
{
    if (localDeviceId.empty() || destinationDeviceId.empty() || sourceDeviceId.empty()) {
        HILOGE("CheckDeviceIdFromRemote failed");
        return false;
    }
    // destinationDeviceId set by remote must be same with localDeviceId
    if (localDeviceId != destinationDeviceId) {
        HILOGE("destinationDeviceId is not same with localDeviceId");
        return false;
    }
    HILOGD("CheckDeviceIdFromRemote sourceDeviceId %s", GetAnonymStr(sourceDeviceId).c_str());
    HILOGD("CheckDeviceIdFromRemote localDeviceId %s", GetAnonymStr(localDeviceId).c_str());
    HILOGD("CheckDeviceIdFromRemote destinationDeviceId %s", GetAnonymStr(destinationDeviceId).c_str());

    if (sourceDeviceId == destinationDeviceId || sourceDeviceId == localDeviceId) {
        HILOGE("destinationDeviceId is different with localDeviceId and destinationDeviceId");
        return false;
    }

    if (sourceDeviceId != IPCSkeleton::GetCallingDeviceID()) {
        HILOGE("sourceDeviceId is not correct");
        return false;
    }
    return true;
}

int32_t DistributedSchedService::ConnectAbilityFromRemote(const OHOS::AAFwk::Want& want,
    const AppExecFwk::AbilityInfo& abilityInfo, const sptr<IRemoteObject>& connect,
    const CallerInfo& callerInfo, const AccountInfo& accountInfo)
{
    HILOGD("[PerformanceTest] DistributedSchedService ConnectAbilityFromRemote begin");
    if (connect == nullptr) {
        HILOGE("ConnectAbilityFromRemote connect is null");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    HILOGD("ConnectAbilityFromRemote uid is %{public}d, pid is %{public}d, AccessTokenID is %{public}s",
        callerInfo.uid, callerInfo.pid, GetAnonymStr(std::to_string(callerInfo.accessToken)).c_str());
    std::string localDeviceId;
    std::string destinationDeviceId = want.GetElement().GetDeviceID();
    if (!GetLocalDeviceId(localDeviceId) ||
        !CheckDeviceIdFromRemote(localDeviceId, destinationDeviceId, callerInfo.sourceDeviceId)) {
        HILOGE("ConnectAbilityFromRemote check deviceId failed");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    int32_t result = CheckTargetPermission(want, callerInfo, accountInfo, START_PERMISSION, true);
    if (result != ERR_OK) {
        HILOGE("CheckTargetPermission failed!!");
        return result;
    }

    HILOGD("ConnectAbilityFromRemote callerType is %{public}d", callerInfo.callerType);
    sptr<IRemoteObject> callbackWrapper = connect;
    std::map<sptr<IRemoteObject>, ConnectInfo>::iterator itConnect;
    if (callerInfo.callerType == CALLER_TYPE_HARMONY) {
        std::lock_guard<std::mutex> autoLock(connectLock_);
        itConnect = connectAbilityMap_.find(connect);
        if (itConnect != connectAbilityMap_.end()) {
            callbackWrapper = itConnect->second.callbackWrapper;
        } else {
            callbackWrapper = new AbilityConnectionWrapperStub(connect);
        }
    }
    int32_t errCode = DistributedSchedAdapter::GetInstance().ConnectAbility(want, callbackWrapper, this);
    HILOGD("[PerformanceTest] ConnectAbilityFromRemote end");
    if (errCode == ERR_OK) {
        std::lock_guard<std::mutex> autoLock(connectLock_);
        if (itConnect == connectAbilityMap_.end()) {
            ConnectInfo connectInfo {callerInfo, callbackWrapper, want.GetElement()};
            ReportDistributedComponentChange(connectInfo, DISTRIBUTED_COMPONENT_ADD,
                IDistributedSched::CONNECT, IDistributedSched::CALLEE);
            connectAbilityMap_.emplace(connect, connectInfo);
        }
    }
    return errCode;
}

int32_t DistributedSchedService::DisconnectEachRemoteAbilityLocked(const std::string& localDeviceId,
    const std::string& remoteDeviceId, const sptr<IRemoteObject>& connect)
{
    sptr<IDistributedSched> remoteDms = GetRemoteDms(remoteDeviceId);
    if (remoteDms == nullptr) {
        HILOGE("DisconnectRemoteAbility get remote dms failed");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t result = remoteDms->DisconnectAbilityFromRemote(connect, IPCSkeleton::GetCallingUid(), localDeviceId);
    if (result != ERR_OK) {
        HILOGE("DisconnectEachRemoteAbilityLocked result is %{public}d", result);
    }
    return result;
}

int32_t DistributedSchedService::DisconnectRemoteAbility(const sptr<IRemoteObject>& connect, int32_t callerUid,
    uint32_t accessToken)
{
    if (connect == nullptr) {
        HILOGE("DisconnectRemoteAbility connect is null");
        return INVALID_PARAMETERS_ERR;
    }

    std::list<ConnectAbilitySession> sessionsList;
    {
        std::lock_guard<std::mutex> autoLock(distributedLock_);
        auto it = distributedConnectAbilityMap_.find(connect);
        if (it != distributedConnectAbilityMap_.end()) {
            sessionsList = it->second;
            int32_t uid = GetUidLocked(sessionsList);
            // also decrease number when erase connect
            DecreaseConnectLocked(uid);
            connect->RemoveDeathRecipient(connectDeathRecipient_);
            if (!sessionsList.empty()) {
                ReportDistributedComponentChange(sessionsList.front().GetCallerInfo(), DISTRIBUTED_COMPONENT_REMOVE,
                    IDistributedSched::CONNECT, IDistributedSched::CALLER);
            }
            distributedConnectAbilityMap_.erase(it);
            HILOGI("remove connection success");
        } else {
#ifdef DMSFWK_INTERACTIVE_ADAPTER
            return DisconnectRemoteAbilityAdapter(connect, callerUid, accessToken);
#endif // DMSFWK_INTERACTIVE_ADAPTER
        }
    }
    if (!sessionsList.empty()) {
        for (const auto& session : sessionsList) {
            if (session.GetTargetComponent() == TargetComponent::HARMONY_COMPONENT) {
                DisconnectEachRemoteAbilityLocked(session.GetSourceDeviceId(),
                    session.GetDestinationDeviceId(), connect);
            } else {
                HILOGW("DisconnectRemoteAbility non-harmony component");
            }
        }
        return ERR_OK;
    }
    return NO_CONNECT_CALLBACK_ERR;
}

int32_t DistributedSchedService::DisconnectAbilityFromRemote(const sptr<IRemoteObject>& connect,
    int32_t uid, const std::string& sourceDeviceId)
{
    if (connect == nullptr) {
        HILOGE("DisconnectAbilityFromRemote connect is null");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    HILOGD("[PerformanceTest] DisconnectAbilityFromRemote begin");
    std::string localDeviceId;
    AppExecFwk::AbilityInfo abilityInfo;
    if (!GetLocalDeviceId(localDeviceId) || localDeviceId.empty() ||
        sourceDeviceId.empty() || localDeviceId == sourceDeviceId) {
        HILOGE("DisconnectAbilityFromRemote check deviceId failed");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    sptr<IRemoteObject> callbackWrapper = connect;
    {
        std::lock_guard<std::mutex> autoLock(connectLock_);
        auto itConnect = connectAbilityMap_.find(connect);
        if (itConnect != connectAbilityMap_.end()) {
            callbackWrapper = itConnect->second.callbackWrapper;
            ReportDistributedComponentChange(itConnect->second, DISTRIBUTED_COMPONENT_REMOVE,
                IDistributedSched::CONNECT, IDistributedSched::CALLEE);
            connectAbilityMap_.erase(itConnect);
        } else {
            if (!IPCSkeleton::IsLocalCalling()) {
                HILOGE("DisconnectAbilityFromRemote connect not found");
                return INVALID_REMOTE_PARAMETERS_ERR;
            }
        }
    }
    int32_t result = DistributedSchedAdapter::GetInstance().DisconnectAbility(callbackWrapper);
    HILOGD("[PerformanceTest] DisconnectAbilityFromRemote end");
    return result;
}

int32_t DistributedSchedService::NotifyProcessDiedFromRemote(const CallerInfo& callerInfo)
{
    HILOGI("NotifyProcessDiedFromRemote called");
    int32_t errCode = ERR_OK;
    {
        std::lock_guard<std::mutex> autoLock(connectLock_);
        for (auto iter = connectAbilityMap_.begin(); iter != connectAbilityMap_.end();) {
            ConnectInfo& connectInfo = iter->second;
            if (callerInfo.sourceDeviceId == connectInfo.callerInfo.sourceDeviceId
                && callerInfo.uid == connectInfo.callerInfo.uid
                && callerInfo.pid == connectInfo.callerInfo.pid
                && callerInfo.callerType == connectInfo.callerInfo.callerType) {
                HILOGI("NotifyProcessDiedFromRemote erase connection success");
                int32_t ret = DistributedSchedAdapter::GetInstance().DisconnectAbility(connectInfo.callbackWrapper);
                if (ret != ERR_OK) {
                    errCode = ret;
                }
                ReportDistributedComponentChange(connectInfo, DISTRIBUTED_COMPONENT_REMOVE,
                    IDistributedSched::CONNECT, IDistributedSched::CALLEE);
                iter = connectAbilityMap_.erase(iter);
            } else {
                iter++;
            }
        }
    }
    return errCode;
}

void DistributedSchedService::RemoveConnectAbilityInfo(const std::string& deviceId)
{
    {
        std::lock_guard<std::mutex> autoLock(distributedLock_);
        for (auto iter = distributedConnectAbilityMap_.begin(); iter != distributedConnectAbilityMap_.end();) {
            std::list<ConnectAbilitySession>& sessionsList = iter->second;
            int32_t uid = GetUidLocked(sessionsList);
            auto itSession = std::find_if(sessionsList.begin(), sessionsList.end(), [&deviceId](const auto& session) {
                return session.GetDestinationDeviceId() == deviceId;
            });
            CallerInfo callerInfo;
            if (itSession != sessionsList.end()) {
                NotifyDeviceOfflineToAppLocked(iter->first, *itSession);
                callerInfo = itSession->GetCallerInfo();
                sessionsList.erase(itSession);
            }

            if (sessionsList.empty()) {
                if (iter->first != nullptr) {
                    iter->first->RemoveDeathRecipient(connectDeathRecipient_);
                }
                DecreaseConnectLocked(uid);
                ReportDistributedComponentChange(callerInfo, DISTRIBUTED_COMPONENT_REMOVE,
                    IDistributedSched::CONNECT, IDistributedSched::CALLER);
                iter = distributedConnectAbilityMap_.erase(iter);
            } else {
                iter++;
            }
        }
    }

    {
        std::lock_guard<std::mutex> autoLock(connectLock_);
        for (auto iter = connectAbilityMap_.begin(); iter != connectAbilityMap_.end();) {
            ConnectInfo& connectInfo = iter->second;
            if (deviceId == connectInfo.callerInfo.sourceDeviceId) {
                DistributedSchedAdapter::GetInstance().DisconnectAbility(connectInfo.callbackWrapper);
                ReportDistributedComponentChange(connectInfo, DISTRIBUTED_COMPONENT_REMOVE,
                    IDistributedSched::CONNECT, IDistributedSched::CALLEE);
                connectAbilityMap_.erase(iter++);
                HILOGI("ProcessDeviceOffline erase connection success");
            } else {
                iter++;
            }
        }
    }
}

ErrCode DistributedSchedService::QueryOsAccount(int32_t& activeAccountId)
{
#ifdef OS_ACCOUNT_PART
    std::vector<int32_t> ids;
    ErrCode err = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (err != ERR_OK || ids.empty()) {
        HILOGE("QueryActiveOsAccountIds passing param invalid or return error!, err : %{public}d", err);
        return INVALID_PARAMETERS_ERR;
    }
    activeAccountId = ids[0];
#endif
    return ERR_OK;
}

void DistributedSchedService::ProcessDeviceOffline(const std::string& deviceId)
{
    HILOGI("ProcessDeviceOffline called");
    std::string localDeviceId;
    if (!GetLocalDeviceId(localDeviceId) || !CheckDeviceId(localDeviceId, deviceId)) {
        HILOGE("ProcessDeviceOffline check deviceId failed");
        return;
    }
    RemoveConnectAbilityInfo(deviceId);
    ProcessCalleeOffline(deviceId);
    ProcessFreeInstallOffline(deviceId);
}

void DistributedSchedService::ProcessFreeInstallOffline(const std::string& deviceId)
{
    if (dmsCallbackTask_ == nullptr) {
        HILOGE("callbackTask object null!");
        return;
    }
    dmsCallbackTask_->NotifyDeviceOffline(deviceId);
}

void DistributedSchedService::NotifyDeviceOfflineToAppLocked(const sptr<IRemoteObject>& connect,
    const ConnectAbilitySession& session)
{
    std::list<AppExecFwk::ElementName> elementsList = session.GetElementsList();
    for (const auto& element : elementsList) {
        int32_t errCode = NotifyApp(connect, element, DEVICE_OFFLINE_ERR);
        if (errCode != ERR_NONE) {
            HILOGW("ProcessDeviceOffline notify failed, errCode = %{public}d", errCode);
        }
    }
}

int32_t DistributedSchedService::NotifyApp(const sptr<IRemoteObject>& connect,
    const AppExecFwk::ElementName& element, int32_t errCode)
{
    if (connect == nullptr) {
        return OBJECT_NULL;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(CONNECTION_CALLBACK_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Parcelable, &element);
    PARCEL_WRITE_HELPER(data, Int32, errCode);
    MessageParcel reply;
    MessageOption option;
    return connect->SendRequest(IAbilityConnection::ON_ABILITY_DISCONNECT_DONE, data, reply, option);
}

void DistributedSchedService::ProcessConnectDied(const sptr<IRemoteObject>& connect)
{
    if (connect == nullptr) {
        HILOGE("ProcessConnectDied connect is null");
        return;
    }

    std::list<ProcessDiedNotifyInfo> notifyList;
    {
        std::lock_guard<std::mutex> autoLock(distributedLock_);
        auto it = distributedConnectAbilityMap_.find(connect);
        if (it == distributedConnectAbilityMap_.end()) {
            return;
        }
        std::list<ConnectAbilitySession>& connectSessionsList = it->second;
        if (connectSessionsList.empty()) {
            return;
        }
        CallerInfo callerInfo = connectSessionsList.front().GetCallerInfo();
        std::set<std::string> processedDeviceSet;
        // to reduce the number of communications between devices, clean all the died process's connections
        for (auto iter = distributedConnectAbilityMap_.begin(); iter != distributedConnectAbilityMap_.end();) {
            std::list<ConnectAbilitySession>& sessionsList = iter->second;
            if (!sessionsList.empty() && sessionsList.front().IsSameCaller(callerInfo)) {
                for (const auto& session : sessionsList) {
                    std::string remoteDeviceId = session.GetDestinationDeviceId();
                    TargetComponent targetComponent = session.GetTargetComponent();
                    // the same session can connect different types component on the same device
                    std::string key = remoteDeviceId + std::to_string(static_cast<int32_t>(targetComponent));
                    // just notify one time for same remote device
                    auto [_, isSuccess] = processedDeviceSet.emplace(key);
                    if (isSuccess) {
                        ProcessDiedNotifyInfo notifyInfo = { remoteDeviceId, callerInfo, targetComponent };
                        notifyList.push_back(notifyInfo);
                    }
                }
                DecreaseConnectLocked(callerInfo.uid);
                if (iter->first != nullptr) {
                    iter->first->RemoveDeathRecipient(connectDeathRecipient_);
                }
                ReportDistributedComponentChange(callerInfo, DISTRIBUTED_COMPONENT_REMOVE,
                    IDistributedSched::CONNECT, IDistributedSched::CALLER);
                iter = distributedConnectAbilityMap_.erase(iter);
            } else {
                iter++;
            }
        }
    }
    NotifyProcessDiedAll(notifyList);
}

void DistributedSchedService::NotifyProcessDiedAll(const std::list<ProcessDiedNotifyInfo>& notifyList)
{
    for (auto it = notifyList.begin(); it != notifyList.end(); ++it) {
        NotifyProcessDied(it->remoteDeviceId, it->callerInfo, it->targetComponent);
    }
}

void DistributedSchedService::NotifyProcessDied(const std::string& remoteDeviceId,
    const CallerInfo& callerInfo, TargetComponent targetComponent)
{
    if (targetComponent != TargetComponent::HARMONY_COMPONENT) {
        HILOGD("NotifyProcessDied not harmony component, no need to notify");
        return;
    }

    sptr<IDistributedSched> remoteDms = GetRemoteDms(remoteDeviceId);
    if (remoteDms == nullptr) {
        HILOGE("NotifyProcessDied get remote dms failed");
        return;
    }
    int32_t result = remoteDms->NotifyProcessDiedFromRemote(callerInfo);
    HILOGI("NotifyProcessDied result is %{public}d", result);
}

ConnectAbilitySession::ConnectAbilitySession(const std::string& sourceDeviceId, const std::string& destinationDeviceId,
    const CallerInfo& callerInfo, TargetComponent targetComponent)
    : sourceDeviceId_(sourceDeviceId),
      destinationDeviceId_(destinationDeviceId),
      callerInfo_(callerInfo),
      targetComponent_(targetComponent)
{
}

void ConnectAbilitySession::AddElement(const AppExecFwk::ElementName& element)
{
    for (const auto& elementName : elementsList_) {
        if (elementName == element) {
            return;
        }
    }
    elementsList_.emplace_back(element);
}

bool ConnectAbilitySession::IsSameCaller(const CallerInfo& callerInfo)
{
    return (callerInfo.uid == callerInfo_.uid &&
            callerInfo.pid == callerInfo_.pid &&
            callerInfo.sourceDeviceId == callerInfo_.sourceDeviceId &&
            callerInfo.callerType == callerInfo_.callerType);
}

void DistributedSchedService::DumpConnectInfo(std::string& info)
{
    std::lock_guard<std::mutex> autoLock(distributedLock_);
    info += "connected remote abilities:\n";
    if (!distributedConnectAbilityMap_.empty()) {
        for (const auto& distributedConnect : distributedConnectAbilityMap_) {
            const std::list<ConnectAbilitySession> sessionsList = distributedConnect.second;
            DumpSessionsLocked(sessionsList, info);
        }
    } else {
        info += "  <none info>\n";
    }
}

void DistributedSchedService::DumpSessionsLocked(const std::list<ConnectAbilitySession>& sessionsList,
    std::string& info)
{
    for (const auto& session : sessionsList) {
        info += "  ";
        info += "SourceDeviceId: ";
        info += session.GetSourceDeviceId();
        info += ", ";
        info += "DestinationDeviceId: ";
        info += session.GetDestinationDeviceId();
        info += ", ";
        info += "CallerUid: ";
        info += std::to_string(session.GetCallerInfo().uid);
        info += ", ";
        info += "CallerPid: ";
        info += std::to_string(session.GetCallerInfo().pid);
        info += ", ";
        info += "CallerType: ";
        info += std::to_string(session.GetCallerInfo().callerType);
        DumpElementLocked(session.GetElementsList(), info);
        info += "\n";
    }
}

void DistributedSchedService::DumpElementLocked(const std::list<AppExecFwk::ElementName>& elementsList,
    std::string& info)
{
    for (const auto& element : elementsList) {
        info += ", ";
        info += "BundleName: ";
        info += element.GetBundleName();
        info += ", ";
        info += "AbilityName: ";
        info += element.GetAbilityName();
    }
}

#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
int32_t DistributedSchedService::GetMissionInfos(const std::string& deviceId, int32_t numMissions,
    std::vector<MissionInfo>& missionInfos)
{
    return DistributedSchedMissionManager::GetInstance().GetMissionInfos(deviceId, numMissions, missionInfos);
}

int32_t DistributedSchedService::NotifyMissionsChangedFromRemote(const std::vector<DstbMissionInfo>& missionInfos,
    const CallerInfo& callerInfo)
{
    return DistributedSchedMissionManager::GetInstance()
        .NotifyMissionsChangedFromRemote(callerInfo, missionInfos);
}

int32_t DistributedSchedService::GetRemoteMissionSnapshotInfo(const std::string& networkId, int32_t missionId,
    std::unique_ptr<MissionSnapshot>& missionSnapshot)
{
    return DistributedSchedMissionManager::GetInstance()
        .GetRemoteMissionSnapshotInfo(networkId, missionId, missionSnapshot);
}

int32_t DistributedSchedService::RegisterMissionListener(const std::u16string& devId,
    const sptr<IRemoteObject>& obj)
{
    return DistributedSchedMissionManager::GetInstance().RegisterMissionListener(devId, obj);
}

int32_t DistributedSchedService::RegisterOnListener(const std::string& type,
    const sptr<IRemoteObject>& obj)
{
    return DMSContinueRecvMgr::GetInstance().RegisterOnListener(type, obj);
}

int32_t DistributedSchedService::RegisterOffListener(const std::string& type,
    const sptr<IRemoteObject>& obj)
{
    return DMSContinueRecvMgr::GetInstance().RegisterOffListener(type, obj);
}

int32_t DistributedSchedService::UnRegisterMissionListener(const std::u16string& devId,
    const sptr<IRemoteObject>& obj)
{
    return DistributedSchedMissionManager::GetInstance().UnRegisterMissionListener(devId, obj);
}

int32_t DistributedSchedService::StartSyncRemoteMissions(const std::string& devId, bool fixConflict, int64_t tag)
{
    return DistributedSchedMissionManager::GetInstance().StartSyncRemoteMissions(devId, fixConflict, tag);
}

int32_t DistributedSchedService::StopSyncRemoteMissions(const std::string& devId)
{
    return DistributedSchedMissionManager::GetInstance().StopSyncRemoteMissions(devId, false, true);
}

int32_t DistributedSchedService::StartSyncMissionsFromRemote(const CallerInfo& callerInfo,
    std::vector<DstbMissionInfo>& missionInfos)
{
    return DistributedSchedMissionManager::GetInstance().StartSyncMissionsFromRemote(callerInfo, missionInfos);
}

int32_t DistributedSchedService::StopSyncMissionsFromRemote(const CallerInfo& callerInfo)
{
    DistributedSchedMissionManager::GetInstance().StopSyncMissionsFromRemote(callerInfo.sourceDeviceId);
    return ERR_NONE;
}

int32_t DistributedSchedService::SetMissionContinueState(int32_t missionId, const AAFwk::ContinueState &state)
{
    return DMSContinueSendMgr::GetInstance().SetMissionContinueState(missionId, state);
}
#endif

int32_t DistributedSchedService::RegisterDSchedEventListener(const DSchedEventType& type,
    const sptr<IRemoteObject>& callback)
{
    if (dschedContinuation_ == nullptr || collaborateCbMgr_ == nullptr) {
        HILOGE("object null!");
        return INVALID_PARAMETERS_ERR;
    }
    bool ret = false;
    switch (type) {
        case DMS_CONTINUE:
            ret = dschedContinuation_->PushCallback(callback);
            break;
        case DMS_COLLABORATION:
            ret = collaborateCbMgr_->PushCallback(callback);
            break;
        case DMS_ALL:
            ret = dschedContinuation_->PushCallback(callback) && collaborateCbMgr_->PushCallback(callback);
            break;
        default:
            HILOGE("Not support register Dms event listener with event type: %{public}d.", type);
            return INVALID_PARAMETERS_ERR;
    }

    if (!ret) {
        HILOGE("The callback does not exist, type: %{public}d", type);
        return CALLBACK_HAS_NOT_REGISTERED;
    }
    HILOGD("Push %{public}d callback success.", type);
    return ERR_OK;
}

int32_t DistributedSchedService::UnRegisterDSchedEventListener(const DSchedEventType& type,
    const sptr<IRemoteObject>& callback)
{
    if (dschedContinuation_ == nullptr || collaborateCbMgr_ == nullptr) {
        HILOGE("object null!");
        return INVALID_PARAMETERS_ERR;
    }
    bool result = 0;
    switch (type) {
        case DMS_CONTINUE:
            result = dschedContinuation_->CleanupCallback(callback);
            break;
        case DMS_COLLABORATION:
            result = collaborateCbMgr_->CleanupCallback(callback);
            break;
        case DMS_ALL:
            result = dschedContinuation_->CleanupCallback(callback) && collaborateCbMgr_->CleanupCallback(callback);
            break;
        default:
            break;
    }

    if (!result) {
        HILOGI("The callback does not exist,type: %{public}d", type);
    } else {
        HILOGI("Clearing the callback succeeded.");
    }
    return 0;
}

int32_t DistributedSchedService::GetContinueInfo(std::string& dstNetworkId, std::string& srcNetworkId)
{
    HILOGI("GetContinueInfo called");
    if (dschedContinuation_ == nullptr) {
        HILOGE("continuation object null!");
        return INVALID_PARAMETERS_ERR;
    }
    dstNetworkId = dschedContinuation_->continueInfo_.dstNetworkId_;
    srcNetworkId = dschedContinuation_->continueInfo_.srcNetworkId_;
    HILOGI("GetContinueInfo dstNetworkId: %{public}s, srcNetworkId: %{public}s",
        GetAnonymStr(dstNetworkId).c_str(), GetAnonymStr(srcNetworkId).c_str());
    return 0;
}

int32_t DistributedSchedService::GetDSchedEventInfo(const DSchedEventType &type, std::vector<EventNotify> &events)
{
    int32_t callingUid = CheckCallingUid() ? DEFAULT_REQUEST_CODE : IPCSkeleton::GetCallingUid();
    HILOGI("GetDSchedEventInfo called, uid %{public}d, dms eventType %{public}d.", callingUid, type);
    switch (type) {
        case DMS_CONTINUE:
            GetContinueEventInfo(callingUid, events);
            break;
        case DMS_COLLABORATION:
            GetCollaborateEventInfo(callingUid, events);
            break;
        case DMS_ALL:
            GetContinueEventInfo(callingUid, events);
            GetCollaborateEventInfo(callingUid, events);
            break;
        default:
            HILOGI("Get dms event info not support eventType %{public}d.", type);
            return INVALID_PARAMETERS_ERR;
    }
    HILOGI("GetDSchedEventInfo end, uid %{public}d, eventType %{public}d, events size %{public}zu.",
        callingUid, type, events.size());
    return ERR_OK;
}

bool DistributedSchedService::CheckCallingUid()
{
    // never allow non-system uid for distributed request
    auto callingUid = IPCSkeleton::GetCallingUid();
    return callingUid < HID_HAP;
}

void DistributedSchedService::GetContinueEventInfo(int32_t callingUid, std::vector<EventNotify> &events)
{
    if (callingUid == DEFAULT_REQUEST_CODE && dschedContinuation_ != nullptr) {
        events.emplace_back(dschedContinuation_->continueEvent_);
        return;
    }

    std::vector<std::string> bundleNames;
    if (!BundleManagerInternal::GetBundleNameListFromBms(callingUid, bundleNames)) {
        HILOGE("Get bundle name from Bms failed");
        return;
    }
    for (const auto &bundleName : bundleNames) {
        HILOGD("Get bundle name %{public}s from Bms.", bundleName.c_str());
        if (bundleName == dschedContinuation_->continueEvent_.srcBundleName_ ||
            bundleName == dschedContinuation_->continueEvent_.destBundleName_) {
            events.emplace_back(dschedContinuation_->continueEvent_);
        }
    }
}

void DistributedSchedService::GetCollaborateEventInfo(int32_t callingUid, std::vector<EventNotify> &events)
{
    if (callingUid == DEFAULT_REQUEST_CODE) {
        GetCollaborateEventsByCallers(callingUid, "", events);
        GetCollaborateEventsByCallees(callingUid, "", events);
        return;
    }

    std::string callingBundleName;
    if (!BundleManagerInternal::GetSpecifyBundleNameFromBms(callingUid, callingBundleName)) {
        HILOGE("Get specify bundle name for from Bms fail, uid %{public}d.", callingUid);
        return;
    }
    GetCollaborateEventsByCallers(callingUid, callingBundleName, events);
    GetCollaborateEventsByCallees(callingUid, callingBundleName, events);
}

void DistributedSchedService::GetCollaborateEventsByCallers(int32_t callingUid, const std::string &callingBundleName,
    std::vector<EventNotify> &events)
{
    std::lock_guard<std::mutex> autoLock(callerLock_);
    for (const auto &iter : callerMap_) {
        for (const auto &connectSession : iter.second) {
            auto bundleNames = connectSession.GetCallerInfo().bundleNames;
            if (callingUid != DEFAULT_REQUEST_CODE && callingUid != connectSession.GetCallerInfo().uid &&
                std::count(bundleNames.begin(), bundleNames.end(), callingBundleName) == 0) {
                HILOGE("Connect session callerInfo uid %{public}d is different from callingUid %{public}d, "
                    "callingbundle %{public}s.", connectSession.GetCallerInfo().uid,
                    callingUid, callingBundleName.c_str());
                continue;
            }
            for (const auto &element : connectSession.GetElementsList()) {
                EventNotify tempEvent;
                GetCurSrcCollaborateEvent(connectSession.GetCallerInfo(), element,
                    DMS_DSCHED_EVENT_PROCESSING, ERR_OK, tempEvent);
                events.emplace_back(tempEvent);
            }
        }
    }
}

void DistributedSchedService::GetCollaborateEventsByCallees(int32_t callingUid, const std::string &callingBundleName,
    std::vector<EventNotify> &events)
{
    std::lock_guard<std::mutex> autoLock(calleeLock_);
    for (const auto &iter : calleeMap_) {
        if (callingUid != DEFAULT_REQUEST_CODE && callingBundleName != iter.second.element.GetBundleName()) {
            HILOGE("Connect session calleeInfo destBundleName %{public}s is different from "
                "callingBundleName %{public}s, callingUid %{public}d.", iter.second.element.GetBundleName().c_str(),
                callingBundleName.c_str(), callingUid);
            continue;
        }

        EventNotify tempEvent;
        GetCurDestCollaborateEvent(iter.second.callerInfo, iter.second.element,
            DMS_DSCHED_EVENT_PROCESSING, ERR_OK, tempEvent);
        events.emplace_back(tempEvent);
    }
}

void CallerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    HILOGI("CallerDeathRecipient OnRemoteDied called");
    DistributedSchedAdapter::GetInstance().ProcessCallerDied(remote.promote(), deviceType_);
}

int32_t DistributedSchedService::SetCallerInfo(
    int32_t callerUid, std::string localDeviceId, uint32_t accessToken, CallerInfo& callerInfo)
{
    callerInfo.uid = callerUid;
    callerInfo.callerType = CALLER_TYPE_HARMONY;
    callerInfo.sourceDeviceId = localDeviceId;
    callerInfo.accessToken = accessToken;
    if (!BundleManagerInternal::GetCallerAppIdFromBms(callerInfo.uid, callerInfo.callerAppId)) {
        HILOGE("GetCallerAppIdFromBms failed");
        return INVALID_PARAMETERS_ERR;
    }
    if (!BundleManagerInternal::GetBundleNameListFromBms(callerInfo.uid, callerInfo.bundleNames)) {
        HILOGE("GetBundleNameListFromBms failed");
        return INVALID_PARAMETERS_ERR;
    }
    callerInfo.extraInfoJson[DMS_VERSION_ID] = DMS_VERSION;
    return ERR_OK;
}

int32_t DistributedSchedService::StartRemoteFreeInstall(const OHOS::AAFwk::Want& want, int32_t callerUid,
    int32_t requestCode, uint32_t accessToken, const sptr<IRemoteObject>& callback)
{
    HILOGI("called");
    std::string localDeviceId;
    std::string deviceId = want.GetElement().GetDeviceID();
    if (!GetLocalDeviceId(localDeviceId) || !CheckDeviceId(localDeviceId, deviceId)) {
        HILOGE("check deviceId failed");
        return INVALID_PARAMETERS_ERR;
    }
    sptr<IDistributedSched> remoteDms = GetRemoteDms(deviceId);
    if (remoteDms == nullptr) {
        HILOGE("get remoteDms failed");
        return INVALID_PARAMETERS_ERR;
    }
    if (dmsCallbackTask_ == nullptr) {
        HILOGE("callbackTask object null!");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    int64_t taskId = dmsCallbackTask_->GenerateTaskId();
    LaunchType launchType = LaunchType::FREEINSTALL_START;
    if (((want.GetFlags() & AAFwk::Want::FLAG_ABILITY_CONTINUATION) != 0)) {
        launchType = LaunchType::FREEINSTALL_CONTINUE;
    }
    if (dmsCallbackTask_->PushCallback(taskId, callback, deviceId, launchType, want) != ERR_OK) {
        HILOGE("Push callback failed!");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    if (launchType == LaunchType::FREEINSTALL_CONTINUE) {
        dmsCallbackTask_->SetContinuationMissionMap(taskId, want.GetIntParam("sessionId", -1));
    }

    CallerInfo callerInfo;
    if (SetCallerInfo(callerUid, localDeviceId, accessToken, callerInfo) != ERR_OK) {
        HILOGE("SetCallerInfo failed");
        return INVALID_PARAMETERS_ERR;
    }
    AccountInfo accountInfo = {};
    if ((DistributedSchedPermission::GetInstance().GetAccountInfo(deviceId, callerInfo, accountInfo)) != ERR_OK) {
        HILOGE("GetAccountInfo failed");
        return INVALID_PARAMETERS_ERR;
    }
    AAFwk::Want* newWant = const_cast<Want*>(&want);
    newWant->SetParam(DMS_SRC_NETWORK_ID, localDeviceId);
    FreeInstallInfo info = {*newWant, requestCode, callerInfo, accountInfo};
    int32_t result = remoteDms->StartFreeInstallFromRemote(info, taskId);
    if (result != ERR_OK) {
        HILOGE("result = %{public}d", result);
        CallbackTaskItem item = dmsCallbackTask_->PopCallback(taskId);
        NotifyFreeInstallResult(item, result);
    }
    return result;
}

int32_t DistributedSchedService::StartFreeInstallFromRemote(const FreeInstallInfo& info, int64_t taskId)
{
    HILOGI("begin taskId : %{public} " PRId64 ". ", taskId);
    std::string localDeviceId;
    std::string deviceId = info.want.GetElement().GetDeviceID();
    if (!GetLocalDeviceId(localDeviceId) ||
        !CheckDeviceIdFromRemote(localDeviceId, deviceId, info.callerInfo.sourceDeviceId)) {
        HILOGE("check deviceId failed");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->Connect();
    if (err != ERR_OK) {
        HILOGE("connect ability server failed %{public}d", err);
        return err;
    }
    int32_t activeAccountId = -1;
    err = QueryOsAccount(activeAccountId);
    if (err != ERR_OK) {
        return err;
    }

    sptr<DmsFreeInstallCallback> callback(new DmsFreeInstallCallback(taskId, info));
    err = AAFwk::AbilityManagerClient::GetInstance()->FreeInstallAbilityFromRemote(
        info.want, callback, activeAccountId, info.requestCode);
    if (err != ERR_OK) {
        HILOGE("FreeInstallAbilityFromRemote failed %{public}d", err);
    }
    return err;
}

int32_t DistributedSchedService::NotifyCompleteFreeInstall(
    const FreeInstallInfo& info, int64_t taskId, int32_t resultCode)
{
    HILOGI("taskId = %{public}" PRId64 ".", taskId);
    if (taskId <= 0) {
        HILOGE("taskId invalid!");
        return INVALID_PARAMETERS_ERR;
    }
    if (resultCode != ERR_OK) {
        HILOGE("free install failed, resultCode : %{public}d", resultCode);
        return HandleRemoteNotify(info, taskId, resultCode);
    }
    int32_t result = StartLocalAbility(info, taskId, resultCode);
    return HandleRemoteNotify(info, taskId, result);
}

int32_t DistributedSchedService::StartLocalAbility(const FreeInstallInfo& info, int64_t taskId, int32_t resultCode)
{
    std::string localDeviceId;
    if (!GetLocalDeviceId(localDeviceId)) {
        HILOGE("get local deviceId failed");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    int32_t result = CheckTargetPermission(info.want, info.callerInfo, info.accountInfo, START_PERMISSION, true);
    if (result != ERR_OK) {
        HILOGE("CheckTargetPermission failed!!");
        return result;
    }

    AAFwk::Want* want = const_cast<Want*>(&info.want);
    want->RemoveFlags(OHOS::AAFwk::Want::FLAG_INSTALL_ON_DEMAND);
    return StartAbility(*want, info.requestCode);
}

int32_t DistributedSchedService::StartAbility(const OHOS::AAFwk::Want& want, int32_t requestCode)
{
    if (!SwitchStatusDependency::GetInstance().IsContinueSwitchOn()) {
        HILOGE("ContinueSwitch status is off");
        return DMS_PERMISSION_DENIED;
    }
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->Connect();
    if (err != ERR_OK) {
        HILOGE("connect ability server failed %{public}d", err);
        return err;
    }
    int32_t activeAccountId = -1;
    err = QueryOsAccount(activeAccountId);
    if (err != ERR_OK) {
        return err;
    }
    if (want.GetBoolParam(Want::PARAM_RESV_FOR_RESULT, false)) {
        HILOGI("StartAbilityForResult start, flag is %{public}d", want.GetFlags());
        sptr<IRemoteObject> dmsTokenCallback(new DmsTokenCallback());
        err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, dmsTokenCallback, requestCode,
            activeAccountId);
    } else {
        HILOGI("StartAbility start, flag is %{public}d", want.GetFlags());
        if (DmsContinueTime::GetInstance().GetPull()) {
            int64_t begin = GetTickCount();
            DmsContinueTime::GetInstance().SetDurationBegin(DMSDURATION_STARTABILITY, begin);
        }
        DmsContinueTime::GetInstance().SetDstAbilityName(want.GetElement().GetAbilityName());
        DmsContinueTime::GetInstance().SetDstBundleName(want.GetElement().GetBundleName());
        DmsRadar::GetInstance().ClickIconDmsStartAbility("StartAbility", err);
        err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, requestCode, activeAccountId);
    }
    if (err != ERR_OK) {
        HILOGE("StartAbility failed %{public}d", err);
    }
    return err;
}

int32_t DistributedSchedService::HandleRemoteNotify(const FreeInstallInfo& info, int64_t taskId, int32_t resultCode)
{
    HILOGI("begin taskId = %{public}" PRId64 ", resultCode = %{public}d", taskId, resultCode);
    sptr<IDistributedSched> remoteDms = GetRemoteDms(info.callerInfo.sourceDeviceId);
    if (remoteDms == nullptr) {
        HILOGE("get remote dms null!");
        return INVALID_PARAMETERS_ERR;
    }
    if (taskId <= 0) {
        HILOGE("taskId invalid!");
        return INVALID_PARAMETERS_ERR;
    }
    return remoteDms->NotifyCompleteFreeInstallFromRemote(taskId, resultCode);
}

int32_t DistributedSchedService::NotifyCompleteFreeInstallFromRemote(int64_t taskId, int32_t resultCode)
{
    HILOGI("begin taskId = %{public}" PRId64 ", resultCode = %{public}d", taskId, resultCode);
    if (dmsCallbackTask_ == nullptr || dschedContinuation_ == nullptr) {
        HILOGE("callbackTask object null!");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    LaunchType launchType = dmsCallbackTask_->GetLaunchType(taskId);
    CallbackTaskItem item = dmsCallbackTask_->PopCallback(taskId);
    if (launchType == LaunchType::FREEINSTALL_START) {
        return NotifyFreeInstallResult(item, resultCode);
    }

    if (resultCode == ERR_OK) {
        HILOGD("continue free install success, waiting for continue result callback.");
        dmsCallbackTask_->PopContinuationMissionMap(taskId);
        return ERR_OK;
    }

    int32_t missionId = dmsCallbackTask_->GetContinuaionMissionId(taskId);
    NotifyContinuationCallbackResult(missionId, CONTINUE_FREE_INSTALL_FAILED);
    dmsCallbackTask_->PopContinuationMissionMap(taskId);
    return ERR_OK;
}

int32_t DistributedSchedService::NotifyFreeInstallResult(const CallbackTaskItem item, int32_t resultCode)
{
    HILOGI("taskId : %{public} " PRId64 ". ", item.taskId);
    if (item.callback == nullptr) {
        HILOGE("item callback null!");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(ATOMIC_SERVICE_STATUS_CALLBACK_TOKEN)) {
        HILOGE("Write interface token failed.");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    if (!data.WriteInt32(resultCode)) {
        HILOGE("Write resultCode error.");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    if (!data.WriteParcelable(&item.want)) {
        HILOGE("Write want error.");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    int32_t userId = 0;
    if (!data.WriteInt32(userId)) {
        HILOGE("Write userId error.");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    return item.callback->SendRequest(IASS_CALLBACK_ON_REMOTE_FREE_INSTALL_DONE, data, reply, option);
}

bool DistributedSchedService::RegisterAppStateObserver(const OHOS::AAFwk::Want& want, const CallerInfo& callerInfo,
    const sptr<IRemoteObject>& srcConnect, const sptr<IRemoteObject>& callbackWrapper)
{
    HILOGD("register app state observer called");
    int32_t connectToken = want.GetIntParam(DMS_CONNECT_TOKEN, DEFAULT_DMS_CONNECT_TOKEN);
    HILOGD("Get connectToken = %{private}s", GetAnonymStr(std::to_string(connectToken)).c_str());
    if (connectToken == DEFAULT_DMS_CONNECT_TOKEN) {
        return false;
    }
    sptr<AppExecFwk::IAppMgr> appObject = GetAppManager();
    if (appObject == nullptr) {
        HILOGE("failed to get app manager service");
        return false;
    }
    sptr<AppStateObserver> appStateObserver;
    std::string bundleName = want.GetElement().GetBundleName();
    {
        std::lock_guard<std::mutex> autoLock(registerMutex_);
        if (!bundleNameMap_.count(bundleName)) {
            std::vector<std::string> bundleNameList = {bundleName};
            appStateObserver = sptr<AppStateObserver>(new (std::nothrow) AppStateObserver());
            bundleNameMap_[bundleName] = appStateObserver;
            int ret = appObject->RegisterApplicationStateObserver(appStateObserver, bundleNameList);
            if (ret != ERR_OK) {
                HILOGE("failed to register application state observer, ret = %{public}d", ret);
                return false;
            }
        }
        appStateObserver = bundleNameMap_[bundleName];
    }
    HILOGI("register application state observer success");
    {
        std::lock_guard<std::mutex> autoLock(observerLock_);
        Want* newWant = const_cast<Want*>(&want);
        newWant->RemoveParam(DMS_MISSION_ID);
        newWant->RemoveParam(DMS_CONNECT_TOKEN);
        observerMap_[callbackWrapper] = {appStateObserver, callerInfo.sourceDeviceId, connectToken,
            want.GetElement().GetBundleName(), want.GetElement().GetAbilityName(), srcConnect};
        HILOGI("add observerMap_ success");
    }
    return true;
}

void DistributedSchedService::UnregisterAppStateObserver(const sptr<IRemoteObject>& callbackWrapper)
{
    HILOGD("unregister app state observer called");
    if (callbackWrapper == nullptr) {
        HILOGD("callbackWrapper is nullptr");
        return;
    }
    bool unRegisterFlag = true;
    std::string bundleName;
    sptr<AppStateObserver> appStateObserver;
    {
        std::lock_guard<std::mutex> autoLock(observerLock_);
        auto it = observerMap_.find(callbackWrapper);
        if (it == observerMap_.end()) {
            HILOGE("state observer not found");
            return;
        }
        appStateObserver = it->second.appStateObserver;
        bundleName = it->second.dstBundleName;
        observerMap_.erase(it);
        for (auto iter = observerMap_.begin(); iter != observerMap_.end(); iter++) {
            if (iter->second.dstBundleName == bundleName) {
                unRegisterFlag = false;
                break;
            }
        }
        HILOGI("remove app state observer success");
    }
    if (unRegisterFlag) {
        {
            std::lock_guard<std::mutex> autoLock(registerMutex_);
            bundleNameMap_.erase(bundleName);
        }
        sptr<AppExecFwk::IAppMgr> appObject = GetAppManager();
        if (appObject == nullptr) {
            HILOGE("failed to get app manager service");
            return;
        }
        int ret = appObject->UnregisterApplicationStateObserver(appStateObserver);
        if (ret != ERR_OK) {
            HILOGE("failed to unregister application state observer, ret = %{public}d", ret);
            return;
        }
    }
    HILOGI("unregister application state observer success");
}

sptr<AppExecFwk::IAppMgr> DistributedSchedService::GetAppManager()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        HILOGE("system ability manager is nullptr.");
        return nullptr;
    }

    sptr<AppExecFwk::IAppMgr> appObject =
        iface_cast<AppExecFwk::IAppMgr>(samgr->GetSystemAbility(APP_MGR_SERVICE_ID));
    if (appObject == nullptr) {
        HILOGE("failed to get app manager service");
        return nullptr;
    }
    return appObject;
}

int32_t DistributedSchedService::NotifyStateChanged(int32_t abilityState, AppExecFwk::ElementName& element,
    const sptr<IRemoteObject>& token)
{
    std::string srcDeviceId = "";
    int32_t connectToken = 0;
    {
        std::lock_guard<std::mutex> autoLock(observerLock_);
        for (auto iter = observerMap_.begin(); iter != observerMap_.end(); iter++) {
            if (iter->second.dstBundleName == element.GetBundleName() &&
                iter->second.dstAbilityName == element.GetAbilityName() && token == iter->second.token) {
                srcDeviceId = iter->second.srcDeviceId;
                connectToken = iter->second.connectToken;
                HILOGD("get srcDeviceId and missionId success");
                break;
            }
        }
    }
    HILOGD("Get connectToken = %{private}s", GetAnonymStr(std::to_string(connectToken)).c_str());
    std::string localDeviceId;
    if (!GetLocalDeviceId(localDeviceId) || !CheckDeviceId(localDeviceId, srcDeviceId)) {
        HILOGE("check deviceId failed");
        return INVALID_PARAMETERS_ERR;
    }
    sptr<IDistributedSched> remoteDms = GetRemoteDms(srcDeviceId);
    if (remoteDms == nullptr) {
        HILOGE("get remoteDms failed");
        return INVALID_PARAMETERS_ERR;
    }
    element.SetDeviceID(localDeviceId);
    return remoteDms->NotifyStateChangedFromRemote(abilityState, connectToken, element);
}

int32_t DistributedSchedService::NotifyStateChangedFromRemote(int32_t abilityState, int32_t connectToken,
    const AppExecFwk::ElementName& element)
{
    HILOGD("Get connectToken = %{private}s", GetAnonymStr(std::to_string(connectToken)).c_str());
    sptr<IRemoteObject> connect;
    {
        std::lock_guard<std::mutex> autoLock(callLock_);
        for (auto iter = callMap_.begin(); iter != callMap_.end(); iter++) {
            if (iter->second.connectToken == connectToken) {
                connect = iter->first;
                break;
            }
        }
        HILOGD("get connect success");
    }
    if (connect == nullptr) {
        HILOGE("NotifyStateChangedFromRemote connect is null");
        return INVALID_PARAMETERS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(CONNECTION_CALLBACK_INTERFACE_TOKEN)) {
        HILOGE("Write interface token failed.");
        return INVALID_PARAMETERS_ERR;
    }
    PARCEL_WRITE_HELPER(data, Parcelable, &element);
    PARCEL_WRITE_HELPER(data, Int32, abilityState);
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    HILOGD("ON_REMOTE_STATE_CHANGED start");
    int32_t result = connect->SendRequest(IAbilityConnection::ON_REMOTE_STATE_CHANGED, data, reply, option);
    HILOGD("ON_REMOTE_STATE_CHANGED end, %{public}d", result);
    return ERR_OK;
}

int32_t DistributedSchedService::CheckTargetPermission(const OHOS::AAFwk::Want& want,
    const CallerInfo& callerInfo, const AccountInfo& accountInfo, int32_t flag,
    bool needQueryExtension)
{
    DistributedSchedPermission& permissionInstance = DistributedSchedPermission::GetInstance();
    AppExecFwk::AbilityInfo targetAbility;
    bool result = permissionInstance.GetTargetAbility(want, targetAbility, needQueryExtension);
    if (!result) {
        HILOGE("GetTargetAbility can not find the target ability");
        return INVALID_PARAMETERS_ERR;
    }
    HILOGD("target ability info bundleName:%{public}s abilityName:%{public}s visible:%{public}d",
        targetAbility.bundleName.c_str(), targetAbility.name.c_str(), targetAbility.visible);
    HILOGD("callerType:%{public}d accountType:%{public}d callerUid:%{public}d AccessTokenID:%{public}s",
        callerInfo.callerType, accountInfo.accountType, callerInfo.uid,
        GetAnonymStr(std::to_string(callerInfo.accessToken)).c_str());
    if (flag == START_PERMISSION) {
        HILOGD("start CheckStartPermission");
        return permissionInstance.CheckStartPermission(want, callerInfo, accountInfo, targetAbility, true);
    } else if (flag == CALL_PERMISSION) {
        HILOGD("Collaboration start check get caller permission");
        return permissionInstance.CheckGetCallerPermission(want, callerInfo, accountInfo, targetAbility);
    } else if (flag == SEND_RESULT_PERMISSION) {
        HILOGD("Collaboration start check send result permission");
        return permissionInstance.CheckSendResultPermission(want, callerInfo, accountInfo, targetAbility);
    }
    HILOGE("CheckTargetPermission denied!!");
    return DMS_PERMISSION_DENIED;
}

int32_t DistributedSchedService::CheckTargetPermission4DiffBundle(const OHOS::AAFwk::Want& want,
    const CallerInfo& callerInfo, const AccountInfo& accountInfo, int32_t flag,
    bool needQueryExtension)
{
    DistributedSchedPermission& permissionInstance = DistributedSchedPermission::GetInstance();
    AppExecFwk::AbilityInfo targetAbility;
    bool result = permissionInstance.GetTargetAbility(want, targetAbility, needQueryExtension);
    if (!result) {
        HILOGE("GetTargetAbility can not find the target ability");
        return INVALID_PARAMETERS_ERR;
    }
    HILOGD("target ability info bundleName:%{public}s abilityName:%{public}s visible:%{public}d",
        targetAbility.bundleName.c_str(), targetAbility.name.c_str(), targetAbility.visible);
    HILOGD("callerType:%{public}d accountType:%{public}d callerUid:%{public}d AccessTokenID:%{public}s",
        callerInfo.callerType, accountInfo.accountType, callerInfo.uid,
        GetAnonymStr(std::to_string(callerInfo.accessToken)).c_str());
    if (flag == START_PERMISSION) {
        HILOGD("start CheckStartPermission");
        return permissionInstance.CheckStartPermission(want, callerInfo, accountInfo, targetAbility, false);
    } else if (flag == CALL_PERMISSION) {
        HILOGD("Collaboration start check get caller permission");
        return permissionInstance.CheckGetCallerPermission(want, callerInfo, accountInfo, targetAbility);
    } else if (flag == SEND_RESULT_PERMISSION) {
        HILOGD("Collaboration start check send result permission");
        return permissionInstance.CheckSendResultPermission(want, callerInfo, accountInfo, targetAbility);
    }
    HILOGE("CheckTargetPermission denied!!");
    return DMS_PERMISSION_DENIED;
}

int32_t DistributedSchedService::StopRemoteExtensionAbility(const OHOS::AAFwk::Want& want, int32_t callerUid,
    uint32_t accessToken, int32_t extensionType)
{
    std::string localDeviceId;
    std::string deviceId = want.GetDeviceId();
    if (!GetLocalDeviceId(localDeviceId) || !CheckDeviceId(localDeviceId, deviceId)) {
        HILOGE("CheckDeviceId failed");
        return INVALID_PARAMETERS_ERR;
    }
    sptr<IDistributedSched> remoteDms = GetRemoteDms(deviceId);
    if (remoteDms == nullptr) {
        HILOGE("GetRemoteDms failed");
        return INVALID_PARAMETERS_ERR;
    }
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = localDeviceId;
    callerInfo.uid = callerUid;
    callerInfo.accessToken = accessToken;
    if (!BundleManagerInternal::GetCallerAppIdFromBms(callerInfo.uid, callerInfo.callerAppId)) {
        HILOGE("GetCallerAppIdFromBms failed");
        return INVALID_PARAMETERS_ERR;
    }
    if (!BundleManagerInternal::GetBundleNameListFromBms(callerInfo.uid, callerInfo.bundleNames)) {
        HILOGE("GetBundleNameListFromBms failed");
        return INVALID_PARAMETERS_ERR;
    }
    AccountInfo accountInfo = {};
    if ((DistributedSchedPermission::GetInstance().GetAccountInfo(deviceId, callerInfo, accountInfo)) != ERR_OK) {
        HILOGE("GetAccountInfo failed");
        return INVALID_PARAMETERS_ERR;
    }
    AAFwk::Want remoteWant = want;
    remoteWant.SetParam(DMS_SRC_NETWORK_ID, localDeviceId);
    return remoteDms->StopExtensionAbilityFromRemote(remoteWant, callerInfo, accountInfo, extensionType);
}

int32_t DistributedSchedService::StopExtensionAbilityFromRemote(const OHOS::AAFwk::Want& remoteWant,
    const CallerInfo& callerInfo, const AccountInfo& accountInfo, int32_t extensionType)
{
    std::string localDeviceId;
    std::string destinationDeviceId = remoteWant.GetElement().GetDeviceID();
    if (!GetLocalDeviceId(localDeviceId) ||
        !CheckDeviceIdFromRemote(localDeviceId, destinationDeviceId, callerInfo.sourceDeviceId)) {
        HILOGE("check deviceId failed");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }

    int32_t permissionValid = CheckTargetPermission(remoteWant, callerInfo, accountInfo, START_PERMISSION, true);
    if (permissionValid != ERR_OK) {
        HILOGE("CheckTargetPermission failed!!");
        return DMS_PERMISSION_DENIED;
    }
    Want want = remoteWant;
    want.RemoveParam(DMS_SRC_NETWORK_ID);
    sptr<IRemoteObject> callerToken(new DmsTokenCallback());

    int32_t activeAccountId = -1;
    ErrCode err = QueryOsAccount(activeAccountId);
    if (err != ERR_OK) {
        return err;
    }

    return AAFwk::AbilityManagerClient::GetInstance()->StopExtensionAbility(
        want, callerToken, activeAccountId, static_cast<AppExecFwk::ExtensionAbilityType>(extensionType));
}

void DistributedSchedService::SetCleanMissionFlag(const OHOS::AAFwk::Want& want, int32_t missionId)
{
    auto value =  want.GetParams().GetParam(SUPPORT_CONTINUE_SOURCE_EXIT_KEY);
    IBoolean *ao = IBoolean::Query(value);
    bool isCleanMission = true;
    if (ao != nullptr) {
        isCleanMission = AAFwk::Boolean::Unbox(ao);
    }
    if (dschedContinuation_ == nullptr) {
        HILOGW("continuation object null!");
        return;
    }
    dschedContinuation_->SetCleanMissionFlag(missionId, isCleanMission);
}
} // namespace DistributedSchedule
} // namespace OHOS
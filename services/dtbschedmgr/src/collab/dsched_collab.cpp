/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <chrono>
#include <sys/prctl.h>
#include <thread>

#include "dsched_collab.h"

#include "ability_connection_wrapper_stub.h"
#include "ability_manager_client.h"
#include "bool_wrapper.h"
#include "bundle/bundle_manager_internal.h"
#include "distributed_sched_permission.h"
#include "dsched_collab_manager.h"
#include "dsched_transport_softbus_adapter.h"
#include "dtbschedmgr_device_info_storage.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "parcel_helper.h"
#include "screenlock_manager.h"
#include "string_wrapper.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace AAFwk;
namespace {
const std::string TAG = "DSchedCollab";
const std::string DMS_VERSION_ID = "dmsVersion";
const std::u16string NAPI_COLLAB_CALLBACK_INTERFACE_TOKEN = u"OHOS.DistributedCollab.IAbilityConnectionManager";
const std::string KEY_START_OPTION = "ohos.collabrate.key.start.option";
const std::string VALUE_START_OPTION_FOREGROUND = "ohos.collabrate.value.foreground";
const std::string VALUE_START_OPTION_BACKGROUND = "ohos.collabrate.value.background";

constexpr int32_t DSCHED_COLLAB_PROTOCOL_VERSION = 1;
constexpr int32_t NOTIFY_COLLAB_PREPARE_RESULT = 0;
constexpr int32_t NOTIFY_COLLAB_DISCONNECT = 1;
constexpr int32_t DMS_VERSION = 5;
constexpr int32_t START_PERMISSION = 0;
std::map<int32_t, std::string> CMDDATA = {
    {MIN_CMD, "MIN_CMD"},
    {SINK_START_CMD, "SINK_START_CMD"},
    {NOTIFY_RESULT_CMD, "NOTIFY_RESULT_CMD"},
    {DISCONNECT_CMD, "DISCONNECT_CMD"},
    {MAX_CMD, "MAX_CMD"},
};
std::map<int32_t, std::string> EVENTDATA = {
    {SOURCE_START_EVENT, "SOURCE_START_EVENT"},
    {NOTIFY_RESULT_EVENT, "NOTIFY_RESULT_EVENT"},
    {START_ABILITY_EVENT, "START_ABILITY_EVENT"},
    {NOTIFY_PREPARE_RESULT_EVENT, "NOTIFY_PREPARE_RESULT_EVENT"},
    {ERR_END_EVENT, "ERR_END_EVENT"},
    {END_EVENT, "END_EVENT"},
};
std::map<int32_t, std::string> STATEDATA = {
    {SOURCE_START_STATE, "SOURCE_START_STATE"},
    {SOURCE_WAIT_RESULT_STATE, "SOURCE_WAIT_RESULT_STATE"},
    {SOURCE_WAIT_END_STATE, "SOURCE_WAIT_END_STATE"},
    {SINK_START_STATE, "SINK_START_STATE"},
    {SINK_CONNECT_STATE, "SINK_CONNECT_STATE"},
    {SINK_WAIT_END_STATE, "SINK_WAIT_END_STATE"},
};
}

DSchedCollab::DSchedCollab(const std::string &collabToken, const DSchedCollabInfo &info)
{
    HILOGI("create");
    collabInfo_ = info;
    collabInfo_.collabToken_ = collabToken;
    collabInfo_.srcCollabVersion_ = DSCHED_COLLAB_PROTOCOL_VERSION;
    HILOGI("created successfully. collabInfo: %{public}s", collabInfo_.ToString().c_str());
}

DSchedCollab::DSchedCollab(std::shared_ptr<SinkStartCmd> startCmd, const int32_t &softbusSessionId)
{
    HILOGI("create by recvCmd");
    if (startCmd == nullptr) {
        HILOGE("startCmd is null");
        return;
    }
    collabInfo_.srcCollabSessionId_ = startCmd->srcCollabSessionId_;
    collabInfo_.collabToken_ = startCmd->collabToken_;
    collabInfo_.srcCollabVersion_ = startCmd->collabVersion_;
    collabInfo_.srcOpt_.needSendBigData_ = startCmd->needSendBigData_;
    collabInfo_.srcOpt_.needSendStream_ = startCmd->needSendStream_;
    collabInfo_.srcOpt_.needRecvStream_ = startCmd->needRecvStream_;
    collabInfo_.srcOpt_.startParams_ = startCmd->startParams_;
    collabInfo_.srcOpt_.messageParams_ = startCmd->messageParams_;
    collabInfo_.srcInfo_.pid_ = startCmd->srcPid_;
    collabInfo_.srcInfo_.uid_ = startCmd->srcUid_;
    collabInfo_.srcInfo_.accessToken_ = startCmd->srcAccessToken_;
    collabInfo_.srcInfo_.deviceId_ = startCmd->srcDeviceId_;
    collabInfo_.srcInfo_.bundleName_ = startCmd->srcBundleName_;
    collabInfo_.srcInfo_.abilityName_ = startCmd->srcAbilityName_;
    collabInfo_.srcInfo_.moduleName_ = startCmd->srcModuleName_;
    collabInfo_.srcInfo_.serverId_ = startCmd->srcServerId_;
    collabInfo_.sinkInfo_.deviceId_ = startCmd->sinkDeviceId_;
    collabInfo_.sinkInfo_.bundleName_ = startCmd->sinkBundleName_;
    collabInfo_.sinkInfo_.abilityName_ = startCmd->sinkAbilityName_;
    collabInfo_.sinkInfo_.moduleName_ = startCmd->sinkModuleName_;
    collabInfo_.sinkInfo_.serverId_ = startCmd->sinkServerId_;
    collabInfo_.srcAppVersion_ = startCmd->appVersion_;
    collabInfo_.callerInfo_ = startCmd->callerInfo_;
    collabInfo_.srcAccountInfo_ = startCmd->accountInfo_;
    collabInfo_.direction_ = COLLAB_SINK;
    softbusSessionId_ = softbusSessionId;

#ifdef OS_ACCOUNT_PART
    std::vector<int32_t> ids;
    int32_t ret = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (ret != ERR_OK || ids.empty()) {
        HILOGE("Get userId from active Os AccountIds fail, ret : %{public}d", ret);
        return;
    }
    collabInfo_.sinkUserId_ = ids[0];
#endif
    HILOGI("created successfully. collabInfo: %{public}s", collabInfo_.ToString().c_str());
}

DSchedCollab::~DSchedCollab()
{
    HILOGI("delete enter");
    UnregisterAbilityLifecycleObserver();
    if ((eventHandler_ != nullptr) && (eventHandler_->GetEventRunner() != nullptr)) {
        eventHandler_->GetEventRunner()->Stop();
    }
    eventThread_.join();
    eventHandler_ = nullptr;
    HILOGI("delete end");
}

int32_t DSchedCollab::Init()
{
    HILOGI("called");
    if (eventHandler_ != nullptr) {
        HILOGI("already inited, end.");
        return ERR_OK;
    }
    auto dCollab = std::shared_ptr<DSchedCollab>(shared_from_this());
    stateMachine_ = std::make_shared<DSchedCollabStateMachine>(dCollab);

    eventThread_ = std::thread(&DSchedCollab::StartEventHandler, this);
    std::unique_lock<std::mutex> lock(eventMutex_);
    eventCon_.wait(lock, [this] {
        return eventHandler_ != nullptr;
    });
    HILOGI("end");
    return ERR_OK;
}

void DSchedCollab::StartEventHandler()
{
    HILOGI("called");
    std::string eventThreadName = "DSchedCollab_EventHandler";
    prctl(PR_SET_NAME, eventThreadName.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    if (runner == nullptr) {
        HILOGE("continue start eventHandler failed.");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventHandler_ = std::make_shared<DSchedCollabEventHandler>(runner, shared_from_this());
    }
    eventCon_.notify_one();
    runner->Run();
}

int32_t DSchedCollab::PostSrcStartTask()
{
    HILOGI("called");
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    DSchedCollabEventType eventType = SOURCE_START_EVENT;
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType);
    if (!eventHandler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        HILOGE("send event type %{public}s fail", EVENTDATA[eventType].c_str());
        return COLLAB_SEND_EVENT_FAILED;
    }
    return ERR_OK;
}

int32_t DSchedCollab::PostSinkStartTask()
{
    HILOGI("called");
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    DSchedCollabEventType eventType = START_ABILITY_EVENT;
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType);
    if (!eventHandler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        HILOGE("send event type %{public}s fail", EVENTDATA[eventType].c_str());
        return COLLAB_SEND_EVENT_FAILED;
    }
    return ERR_OK;
}

int32_t DSchedCollab::PostSinkPrepareResultTask(const int32_t &result, const int32_t &collabSessionId,
    const std::string &socketName, const sptr<IRemoteObject> &clientCB)
{
    HILOGI("called, collabSessionId: %{public}d, result: %{public}d, socketName: %{public}s",
        collabSessionId, result, socketName.c_str());
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    collabInfo_.sinkCollabSessionId_ = collabSessionId;
    collabInfo_.sinkInfo_.socketName_ = socketName;
    collabInfo_.sinkClientCB_ = clientCB;
    auto data = std::make_shared<int32_t>(result);
    DSchedCollabEventType eventType = NOTIFY_PREPARE_RESULT_EVENT;
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    if (!eventHandler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        HILOGE("send event type %{public}s fail", EVENTDATA[eventType].c_str());
        return COLLAB_SEND_EVENT_FAILED;
    }
    HILOGI("end");
    return ERR_OK;
}

int32_t DSchedCollab::PostSrcResultTask(std::shared_ptr<NotifyResultCmd> notifyResultCmd)
{
    HILOGI("called, collabInfo %{public}s", collabInfo_.ToString().c_str());
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    if (!notifyResultCmd->abilityRejectReason_.empty()) {
        DSchedCollabEventType eventType = ABILITY_REJECT_EVENT;
        auto data = std::make_shared<std::string>(notifyResultCmd->abilityRejectReason_);
        auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
        if (!eventHandler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
            HILOGE("send event type %{public}s fail", EVENTDATA[eventType].c_str());
            return COLLAB_SEND_EVENT_FAILED;
        }
        return ERR_OK;
    }
    collabInfo_.sinkCollabSessionId_ = notifyResultCmd->sinkCollabSessionId_;
    collabInfo_.sinkInfo_.socketName_ = notifyResultCmd->sinkSocketName_;
    DSchedCollabEventType eventType = NOTIFY_RESULT_EVENT;
    auto data = std::make_shared<int32_t>(notifyResultCmd->result_);
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    if (!eventHandler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        HILOGE("send event type %{public}s fail", EVENTDATA[eventType].c_str());
        return COLLAB_SEND_EVENT_FAILED;
    }
    return ERR_OK;
}

int32_t DSchedCollab::PostErrEndTask(const int32_t &result)
{
    HILOGI("called, collabInfo %{public}s", collabInfo_.ToString().c_str());
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    DSchedCollabEventType eventType = ERR_END_EVENT;
    auto data = std::make_shared<int32_t>(result);
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    if (!eventHandler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        HILOGE("send event type %{public}s fail", EVENTDATA[eventType].c_str());
        return COLLAB_SEND_EVENT_FAILED;
    }
    return ERR_OK;
}

int32_t DSchedCollab::PostAbilityRejectTask(const std::string &reason)
{
    HILOGI("called, reason: %{public}s", reason.c_str());
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    DSchedCollabEventType eventType = ABILITY_REJECT_EVENT;
    auto data = std::make_shared<std::string>(reason);
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    if (!eventHandler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        HILOGE("send event type %{public}s fail", EVENTDATA[eventType].c_str());
        return COLLAB_SEND_EVENT_FAILED;
    }
    return ERR_OK;
}

int32_t DSchedCollab::PostEndTask()
{
    HILOGI("called, collabInfo %{public}s", collabInfo_.ToString().c_str());
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    DSchedCollabEventType eventType = END_EVENT;
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType);
    if (!eventHandler_->SendEvent(msgEvent, 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        HILOGE("send event type %{public}s fail", EVENTDATA[eventType].c_str());
        return COLLAB_SEND_EVENT_FAILED;
    }
    HILOGI("end");
    return ERR_OK;
}

void DSchedCollab::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr || stateMachine_ == nullptr) {
        HILOGE("event or state machine is null");
        return;
    }
    auto eventId = event->GetInnerEventId();
    HILOGI("process event: %{public}s with state %{public}s",
        EVENTDATA[eventId].c_str(), STATEDATA[stateMachine_->GetStateType()].c_str());
    int32_t ret = stateMachine_->Execute(event);
    if (ret != ERR_OK) {
        HILOGE("event %{public}s execute failed, ret %{public}d", EVENTDATA[eventId].c_str(), ret);
        PostErrEndTask(ret);
    }
    return;
}

int32_t DSchedCollab::ExeSrcStart()
{
    HILOGI("called");
    const std::string sinkDeviceId = collabInfo_.sinkInfo_.deviceId_;
    int32_t ret = DSchedTransportSoftbusAdapter::GetInstance().ConnectDevice(sinkDeviceId,
        softbusSessionId_, SERVICE_TYPE_COLLAB);
    if (ret != ERR_OK) {
        HILOGE("connect peer device failed, ret %{public}d", ret);
        return ret;
    }
    HILOGI("this connection is successful, softbusSessionId %{public}d", softbusSessionId_);

    auto startCmd = std::make_shared<SinkStartCmd>();
    ret = PackStartCmd(startCmd);
    if (ret != ERR_OK) {
        HILOGE("pack startCmd failed, ret %{public}d", ret);
        return ret;
    }
    ret = SendCommand(startCmd);
    if (ret != ERR_OK) {
        HILOGE("send startCmd failed, ret %{public}d", ret);
        return ret;
    }

    UpdateState(SOURCE_WAIT_RESULT_STATE);
    RegisterAbilityLifecycleObserver(collabInfo_.srcInfo_.bundleName_);
    HILOGI("end");
    return ERR_OK;
}

int32_t DSchedCollab::PackStartCmd(std::shared_ptr<SinkStartCmd>& cmd)
{
    if (cmd == nullptr) {
        HILOGE("cmd or is null");
        return INVALID_PARAMETERS_ERR;
    }
    cmd->collabVersion_ = collabInfo_.srcCollabVersion_;
    cmd->dmsVersion_ = DMS_VERSION;
    cmd->command_ = SINK_START_CMD;
    cmd->srcCollabSessionId_ = collabInfo_.srcCollabSessionId_;
    cmd->collabToken_ = collabInfo_.collabToken_;
    cmd->srcPid_ = collabInfo_.srcInfo_.pid_;
    cmd->srcUid_ = collabInfo_.srcInfo_.uid_;
    cmd->srcAccessToken_ = collabInfo_.srcInfo_.accessToken_;
    cmd->srcServerId_ = collabInfo_.srcInfo_.serverId_;
    cmd->sinkServerId_ = collabInfo_.sinkInfo_.serverId_;
    cmd->srcDeviceId_ = collabInfo_.srcInfo_.deviceId_;
    cmd->sinkDeviceId_ = collabInfo_.sinkInfo_.deviceId_;
    cmd->srcBundleName_ = collabInfo_.srcInfo_.bundleName_;
    cmd->sinkBundleName_ = collabInfo_.sinkInfo_.bundleName_;
    cmd->srcAbilityName_ = collabInfo_.srcInfo_.abilityName_;
    cmd->sinkAbilityName_ = collabInfo_.sinkInfo_.abilityName_;
    cmd->srcModuleName_ = collabInfo_.srcInfo_.moduleName_;
    cmd->sinkModuleName_ = collabInfo_.sinkInfo_.moduleName_;
    cmd->needSendBigData_ = collabInfo_.srcOpt_.needSendBigData_;
    cmd->needSendStream_ = collabInfo_.srcOpt_.needSendStream_;
    cmd->needRecvStream_ = collabInfo_.srcOpt_.needRecvStream_;
    cmd->startParams_ = collabInfo_.srcOpt_.startParams_;
    cmd->messageParams_ = collabInfo_.srcOpt_.messageParams_;
    return PackPartCmd(cmd);
}

int32_t DSchedCollab::PackPartCmd(std::shared_ptr<SinkStartCmd>& cmd)
{
    AppExecFwk::BundleInfo localBundleInfo;
    int32_t ret = BundleManagerInternal::GetLocalBundleInfoV9(cmd->srcBundleName_, localBundleInfo);
    if (ret != ERR_OK) {
        HILOGE("pack start cmd failed, the bundle is not installed on local device.");
        return ret;
    }
    cmd->appVersion_ = static_cast<int32_t>(localBundleInfo.versionCode);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = collabInfo_.srcInfo_.deviceId_;
    callerInfo.uid = collabInfo_.srcInfo_.uid_;
    callerInfo.accessToken = collabInfo_.srcInfo_.accessToken_;
    if (!BundleManagerInternal::GetCallerAppIdFromBms(callerInfo.uid, callerInfo.callerAppId)) {
        HILOGE("GetCallerAppIdFromBms failed");
        return GET_APPID_ERR;
    }
    if (!BundleManagerInternal::GetBundleNameListFromBms(callerInfo.uid, callerInfo.bundleNames)) {
        HILOGE("GetBundleNameListFromBms failed");
        return GET_BUNDLENAMELIST_ERR;
    }
    callerInfo.extraInfoJson[DMS_VERSION_ID] = DMS_VERSION;
    AccountInfo accountInfo;
    ret = DistributedSchedPermission::GetInstance().GetAccountInfo(collabInfo_.sinkInfo_.deviceId_,
        callerInfo, accountInfo);
    if (ret != ERR_OK) {
        HILOGE("get or check accountInfo failed");
        return GET_ACCOUNT_INFO_ERR;
    }
    cmd->callerInfo_ = callerInfo;
    cmd->accountInfo_ = accountInfo;
    return ERR_OK;
}

int32_t DSchedCollab::ExeStartAbility()
{
    HILOGI("called");
    AAFwk::Want want = GenerateCollabWant();
    int32_t ret = DistributedSchedService::GetInstance().CheckTargetPermission(want, collabInfo_.callerInfo_,
        collabInfo_.srcAccountInfo_, START_PERMISSION, true);
    if (ret != ERR_OK) {
        HILOGE("CheckTargetPermission failed!");
        return ret;
    }

    HILOGI("flag is %{public}d", want.GetFlags());
    ret = AAFwk::AbilityManagerClient::GetInstance()->Connect();
    if (ret != ERR_OK) {
        HILOGE("connect ability server failed %{public}d", ret);
        return ret;
    }
    sptr<IRemoteObject> callbackWrapper = sptr<AbilityConnectionWrapperStub>(new AbilityConnectionWrapperStub());
    ret = AAFwk::AbilityManagerClient::GetInstance()->StartAbilityByCall(want,
        iface_cast<AAFwk::IAbilityConnection>(callbackWrapper));
    if (ret != ERR_OK) {
        HILOGE("startAbilityByCall failed! ret: %{public}d", ret);
        return PostErrEndTask(ret);
    }

    UpdateState(SINK_CONNECT_STATE);
    RegisterAbilityLifecycleObserver(collabInfo_.sinkInfo_.bundleName_);
    HILOGI("end");
    return ERR_OK;
}

AAFwk::Want DSchedCollab::GenerateCollabWant()
{
    HILOGI("called");
    AAFwk::Want want;
    want.AddFlags(want.FLAG_ABILITY_ON_COLLABORATE);
    want.SetParam("deviceId", collabInfo_.sinkInfo_.deviceId_);
    want.SetElementName(collabInfo_.sinkInfo_.deviceId_, collabInfo_.sinkInfo_.bundleName_,
        collabInfo_.sinkInfo_.abilityName_);

    AAFwk::WantParams peerInfoParams;
    peerInfoParams.SetParam("deviceId", AAFwk::String::Box(collabInfo_.srcInfo_.deviceId_));
    peerInfoParams.SetParam("bundleName", AAFwk::String::Box(collabInfo_.srcInfo_.bundleName_));
    peerInfoParams.SetParam("moduleName", AAFwk::String::Box(collabInfo_.srcInfo_.moduleName_));
    peerInfoParams.SetParam("abilityName", AAFwk::String::Box(collabInfo_.srcInfo_.abilityName_));
    peerInfoParams.SetParam("serverId", AAFwk::String::Box(collabInfo_.srcInfo_.serverId_));

    AAFwk::WantParams optParams;
    optParams.SetParam("needSendData", AAFwk::Boolean::Box(collabInfo_.srcOpt_.needSendBigData_));
    optParams.SetParam("needSendStream", AAFwk::Boolean::Box(collabInfo_.srcOpt_.needSendStream_));
    optParams.SetParam("needReceiveStream", AAFwk::Boolean::Box(collabInfo_.srcOpt_.needRecvStream_));
    optParams.SetParam("parameters", AAFwk::WantParamWrapper::Box(collabInfo_.srcOpt_.messageParams_));

    AAFwk::WantParams collabParams;
    collabParams.SetParam("PeerInfo", AAFwk::WantParamWrapper::Box(peerInfoParams));
    collabParams.SetParam("ConnectOption", AAFwk::WantParamWrapper::Box(optParams));
    collabParams.SetParam("ohos.dms.collabToken", AAFwk::String::Box(collabInfo_.collabToken_));

    AAFwk::WantParams wantParams;
    SetScreenLockParameters(wantParams);
    wantParams.SetParam("ohos.extra.param.key.supportCollaborateIndex", AAFwk::WantParamWrapper::Box(collabParams));
    wantParams.SetParam("ohos.aafwk.param.callAbilityToForeground", AAFwk::Boolean::Box(IsStartForeground()));
    want.SetParams(wantParams);
    return want;
}

void DSchedCollab::SetScreenLockParameters(AAFwk::WantParams& wantParams)
{
    bool isSecureMode = OHOS::ScreenLock::ScreenLockManager::GetInstance()->GetSecure();
    bool isLocked = false;
    OHOS::ScreenLock::ScreenLockManager::GetInstance()->IsLocked(isLocked);
    HILOGI("isSecureMode is %{public}d, isLocked is %{public}d", isSecureMode, isLocked);
    wantParams.SetParam("isSecureMode", AAFwk::Boolean::Box(isSecureMode));
    wantParams.SetParam("isFromScreenLock", AAFwk::Boolean::Box(isLocked));
}

bool DSchedCollab::IsStartForeground()
{
    auto value = collabInfo_.srcOpt_.startParams_.GetParam(KEY_START_OPTION);
    IString *ao = IString::Query(value);
    if (ao != nullptr) {
        std::string startOpt = AAFwk::String::Unbox(ao);
        return (startOpt == VALUE_START_OPTION_BACKGROUND) ? false : true;
    }
    return true;
}

int32_t DSchedCollab::SaveSinkAbilityData(const std::string& collabToken, const int32_t &result,
    const int32_t &sinkPid, const int32_t &sinkUid, const int32_t &sinkAccessTokenId)
{
    HILOGI("called, pid: %{public}d, uid: %{public}d, accessTokenId: %{public}d", sinkPid, sinkUid, sinkAccessTokenId);
    collabInfo_.sinkInfo_.pid_ = sinkPid;
    collabInfo_.sinkInfo_.uid_ = sinkUid;
    collabInfo_.sinkInfo_.accessToken_ = sinkAccessTokenId;
    HILOGI("end, continueInfo %{public}s", collabInfo_.ToString().c_str());
    return ERR_OK;
}

int32_t DSchedCollab::ExeAbilityRejectError(const std::string &reason)
{
    HILOGE("called");
    auto cmd = std::make_shared<NotifyResultCmd>();
    PackNotifyResultCmd(cmd, COLLAB_ABILITY_REJECT_ERR, reason);
    SendCommand(cmd);
    CleanUpSession();
    HILOGI("end");
    return ERR_OK;
}

int32_t DSchedCollab::ExeSinkPrepareResult(const int32_t &result)
{
    HILOGI("called");
    if (result != ERR_OK && result != COLLAB_ABILITY_REJECT_ERR) {
        HILOGE("failed %{public}d", result);
        return PostErrEndTask(result);
    }
    auto notifyResCmd = std::make_shared<NotifyResultCmd>();
    PackNotifyResultCmd(notifyResCmd, result);
    int32_t ret = SendCommand(notifyResCmd);
    if (ret != ERR_OK) {
        HILOGE("send notifyResCmd failed, ret %{public}d", ret);
        return ret;
    }
    UpdateState(SINK_WAIT_END_STATE);
    collabInfo_.srcUdid_ = DtbschedmgrDeviceInfoStorage::GetInstance().GetUdidByNetworkId(
        collabInfo_.srcInfo_.deviceId_);
    collabInfo_.sinkUdid_ = DtbschedmgrDeviceInfoStorage::GetInstance().GetUdidByNetworkId(
        collabInfo_.sinkInfo_.deviceId_);
    HILOGI("end, info: %{public}s.", collabInfo_.ToString().c_str());
    return ERR_OK;
}

int32_t DSchedCollab::PackNotifyResultCmd(std::shared_ptr<NotifyResultCmd> cmd, const int32_t &result,
    const std::string &abilityRejectReason)
{
    if (cmd == nullptr) {
        HILOGE("cmd is null");
        return INVALID_PARAMETERS_ERR;
    }
    cmd->command_ = NOTIFY_RESULT_CMD;
    cmd->result_ = result;
    cmd->collabToken_ = collabInfo_.collabToken_;
    cmd->sinkSocketName_ = collabInfo_.sinkInfo_.socketName_;
    cmd->sinkCollabSessionId_ = collabInfo_.sinkCollabSessionId_;
    cmd->abilityRejectReason_ = abilityRejectReason;
    return ERR_OK;
}

int32_t DSchedCollab::ExeSrcCollabResult(const int32_t &result, const std::string reason)
{
    HILOGI("called, collabInfo: %{public}s", collabInfo_.ToString().c_str());
    if (result != ERR_OK && result != COLLAB_ABILITY_REJECT_ERR) {
        HILOGE("failed, result: %{public}d", result);
        return PostErrEndTask(result);
    }
    int32_t ret = ExeSrcClientNotify(result, reason);
    if (ret != ERR_OK) {
        HILOGE("failed, ret: %{public}d", ret);
        return PostErrEndTask(result);
    }
    UpdateState(SOURCE_WAIT_END_STATE);
    HILOGI("end");
    return ERR_OK;
}

int32_t DSchedCollab::CleanUpSession()
{
    if (collabInfo_.direction_ == COLLAB_SOURCE) {
        const std::string peerDeviceId = collabInfo_.sinkInfo_.deviceId_;
        HILOGI("disconnect peer device %{public}s", GetAnonymStr(peerDeviceId).c_str());
        DSchedTransportSoftbusAdapter::GetInstance().DisconnectDevice(peerDeviceId);
    }
    ExeClientDisconnectNotify();
    return DSchedCollabManager::GetInstance().CleanUpSession(collabInfo_.collabToken_);
}

int32_t DSchedCollab::ExeSrcClientNotify(const int32_t &result, const std::string reason)
{
    HILOGI("called, result: %{public}d, collabInfo: %{public}s", result, collabInfo_.ToString().c_str());
    if (collabInfo_.srcClientCB_ == nullptr) {
        HILOGW("callback object null.");
        return INVALID_PARAMETERS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(NAPI_COLLAB_CALLBACK_INTERFACE_TOKEN)) {
        HILOGE("write token failed");
        return INVALID_PARAMETERS_ERR;
    }
    PARCEL_WRITE_HELPER(data, Int32, collabInfo_.srcCollabSessionId_);
    PARCEL_WRITE_HELPER(data, Int32, result);
    PARCEL_WRITE_HELPER(data, String, collabInfo_.sinkInfo_.socketName_);
    PARCEL_WRITE_HELPER(data, String, collabInfo_.collabToken_);
    PARCEL_WRITE_HELPER(data, String, reason);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = collabInfo_.srcClientCB_->SendRequest(NOTIFY_COLLAB_PREPARE_RESULT, data, reply, option);
    if (ret != ERR_OK) {
        HILOGE("send request failed, ret: %{public}d", ret);
    }
    HILOGI("end");
    return ret;
}

int32_t DSchedCollab::ExeClientDisconnectNotify()
{
    HILOGI("called");
    int32_t collabSessionId;
    sptr<IRemoteObject> clientCB;
    if (collabInfo_.direction_ == COLLAB_SOURCE) {
        if (collabInfo_.srcClientCB_ == nullptr) {
            HILOGW("srcClientCB object null.");
            return ERR_NULL_OBJECT;
        }
        collabSessionId = collabInfo_.srcCollabSessionId_;
        clientCB = collabInfo_.srcClientCB_;
    } else {
        if (collabInfo_.sinkClientCB_ == nullptr) {
            HILOGW("sinkClientCB object null.");
            return ERR_NULL_OBJECT;
        }
        collabSessionId = collabInfo_.srcCollabSessionId_;
        clientCB = collabInfo_.sinkClientCB_;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(NAPI_COLLAB_CALLBACK_INTERFACE_TOKEN)) {
        HILOGE("write token failed");
        return SEND_REQUEST_DEF_FAIL;
    }
    PARCEL_WRITE_HELPER(data, Int32, collabInfo_.sinkCollabSessionId_);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = clientCB->SendRequest(NOTIFY_COLLAB_DISCONNECT, data, reply, option);
    if (ret != ERR_OK) {
        HILOGE("send request failed, ret: %{public}d", ret);
        return SEND_REQUEST_DEF_FAIL;
    }
    HILOGI("end");
    return ERR_OK;
}

int32_t DSchedCollab::ExeSrcStartError(const int32_t &result)
{
    HILOGE("called, reason: %{public}d", result);
    ExeSrcClientNotify(result);
    CleanUpSession();
    HILOGI("end");
    return ERR_OK;
}

int32_t DSchedCollab::ExeSrcWaitResultError(const int32_t &result)
{
    HILOGE("called, reason: %{public}d", result);
    auto cmd = std::make_shared<NotifyResultCmd>();
    PackNotifyResultCmd(cmd, result);
    SendCommand(cmd);
    ExeSrcClientNotify(result);
    CleanUpSession();
    HILOGI("end");
    return ERR_OK;
}

int32_t DSchedCollab::ExeSinkError(const int32_t &result)
{
    HILOGE("called, reason: %{public}d", result);
    auto cmd = std::make_shared<NotifyResultCmd>();
    PackNotifyResultCmd(cmd, result);
    SendCommand(cmd);
    CleanUpSession();
    HILOGI("end");
    return ERR_OK;
}

int32_t DSchedCollab::ExeSinkStartError(const int32_t &result)
{
    HILOGE("called, reason: %{public}d", result);
    auto cmd = std::make_shared<NotifyResultCmd>();
    PackNotifyResultCmd(cmd, result);
    SendCommand(cmd);
    CleanUpSession();
    HILOGI("end");
    return ERR_OK;
}

int32_t DSchedCollab::ExeSinkConnectError(const int32_t &result)
{
    HILOGE("called, reason: %{public}d", result);
    auto cmd = std::make_shared<NotifyResultCmd>();
    PackNotifyResultCmd(cmd, result);
    SendCommand(cmd);
    CleanUpSession();
    HILOGI("end");
    return ERR_OK;
}

int32_t DSchedCollab::ExeDisconnect()
{
    HILOGI("called");
    auto cmd = std::make_shared<DisconnectCmd>();
    PackDisconnectCmd(cmd);
    SendCommand(cmd);
    CleanUpSession();
    HILOGI("end");
    return ERR_OK;
}

int32_t DSchedCollab::PackDisconnectCmd(std::shared_ptr<DisconnectCmd> cmd)
{
    if (cmd == nullptr) {
        HILOGE("cmd is null");
        return INVALID_PARAMETERS_ERR;
    }
    cmd->command_ = DISCONNECT_CMD;
    cmd->collabToken_ = collabInfo_.collabToken_;
    return ERR_OK;
}

int32_t DSchedCollab::SendCommand(std::shared_ptr<BaseCmd> cmd)
{
    HILOGI("called, cmd %{public}s", CMDDATA[cmd->command_].c_str());
    if (cmd == nullptr) {
        HILOGE("cmd is null");
        return INVALID_PARAMETERS_ERR;
    }
    std::string jsonStr;
    int32_t ret = cmd->Marshal(jsonStr);
    if (ret != ERR_OK) {
        HILOGE("marshal cmd %{public}s failed, ret %{public}d", CMDDATA[cmd->command_].c_str(), ret);
        return ret;
    }
    auto buffer = std::make_shared<DSchedDataBuffer>(jsonStr.length() + 1);
    ret = memcpy_s(buffer->Data(), buffer->Capacity(), jsonStr.c_str(), jsonStr.length());
    if (ret != ERR_OK) {
        HILOGE("memcpy_s failed, cmd %{public}s, ret %{public}d", CMDDATA[cmd->command_].c_str(), ret);
        return ret;
    }
    ret = DSchedTransportSoftbusAdapter::GetInstance().SendData(softbusSessionId_, SERVICE_TYPE_COLLAB, buffer);
    if (ret != ERR_OK) {
        HILOGE("send data failed, cmd %{public}s, ret %{public}d", CMDDATA[cmd->command_].c_str(), ret);
        return ret;
    }
    HILOGI("end");
    return ERR_OK;
}

int32_t DSchedCollab::GetSoftbusSessionId()
{
    return softbusSessionId_;
}

DSchedCollabInfo DSchedCollab::GetCollabInfo()
{
    return collabInfo_;
}

void DSchedCollab::OnDataRecv(int32_t command, std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    HILOGI("called, command: %{public}s", CMDDATA[command].c_str());
    if (dataBuffer == nullptr) {
        HILOGE("dataBuffer is null");
        return;
    }
    int32_t ret = 0;
    uint8_t *data = dataBuffer->Data();
    std::string jsonStr(reinterpret_cast<const char *>(data), dataBuffer->Capacity());

    switch (command) {
        case SINK_START_CMD: {
            auto startCmd = std::make_shared<SinkStartCmd>();
            ret = startCmd->Unmarshal(jsonStr);
            if (ret != ERR_OK) {
                HILOGE("Unmarshal reply cmd failed, ret: %{public}d", ret);
                PostErrEndTask(ret);
                return;
            }
            PostSinkStartTask();
            break;
        }
        case NOTIFY_RESULT_CMD: {
            auto notifyResultCmd = std::make_shared<NotifyResultCmd>();
            ret = notifyResultCmd->Unmarshal(jsonStr);
            if (ret != ERR_OK) {
                HILOGE("unmarshal cmd failed, ret: %{public}d", ret);
                PostErrEndTask(ret);
                return;
            }
            PostSrcResultTask(notifyResultCmd);
            break;
        }
        case DISCONNECT_CMD: {
            CleanUpSession();
            break;
        }
        default:
            HILOGW("Invalid command.");
            break;
    }
}

void DSchedCollab::UpdateState(CollabStateType stateType)
{
    HILOGI("called");
    if (stateMachine_ == nullptr) {
        HILOGE("stateMachine is null");
        return;
    }
    stateMachine_->UpdateState(stateType);
}

bool DSchedCollab::RegisterAbilityLifecycleObserver(const std::string &bundleName)
{
    HILOGI("called");
    sptr<AppExecFwk::IAppMgr> appObject = GetAppManager();
    if (appObject == nullptr) {
        HILOGE("failed to get app manager service");
        return false;
    }
    std::vector<std::string> bundleNameList = {bundleName};
    appStateObserver_ = sptr<AbilityLifecycleObserver>(new (std::nothrow) AbilityLifecycleObserver());
    int ret = appObject->RegisterApplicationStateObserver(appStateObserver_, bundleNameList);
    if (ret != ERR_OK) {
        HILOGE("failed to register observer, ret = %{public}d", ret);
        return false;
    }
    HILOGI("success");
    return true;
}

void DSchedCollab::UnregisterAbilityLifecycleObserver()
{
    HILOGI("called");
    if (appStateObserver_ == nullptr) {
        HILOGW("no need to unregister");
        return;
    }
    sptr<AppExecFwk::IAppMgr> appObject = GetAppManager();
    if (appObject == nullptr) {
        HILOGE("failed to get app manager service");
        return;
    }
    int ret = appObject->UnregisterApplicationStateObserver(appStateObserver_);
    if (ret != ERR_OK) {
        HILOGE("failed to unregister observer, ret = %{public}d", ret);
        return;
    }
    HILOGI("success");
}

sptr<AppExecFwk::IAppMgr> DSchedCollab::GetAppManager()
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

void DSchedCollab::OnShutDown()
{
}

void DSchedCollab::OnBind()
{
}
}  // namespace DistributedSchedule
}  // namespace OHOS

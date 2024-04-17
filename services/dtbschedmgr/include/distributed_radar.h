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

#ifndef OHOS_DISTRIBUTED_RADAR_H
#define OHOS_DISTRIBUTED_RADAR_H

#include <cstdint>
#include <chrono>
#include <string>
#include <vector>

#include "dtbschedmgr_log.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string ORG_PKG_NAME = "ohos.distributedschedule";
const std::string APPLICATION_CONTINUE_BEHAVIOR = "APPLICATION_CONTINUE_BEHAVIOR";
const std::string ABILITY_MANAGER_SERVICE = "ohos.abilitymanagerservice";
const std::string INIT = "init";
const std::string NORMAL = "normal";
const std::string MULTIMODE = "multimode";
const std::string DEVICEONLINE = "deviceonline";
const std::string FOCUSED = "focused";
const std::string UNFOCUSED = "unfocused";
const std::string BMS_PKG_NAME = "foundation_bms";
const std::string DBMS_PKG_NAME = "d_bms";
const std::string DSOFTBUS_PKG_NAME = "dsoftbus";
const std::string ORG_PKG = "ORG_PKG";
const std::string FUNC = "FUNC";
const std::string BIZ_SCENE = "BIZ_SCENE";
const std::string BIZ_STAGE = "BIZ_STAGE";
const std::string STAGE_RES = "STAGE_RES";
const std::string BIZ_STATE = "BIZ_STATE";
const std::string TO_CALL_PKG = "TO_CALL_PKG";
const std::string HOST_PKG = "HOST_PKG";
const std::string ERROR_CODE = "ERROR_CODE";
constexpr char APP_CONTINUE_DOMAIN[] = "APP_CONTINUE";
enum class BizScene : int32_t {
    DMS_INIT = 1,
    /*2 not our scene*/
    NORMAL_MULTIMODE_FOCUSED  = 3,
    CHANGE_STATE_FOCUSED = 4,
    NORMAL_UNFOCUSED = 5,
    MULTIMODE_UNFOCUSED = 6,
    CHANGE_STATE_UNFOCUSED = 7,
    RECV_FOCUSED = 8,
    RECV_UNFOCUSED = 9,
    CLICK_ICON = 10,
    SAVE_DATA = 11,
};

enum class StageRes : int32_t {
    STAGE_IDLE = 0,
    STAGE_SUCC = 1,
    STAGE_FAIL = 2,
    STAGE_CANCEL = 3,
    STAGE_UNKNOW = 4,
};

enum class BizState : int32_t {
    BIZ_STATE_START = 1,
    BIZ_STATE_END = 2,
};

enum class DmsInit : int32_t {
    REGISTER_ABILITY_FOCUSED = 1,
    REGISTER_SOFTBUS_CALLBACK = 2,
};

enum class NormalOrMultimodeFocused : int32_t {
    DMS_FOCUSED = 1,
    GET_BMS_ACCESSTOKENID = 2,
    SOFTBUS_SENDEVENT = 3,
};

enum class ChangeStateFocused : int32_t {
    SET_STATE = 1,
    GET_BMS_ACCESSTOKENID = 2,
    SOFTBUS_SENDEVENT = 3,
};

enum class NormalUnfocused : int32_t {
    DMS_UNFOCUSED = 1,
    GET_BMS_ACCESSTOKENID = 2,
    SOFTBUS_SENDEVENT = 3,
};

enum class MultimodeUnfocused : int32_t {
    RECORD_TIME = 1,
    GET_BMS_ACCESSTOKENID = 2,
    SOFTBUS_SENDEVENT = 3,
};

enum class ChangeStateUnfocused : int32_t {
    SET_STATE = 1,
    GET_BMS_ACCESSTOKENID = 2,
    SOFTBUS_SENDEVENT = 3,
};

enum class RecvFocused : int32_t {
    RECV_FOCUSED = 1,
    GET_DBMS_BUNDLENAME = 2,
    NOTIFY_DOCK_FOCUSED = 3,
};

enum class RecvUnfocused : int32_t {
    RECV_UNFOCUSED = 1,
    GET_DBMS_BUNDLENAME = 2,
    NOTIFY_DOCK_UNFOCUSED = 3,
};

enum class ClickIcon : int32_t {
    DMS_CONTINUE = 4,
    DMS_STARTABILITY = 5,
    DMS_RECV_OVER = 10,
};

enum class SaveData : int32_t {
    DMS_CONTINUE = 1,
    DMS_REMOTE_WANT = 5,
};

enum class Module : int32_t {
    DMS_CONTINUE = 0,
};

class DmsRadar {
    DECLARE_SINGLE_INSTANCE(DmsRadar);
public:
    bool RegisterSoftbusCallbackRes(const std::string& func, int32_t errCode);
    bool RegisterFocusedRes(const std::string& func, int32_t errCode);
    bool DmsFocused(const std::string& func, std::string focusMode);
    bool NormalFocusedGetAccessTokenIdRes(const std::string& func, int32_t errCode);
    bool NormalFocusedSendEventRes(const std::string& func, int32_t errCode);
    bool SetFocusedState(const std::string& func);
    bool ChangeStateFocusedGetAccessTokenIdRes(const std::string& func, int32_t errCode);
    bool ChangeStateFocusedSendEventRes(const std::string& func, int32_t errCode);
    bool DmsUnfocused(const std::string& func);
    bool NormalUnfocusedGetAccessTokenIdRes(const std::string& func, int32_t errCode);
    bool NormalUnfocusedSendEventRes(const std::string& func, int32_t errCode);
    bool RecordTime(const std::string& func);
    bool MultimodeUnfocusedGetAccessTokenIdRes(const std::string& func, int32_t errCode);
    bool MultimodeUnfocusedSendEventRes(const std::string& func, int32_t errCode);
    bool SetUnfocusedState(const std::string& func);
    bool ChangeStateUnfocusedGetAccessTokenIdRes(const std::string& func, int32_t errCode);
    bool ChangeStateUnfocusedSendEventRes(const std::string& func, int32_t errCode);
    bool RecvFocused(const std::string& func);
    bool FocusedGetBundleName(const std::string& func, int32_t errCode);
    bool NotifyDockFocused(const std::string& func, int32_t errCode);
    bool RecvUnfocused(const std::string& func);
    bool UnfocusedGetBundleName(const std::string& func, int32_t errCode);
    bool NotifyDockUnfocused(const std::string& func, int32_t errCode);
    bool ClickIconDmsContinue(const std::string& func, int32_t errCode);
    bool ClickIconDmsStartAbility(const std::string& func, int32_t errCode);
    bool ClickIconDmsRecvOver(const std::string& func, int32_t errCode);
    bool SaveDataDmsContinue(const std::string& func, int32_t errCode);
    bool SaveDataDmsRemoteWant(const std::string& func, int32_t errCode);
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_RADAR_H
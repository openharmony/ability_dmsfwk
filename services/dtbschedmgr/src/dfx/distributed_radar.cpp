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

#include "dfx/distributed_radar.h"

#include "hisysevent.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DmsRadar";
IMPLEMENT_SINGLE_INSTANCE(DmsRadar);

bool DmsRadar::RegisterFocusedRes(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::DMS_INIT),
            BIZ_STAGE, static_cast<int32_t>(DmsInit::REGISTER_ABILITY_FOCUSED),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_START));
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::DMS_INIT),
            BIZ_STAGE, static_cast<int32_t>(DmsInit::REGISTER_ABILITY_FOCUSED),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_START),
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("RegisterFocusedRes error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::RegisterSoftbusCallbackRes(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::DMS_INIT),
            BIZ_STAGE, static_cast<int32_t>(DmsInit::REGISTER_SOFTBUS_CALLBACK),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END),
            TO_CALL_PKG, ABILITY_MANAGER_SERVICE);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::DMS_INIT),
            BIZ_STAGE, static_cast<int32_t>(DmsInit::REGISTER_SOFTBUS_CALLBACK),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END),
            TO_CALL_PKG, ABILITY_MANAGER_SERVICE,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("RegisterSoftbusCallbackRes error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::DmsFocused(const std::string& func, std::string focusMode)
{
    int32_t res = HiSysEventWrite(
        APP_CONTINUE_DOMAIN,
        APPLICATION_CONTINUE_BEHAVIOR,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        ORG_PKG, ORG_PKG_NAME,
        FUNC, func,
        BIZ_SCENE, static_cast<int32_t>(BizScene::NORMAL_MULTIMODE_FOCUSED),
        BIZ_STAGE, static_cast<int32_t>(NormalOrMultimodeFocused::DMS_FOCUSED),
        STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
        BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_START),
        "FOCUS_MODE", focusMode);
    if (res != ERR_OK) {
        HILOGE("DmsFocused error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::NormalFocusedGetAccessTokenIdRes(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::NORMAL_MULTIMODE_FOCUSED),
            BIZ_STAGE, static_cast<int32_t>(NormalOrMultimodeFocused::GET_BMS_ACCESSTOKENID),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            TO_CALL_PKG, BMS_PKG_NAME);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::NORMAL_MULTIMODE_FOCUSED),
            BIZ_STAGE, static_cast<int32_t>(NormalOrMultimodeFocused::GET_BMS_ACCESSTOKENID),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            TO_CALL_PKG, BMS_PKG_NAME,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("NormalFocusedGetAccessTokenIdRes error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::NormalFocusedSendEventRes(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::NORMAL_MULTIMODE_FOCUSED),
            BIZ_STAGE, static_cast<int32_t>(NormalOrMultimodeFocused::SOFTBUS_SENDEVENT),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END),
            TO_CALL_PKG, DSOFTBUS_PKG_NAME);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::NORMAL_MULTIMODE_FOCUSED),
            BIZ_STAGE, static_cast<int32_t>(NormalOrMultimodeFocused::SOFTBUS_SENDEVENT),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END),
            TO_CALL_PKG, DSOFTBUS_PKG_NAME,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("NormalFocusedSendEventRes error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::SetFocusedState(const std::string& func)
{
    int32_t res = HiSysEventWrite(
        APP_CONTINUE_DOMAIN,
        APPLICATION_CONTINUE_BEHAVIOR,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        ORG_PKG, ORG_PKG_NAME,
        FUNC, func,
        BIZ_SCENE, static_cast<int32_t>(BizScene::CHANGE_STATE_FOCUSED),
        BIZ_STAGE, static_cast<int32_t>(ChangeStateFocused::SET_STATE),
        STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
        BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_START));
    if (res != ERR_OK) {
        HILOGE("SetFocusedState error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::ChangeStateFocusedGetAccessTokenIdRes(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::CHANGE_STATE_FOCUSED),
            BIZ_STAGE, static_cast<int32_t>(ChangeStateFocused::GET_BMS_ACCESSTOKENID),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            TO_CALL_PKG, BMS_PKG_NAME);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::CHANGE_STATE_FOCUSED),
            BIZ_STAGE, static_cast<int32_t>(ChangeStateFocused::GET_BMS_ACCESSTOKENID),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            TO_CALL_PKG, BMS_PKG_NAME,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("ChangeStateFocusedGetAccessTokenIdRes error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::ChangeStateFocusedSendEventRes(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::CHANGE_STATE_FOCUSED),
            BIZ_STAGE, static_cast<int32_t>(ChangeStateFocused::SOFTBUS_SENDEVENT),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END),
            TO_CALL_PKG, DSOFTBUS_PKG_NAME);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::CHANGE_STATE_FOCUSED),
            BIZ_STAGE, static_cast<int32_t>(ChangeStateFocused::SOFTBUS_SENDEVENT),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END),
            TO_CALL_PKG, DSOFTBUS_PKG_NAME,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("ChangeStateFocusedSendEventRes error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::DmsUnfocused(const std::string& func)
{
    int32_t res = HiSysEventWrite(
        APP_CONTINUE_DOMAIN,
        APPLICATION_CONTINUE_BEHAVIOR,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        ORG_PKG, ORG_PKG_NAME,
        FUNC, func,
        BIZ_SCENE, static_cast<int32_t>(BizScene::NORMAL_UNFOCUSED),
        BIZ_STAGE, static_cast<int32_t>(NormalUnfocused::DMS_UNFOCUSED),
        STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
        BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_START));
    if (res != ERR_OK) {
        HILOGE("DmsUnfocused error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::NormalUnfocusedGetAccessTokenIdRes(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::NORMAL_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(NormalUnfocused::GET_BMS_ACCESSTOKENID),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            TO_CALL_PKG, BMS_PKG_NAME);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::NORMAL_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(NormalUnfocused::GET_BMS_ACCESSTOKENID),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            TO_CALL_PKG, BMS_PKG_NAME,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("NormalUnfocusedGetAccessTokenIdRes error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::NormalUnfocusedSendEventRes(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::NORMAL_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(NormalUnfocused::SOFTBUS_SENDEVENT),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END),
            TO_CALL_PKG, DSOFTBUS_PKG_NAME);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::NORMAL_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(NormalUnfocused::SOFTBUS_SENDEVENT),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END),
            TO_CALL_PKG, DSOFTBUS_PKG_NAME,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("NormalUnfocusedSendEventRes error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::RecordTime(const std::string& func)
{
    int32_t res = HiSysEventWrite(
        APP_CONTINUE_DOMAIN,
        APPLICATION_CONTINUE_BEHAVIOR,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        ORG_PKG, ORG_PKG_NAME,
        FUNC, func,
        BIZ_SCENE, static_cast<int32_t>(BizScene::MULTIMODE_UNFOCUSED),
        BIZ_STAGE, static_cast<int32_t>(MultimodeUnfocused::RECORD_TIME),
        STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
        BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_START));
    if (res != ERR_OK) {
        HILOGE("RecordTime error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::MultimodeUnfocusedGetAccessTokenIdRes(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::MULTIMODE_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(MultimodeUnfocused::GET_BMS_ACCESSTOKENID),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            TO_CALL_PKG, BMS_PKG_NAME);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::MULTIMODE_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(MultimodeUnfocused::GET_BMS_ACCESSTOKENID),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            TO_CALL_PKG, BMS_PKG_NAME,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("MultimodeUnfocusedGetAccessTokenIdRes error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::MultimodeUnfocusedSendEventRes(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::MULTIMODE_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(MultimodeUnfocused::SOFTBUS_SENDEVENT),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END),
            TO_CALL_PKG, DSOFTBUS_PKG_NAME);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::MULTIMODE_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(MultimodeUnfocused::SOFTBUS_SENDEVENT),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END),
            TO_CALL_PKG, DSOFTBUS_PKG_NAME,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("MultimodeUnfocusedSendEventRes error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::SetUnfocusedState(const std::string& func)
{
    int32_t res = HiSysEventWrite(
        APP_CONTINUE_DOMAIN,
        APPLICATION_CONTINUE_BEHAVIOR,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        ORG_PKG, ORG_PKG_NAME,
        FUNC, func,
        BIZ_SCENE, static_cast<int32_t>(BizScene::CHANGE_STATE_UNFOCUSED),
        BIZ_STAGE, static_cast<int32_t>(ChangeStateUnfocused::SET_STATE),
        STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
        BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_START));
    if (res != ERR_OK) {
        HILOGE("SetFocusedState error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::ChangeStateUnfocusedGetAccessTokenIdRes(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::CHANGE_STATE_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(ChangeStateUnfocused::GET_BMS_ACCESSTOKENID),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            TO_CALL_PKG, BMS_PKG_NAME);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::CHANGE_STATE_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(ChangeStateUnfocused::GET_BMS_ACCESSTOKENID),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            TO_CALL_PKG, BMS_PKG_NAME,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("ChangeStateUnfocusedGetAccessTokenIdRes error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::ChangeStateUnfocusedSendEventRes(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::CHANGE_STATE_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(ChangeStateUnfocused::SOFTBUS_SENDEVENT),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END),
            TO_CALL_PKG, DSOFTBUS_PKG_NAME);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::CHANGE_STATE_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(ChangeStateUnfocused::SOFTBUS_SENDEVENT),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END),
            TO_CALL_PKG, DSOFTBUS_PKG_NAME,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("ChangeStateUnfocusedSendEventRes error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::RecvFocused(const std::string& func)
{
    int32_t res = HiSysEventWrite(
        APP_CONTINUE_DOMAIN,
        APPLICATION_CONTINUE_BEHAVIOR,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        ORG_PKG, ORG_PKG_NAME,
        FUNC, func,
        BIZ_SCENE, static_cast<int32_t>(BizScene::RECV_FOCUSED),
        BIZ_STAGE, static_cast<int32_t>(RecvFocused::RECV_FOCUSED),
        STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
        BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_START),
        "BROADCAST_INFO", FOCUSED,
        HOST_PKG, DSOFTBUS_PKG_NAME);
    if (res != ERR_OK) {
        HILOGE("RecvFocused error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::FocusedGetBundleName(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::RECV_FOCUSED),
            BIZ_STAGE, static_cast<int32_t>(RecvFocused::GET_DBMS_BUNDLENAME),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            TO_CALL_PKG, DBMS_PKG_NAME);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::RECV_FOCUSED),
            BIZ_STAGE, static_cast<int32_t>(RecvFocused::GET_DBMS_BUNDLENAME),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            TO_CALL_PKG, DBMS_PKG_NAME,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("FocusedGetBundleName error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::NotifyDockFocused(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::RECV_FOCUSED),
            BIZ_STAGE, static_cast<int32_t>(RecvFocused::NOTIFY_DOCK_FOCUSED),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC));
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::RECV_FOCUSED),
            BIZ_STAGE, static_cast<int32_t>(RecvFocused::NOTIFY_DOCK_FOCUSED),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("NotifyDockFocused error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::RecvUnfocused(const std::string& func)
{
    int32_t res = HiSysEventWrite(
        APP_CONTINUE_DOMAIN,
        APPLICATION_CONTINUE_BEHAVIOR,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        ORG_PKG, ORG_PKG_NAME,
        FUNC, func,
        BIZ_SCENE, static_cast<int32_t>(BizScene::RECV_UNFOCUSED),
        BIZ_STAGE, static_cast<int32_t>(RecvUnfocused::RECV_UNFOCUSED),
        STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
        BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_START),
        "BROADCAST_INFO", UNFOCUSED,
        TO_CALL_PKG, DSOFTBUS_PKG_NAME);
    if (res != ERR_OK) {
        HILOGE("RecvUnfocused error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::UnfocusedGetBundleName(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::RECV_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(RecvUnfocused::GET_DBMS_BUNDLENAME),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            TO_CALL_PKG, DBMS_PKG_NAME);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::RECV_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(RecvUnfocused::GET_DBMS_BUNDLENAME),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            TO_CALL_PKG, DBMS_PKG_NAME,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("UnfocusedGetBundleName error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::NotifyDockUnfocused(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::RECV_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(RecvUnfocused::NOTIFY_DOCK_UNFOCUSED),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC));
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::RECV_UNFOCUSED),
            BIZ_STAGE, static_cast<int32_t>(RecvUnfocused::NOTIFY_DOCK_UNFOCUSED),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("NotifyDockUnfocused error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::ClickIconDmsContinue(const std::string& func, int32_t errCode, std::string peerUdid,
    const std::string& srcBundleName, const std::string& dstBundleName)
{
    if (peerUdid.empty()) {
        HILOGE("peerUdid is empty.");
        return false;
    }
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::CLICK_ICON),
            BIZ_STAGE, static_cast<int32_t>(ClickIcon::DMS_CONTINUE),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            PEER_UDID, GetAnonyUdid(peerUdid),
            APP_CALLEE, srcBundleName,
            APP_CALLER, dstBundleName);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::CLICK_ICON),
            BIZ_STAGE, static_cast<int32_t>(ClickIcon::DMS_CONTINUE),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            PEER_UDID, GetAnonyUdid(peerUdid),
            APP_CALLEE, srcBundleName,
            APP_CALLER, dstBundleName,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("ClickIconDmsContinue error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::ClickIconDmsStartAbility(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::CLICK_ICON),
            BIZ_STAGE, static_cast<int32_t>(ClickIcon::DMS_STARTABILITY),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            TO_CALL_PKG, ABILITY_MANAGER_SERVICE);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::CLICK_ICON),
            BIZ_STAGE, static_cast<int32_t>(ClickIcon::DMS_STARTABILITY),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            TO_CALL_PKG, ABILITY_MANAGER_SERVICE,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("ClickIconDmsStartAbility error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::ClickIconDmsRecvOver(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::CLICK_ICON),
            BIZ_STAGE, static_cast<int32_t>(ClickIcon::DMS_RECV_OVER),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END));
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::CLICK_ICON),
            BIZ_STAGE, static_cast<int32_t>(ClickIcon::DMS_RECV_OVER),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END),
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("ClickIconDmsRecvOver error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::SaveDataDmsContinue(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::SAVE_DATA),
            BIZ_STAGE, static_cast<int32_t>(SaveData::DMS_CONTINUE),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_START),
            TO_CALL_PKG, ABILITY_MANAGER_SERVICE);
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::SAVE_DATA),
            BIZ_STAGE, static_cast<int32_t>(SaveData::DMS_CONTINUE),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_START),
            TO_CALL_PKG, ABILITY_MANAGER_SERVICE,
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("SaveDataDmsContinue error, res:%{public}d", res);
        return false;
    }
    return true;
}

bool DmsRadar::SaveDataDmsRemoteWant(const std::string& func, int32_t errCode)
{
    int32_t res = ERR_OK;
    StageRes stageRes = (errCode == ERR_OK) ? StageRes::STAGE_SUCC : StageRes::STAGE_FAIL;
    if (stageRes == StageRes::STAGE_SUCC) {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::SAVE_DATA),
            BIZ_STAGE, static_cast<int32_t>(SaveData::DMS_REMOTE_WANT),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_SUCC),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END));
    } else {
        res = HiSysEventWrite(
            APP_CONTINUE_DOMAIN,
            APPLICATION_CONTINUE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            ORG_PKG, ORG_PKG_NAME,
            FUNC, func,
            BIZ_SCENE, static_cast<int32_t>(BizScene::SAVE_DATA),
            BIZ_STAGE, static_cast<int32_t>(SaveData::DMS_REMOTE_WANT),
            STAGE_RES, static_cast<int32_t>(StageRes::STAGE_FAIL),
            BIZ_STATE, static_cast<int32_t>(BizState::BIZ_STATE_END),
            ERROR_CODE, errCode);
    }
    if (res != ERR_OK) {
        HILOGE("SaveDataDmsRemoteWant error, res:%{public}d", res);
        return false;
    }
    return true;
}

std::string DmsRadar::GetAnonyUdid(std::string udid)
{
    if (udid.empty() || udid.length() < ANONYM_MIN_LENGTH) {
        return "";
    }
    return udid.substr(0, SUBSTR_UDID_LENGTH) + "**" + udid.substr(udid.length() - SUBSTR_UDID_LENGTH);
}
} // namespace DistributedSchedule
} // namespace OHOS
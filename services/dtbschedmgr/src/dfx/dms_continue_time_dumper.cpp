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

#include "dfx/dms_continue_time_dumper.h"

#include <iomanip>
#include <sstream>

#include "adapter/dnetwork_adapter.h"
#include "cJSON.h"
#include "datetime_ex.h"
#include "dtbschedmgr_log.h"
#include "dtbschedmgr_device_info_storage.h"
#include "deviceManager/dms_device_info.h"
#include "distributed_device_node_listener.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DmsContinueTime";
const std::string DMSDURATION_STARTTIME = "Continue Start Time: ";
const std::string DMSDURATION_ENDTIME = "Continue End Time  : ";
const std::string DMSDURATION_TOTAL = "Total Time Cost             : ";
const std::string DMSDURATION_SINKTOSOURCERPC = "-- Request Transaction Cost : ";
const std::string DMSDURATION_SOURCEDATASAVE = "-- Source Data Save Cost    : ";
const std::string DMSDURATION_SOURCETOSINKRPC = "-- Data Transaction Cost    : ";
const std::string DMSDURATION_SINKABILITYSTART = "-- Sink Ability Start Cost  : ";
constexpr int32_t DMSDURATION_MAXSIZE = 100;
constexpr int32_t DMSDURATION_SPACE = 40;
constexpr int32_t DMSDURATION_TOTALTIME = 2;
constexpr int32_t DMSDURATION_DSTTOSRCRPCTIME = 3;
constexpr int32_t DMSDURATION_SAVETIME = 4;
constexpr int32_t DMSDURATION_SRCTODSTRPCTIME = 5;
constexpr int32_t DMSDURATION_STARTABILITY = 6;
}

IMPLEMENT_SINGLE_INSTANCE(DmsContinueTime);

DmsDuration::DmsDuration(const int64_t begin, const int64_t end, const std::string name)
{
    beginTime_ = begin;
    endTime_ = end;
    durationName_ = name;
}

void DmsDuration::SetBeginTime(const int64_t time)
{
    beginTime_ = time;
}

void DmsDuration::SetEndTime(const int64_t time)
{
    endTime_ = time;
}

void DmsDuration::SetDurationTime(const int64_t time)
{
    duration_ = time;
}

void DmsDuration::SetStrTime(const std::string name)
{
    strTime_ = name;
}

void DmsDuration::SetDurationName(const std::string name)
{
    durationName_ = name;
}

int64_t DmsDuration::GetBeginTime()
{
    return beginTime_;
}

int64_t DmsDuration::GetEndTime()
{
    return endTime_;
}

int64_t DmsDuration::GetDurationTime()
{
    return duration_;
}

std::string DmsDuration::GetStrTime()
{
    return strTime_;
}

std::string DmsDuration::GetDurationName()
{
    return durationName_;
}

void DmsContinueTime::Init()
{
    srcInfo_.bundleName.clear();
    srcInfo_.abilityName.clear();
    srcInfo_.netWorkId.clear();
    srcInfo_.deviceName.clear();
    dstInfo_.bundleName.clear();
    dstInfo_.abilityName.clear();
    dstInfo_.netWorkId.clear();
    dstInfo_.deviceName.clear();
    durationInfo_.clear();

    durationInfo_.push_back(DmsDuration(0, 0, DMSDURATION_STARTTIME));
    durationInfo_.push_back(DmsDuration(0, 0, DMSDURATION_ENDTIME));
    durationInfo_.push_back(DmsDuration(0, 0, DMSDURATION_TOTAL));
    durationInfo_.push_back(DmsDuration(0, 0, DMSDURATION_SINKTOSOURCERPC));
    durationInfo_.push_back(DmsDuration(0, 0, DMSDURATION_SOURCEDATASAVE));
    durationInfo_.push_back(DmsDuration(0, 0, DMSDURATION_SOURCETOSINKRPC));
    durationInfo_.push_back(DmsDuration(0, 0, DMSDURATION_SINKABILITYSTART));
}

void DmsContinueTime::SetPull(bool sign)
{
    isPull_ = sign;
}

bool DmsContinueTime::GetPull()
{
    return isPull_;
}

void DmsContinueTime::SetSrcBundleName(const std::string bundleName)
{
    srcInfo_.bundleName = bundleName;
}

void DmsContinueTime::SetSrcAbilityName(const std::string abilityName)
{
    srcInfo_.abilityName = abilityName;
}

void DmsContinueTime::SetDstBundleName(const std::string bundleName)
{
    dstInfo_.bundleName = bundleName;
}

void DmsContinueTime::SetDstAbilityName(const std::string abilityName)
{
    dstInfo_.abilityName = abilityName;
}

void DmsContinueTime::SetNetWorkId(const std::string srcNetWorkId, const std::string dstNetWorkId)
{
    srcInfo_.netWorkId = srcNetWorkId;
    dstInfo_.netWorkId = dstNetWorkId;
}

void DmsContinueTime::SetDeviceNamePull()
{
    srcInfo_.deviceName = DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceName(srcInfo_.netWorkId);

    DistributedHardware::DmDeviceInfo dmDeviceInfo;
    DnetworkAdapter::GetInstance()->GetLocalBasicInfo(dmDeviceInfo);
    dstInfo_.deviceName = dmDeviceInfo.deviceName;
}

void DmsContinueTime::SetDeviceNamePush()
{
    dstInfo_.deviceName = DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceName(dstInfo_.netWorkId);

    DistributedHardware::DmDeviceInfo dmDeviceInfo;
    DnetworkAdapter::GetInstance()->GetLocalBasicInfo(dmDeviceInfo);
    srcInfo_.deviceName = dmDeviceInfo.deviceName;
}

DmsDumperInfo DmsContinueTime::GetDstInfo()
{
    return dstInfo_;
}

void DmsContinueTime::SetDurationBegin(const int32_t idx, const int64_t time)
{
    if (durationInfo_.empty()) {
        return;
    }
    durationInfo_[idx].SetBeginTime(time);
}

void DmsContinueTime::SetDurationEnd(const int32_t idx, const int64_t time)
{
    if (durationInfo_.empty()) {
        return;
    }
    durationInfo_[idx].SetEndTime(time);
}

void DmsContinueTime::SetDurationStrTime(const int32_t idx, const std::string info)
{
    if (durationInfo_.empty()) {
        return;
    }
    durationInfo_[idx].SetStrTime(info);
}

void DmsContinueTime::SetSaveDataDurationBegin(const int64_t time)
{
    saveDataDuration_.SetBeginTime(time);
}

void DmsContinueTime::SetSaveDataDurationEnd(const int64_t time)
{
    saveDataDuration_.SetEndTime(time);
}

DmsDuration DmsContinueTime::GetSaveDataDuration()
{
    return saveDataDuration_;
}

std::string DmsContinueTime::WriteDurationInfo(DmsDuration duration)
{
    cJSON* durationInfo = cJSON_CreateObject();
    if (durationInfo == nullptr) {
        HILOGW("Create cJSON Object failed!");
        return "";
    }
    cJSON_AddNumberToObject(durationInfo, "beginTime", duration.GetBeginTime());
    cJSON_AddNumberToObject(durationInfo, "endTime", duration.GetEndTime());
    char* cjson_str = cJSON_PrintUnformatted(durationInfo);
    std::string message(cjson_str);
    if (message.empty()) {
        HILOGW("Write Info failed!");
    }
    cJSON_Delete(durationInfo);
    free(cjson_str);
    return message;
}

void DmsContinueTime::ReadDurationInfo(const char* info)
{
    cJSON* durationInfo = cJSON_Parse(info);
    if (durationInfo == nullptr) {
        HILOGW("Accept cJSON Object failed!");
        return;
    }
    cJSON* beginTimeItem = cJSON_GetObjectItem(durationInfo, "beginTime");
    if (beginTimeItem == NULL) {
        cJSON_Delete(durationInfo);
        return;
    }
    int64_t beginTime = beginTimeItem->valueint;
    cJSON* endTimeItem = cJSON_GetObjectItem(durationInfo, "endTime");
    if (endTimeItem == NULL) {
        cJSON_Delete(durationInfo);
        return;
    }
    int64_t endTime = endTimeItem->valueint;
    saveDataDuration_.SetBeginTime(beginTime);
    saveDataDuration_.SetEndTime(endTime);
    cJSON_Delete(durationInfo);
}

std::string DmsContinueTime::WriteDstInfo(const std::string bundleName, const std::string abilityName)
{
    cJSON* info = cJSON_CreateObject();
    if (info == nullptr) {
        HILOGW("Create cJSON Object failed!");
        return "";
    }
    cJSON_AddStringToObject(info, "DstBundleName", bundleName.c_str());
    cJSON_AddStringToObject(info, "DstAbilityName", abilityName.c_str());
    char* cjson_str = cJSON_PrintUnformatted(info);
    std::string message(cjson_str);
    if (message.empty()) {
        HILOGW("Write info failed!");
    }
    cJSON_Delete(info);
    free(cjson_str);
    return message;
}

void DmsContinueTime::ReadDstInfo(const char* info)
{
    cJSON* dstInfo = cJSON_Parse(info);
    if (dstInfo == nullptr) {
        HILOGW("Accept cJSON Object failed!");
        return;
    }
    cJSON* bundleNameItem = cJSON_GetObjectItem(dstInfo, "DstBundleName");
    if (bundleNameItem == NULL) {
        cJSON_Delete(dstInfo);
        return;
    }
    std::string bundleName = bundleNameItem->valuestring;
    cJSON* abilityNameItem = cJSON_GetObjectItem(dstInfo, "DstAbilityName");
    if (abilityNameItem == NULL) {
        cJSON_Delete(dstInfo);
        return;
    }
    std::string abilityName = abilityNameItem->valuestring;
    dstInfo_.bundleName = bundleName;
    dstInfo_.abilityName = abilityName;
    cJSON_Delete(dstInfo);
}

std::string DmsContinueTime::GetCurrentTime()
{
    std::chrono::system_clock::time_point time = std::chrono::system_clock::now();
    std::time_t time_c = std::chrono::system_clock::to_time_t(time);
    std::tm* time_tm = std::localtime(&time_c);
    std::stringstream timeStr;
    timeStr << std::put_time(time_tm, "%Y/%m/%d %H:%M:%S");
    return timeStr.str();
}

void DmsContinueTime::DealDurationPull()
{
    durationInfo_[DMSDURATION_SAVETIME].SetBeginTime(saveDataDuration_.GetBeginTime());
    durationInfo_[DMSDURATION_SAVETIME].SetEndTime(saveDataDuration_.GetEndTime());

    for (auto& duration : durationInfo_) {
        if (duration.GetStrTime().empty() && duration.GetBeginTime() != 0 && duration.GetEndTime() != 0) {
            duration.SetDurationTime(duration.GetEndTime() - duration.GetBeginTime());
            duration.SetStrTime(std::to_string(duration.GetDurationTime()) += "ms");
        }
    }
    durationInfo_[DMSDURATION_SRCTODSTRPCTIME].SetDurationTime(
        durationInfo_[DMSDURATION_TOTALTIME].GetDurationTime() -
        durationInfo_[DMSDURATION_DSTTOSRCRPCTIME].GetDurationTime() -
        durationInfo_[DMSDURATION_SAVETIME].GetDurationTime() -
        durationInfo_[DMSDURATION_STARTABILITY].GetDurationTime());
    durationInfo_[DMSDURATION_SRCTODSTRPCTIME].SetStrTime(
        std::to_string(durationInfo_[DMSDURATION_SRCTODSTRPCTIME].GetDurationTime()) += "ms");
}

void DmsContinueTime::DealDurationPush()
{
    durationInfo_[DMSDURATION_SAVETIME].SetBeginTime(saveDataDuration_.GetBeginTime());
    durationInfo_[DMSDURATION_SAVETIME].SetEndTime(saveDataDuration_.GetEndTime());

    for (auto& duration : durationInfo_) {
        if (duration.GetStrTime().empty() && duration.GetBeginTime() != 0 && duration.GetEndTime() != 0) {
            duration.SetDurationTime(duration.GetEndTime() - duration.GetBeginTime());
            duration.SetStrTime(std::to_string(duration.GetDurationTime()) += "ms");
        }
    }
    durationInfo_[DMSDURATION_STARTABILITY].SetDurationTime(
        durationInfo_[DMSDURATION_STARTABILITY].GetDurationTime() -
        durationInfo_[DMSDURATION_SRCTODSTRPCTIME].GetDurationTime());
    durationInfo_[DMSDURATION_STARTABILITY].SetStrTime(
        std::to_string(durationInfo_[DMSDURATION_STARTABILITY].GetDurationTime()) += "ms");
}

void DmsContinueTime::AppendInfo()
{
    if (isPull_) {
        SetDeviceNamePull();
        DealDurationPull();
        appendInfo_.append("PULL\n");
    } else {
        SetDeviceNamePush();
        DealDurationPush();
        appendInfo_.append("PUSH\n");
    }

    std::stringstream str;
    str << "== SOURCE ==\n"
        << "Network Id  : " << std::setw(DMSDURATION_SPACE) << std::left
        << DnetworkAdapter::AnonymizeNetworkId(srcInfo_.netWorkId.c_str())
        << "Device Name  : " << srcInfo_.deviceName << "\n"
        << "Bundle Name : " << std::setw(DMSDURATION_SPACE) << std::left
        << srcInfo_.bundleName
        << "Ability Name : " << srcInfo_.abilityName << "\n"
        << "== SINK ==\n"
        << "Network Id  : " << std::setw(DMSDURATION_SPACE) << std::left
        << DnetworkAdapter::AnonymizeNetworkId(dstInfo_.netWorkId.c_str())
        << "Device Name  : " << dstInfo_.deviceName << "\n"
        << "Bundle Name : " << std::setw(DMSDURATION_SPACE) << std::left
        << dstInfo_.bundleName
        << "Ability Name : " << dstInfo_.abilityName << "\n";
    appendInfo_.append(str.str());
    appendInfo_.append("------------------------------------------------------------------------------------\n");

    for (auto duration : durationInfo_) {
        appendInfo_.append(duration.GetDurationName().c_str());
        appendInfo_.append(duration.GetStrTime().c_str());
        appendInfo_.append("\n");
    }

    if (timeInfoList_.size() >= DMSDURATION_MAXSIZE) {
        timeInfoList_.pop_front();
    }
    timeInfoList_.push_back(appendInfo_);
    appendInfo_.clear();
    durationInfo_.clear();
}

void DmsContinueTime::ShowInfo(std::string& result)
{
    int32_t nIdx = 1;
    for (const auto& info : timeInfoList_) {
        result.append("[" + std::to_string(nIdx) + "]\n");
        result.append("------------------------------------------------------------------------------------\n");
        result.append(info.c_str());
        result.append("------------------------------------------------------------------------------------\n");
        nIdx++;
    }
}
}
}
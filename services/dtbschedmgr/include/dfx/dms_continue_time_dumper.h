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

#ifndef OHOS_DISTRIBUTED_CONTINUE_TIME_DUMPER_H
#define OHOS_DISTRIBUTED_CONTINUE_TIME_DUMPER_H

#include <list>
#include <string>
#include <vector>

#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {

struct DmsDumperInfo {
    std::string bundleName;
    std::string netWorkId;
    std::string abilityName;
    std::string deviceName;
};

class DmsDuration {
public:
    DmsDuration() = default;
    DmsDuration(const int64_t begin, const int64_t end, const std::string name);
    ~DmsDuration() = default;

    void SetBeginTime(const int64_t time);
    void SetEndTime(const int64_t time);
    void SetDurationTime(const int64_t time);
    void SetStrTime(const std::string name);
    void SetDurationName(const std::string name);

    int64_t GetBeginTime();
    int64_t GetEndTime();
    int64_t GetDurationTime();
    std::string GetStrTime();
    std::string GetDurationName();

private:
    int64_t beginTime_;
    int64_t endTime_;
    int64_t duration_ = 0;
    std::string strTime_;
    std::string durationName_;
};

class DmsContinueTime {
public:
    DECLARE_SINGLE_INSTANCE_BASE(DmsContinueTime);
    
public:
    DmsContinueTime() = default;
    ~DmsContinueTime() = default;

    void Init();
    void SetPull(bool sign);
    bool GetPull();
    void SetSrcBundleName(const std::string bundleName);
    void SetSrcAbilityName(const std::string abilityName);
    void SetDstBundleName(const std::string bundleName);
    void SetDstAbilityName(const std::string abilityName);
    void SetNetWorkId(const std::string srcNetWorkId, const std::string dstNetWorkId);
    void SetDeviceNamePull();
    void SetDeviceNamePush();
    DmsDumperInfo GetDstInfo();

    void SetDurationBegin(const int32_t idx, const int64_t time);
    void SetDurationEnd(const int32_t idx, const int64_t time);
    void SetDurationStrTime(const int32_t idx, const std::string info);

    void SetSaveDataDurationBegin(const int64_t time);
    void SetSaveDataDurationEnd(const int64_t time);
    DmsDuration GetSaveDataDuration();

    std::string WriteDurationInfo(DmsDuration duration);
    void ReadDurationInfo(const char* info);
    std::string WriteDstInfo(const std::string bundleName, const std::string abilityName);
    void ReadDstInfo(const char* info);
    std::string GetCurrentTime();
    void DealDurationPull();
    void DealDurationPush();
    void AppendInfo();
    void ShowInfo(std::string& result);

private:
    bool isPull_;
    std::list<std::string> timeInfoList_;
    std::vector<DmsDuration> durationInfo_;
    std::string appendInfo_;
    DmsDumperInfo srcInfo_;
    DmsDumperInfo dstInfo_;
    DmsDuration saveDataDuration_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_CONTINUE_TIME_DUMPER_H
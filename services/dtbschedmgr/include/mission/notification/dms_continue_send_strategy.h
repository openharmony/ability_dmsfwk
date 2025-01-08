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

#ifndef OHOS_DMS_CONTINUE_SEND_STRATEGY_H
#define OHOS_DMS_CONTINUE_SEND_STRATEGY_H

#include <string>

#include "mission/dms_continue_condition_manager.h"

namespace OHOS {
namespace DistributedSchedule {
class DMSContinueSendMgr;

class ContinueSendStrategy {
public:
    ContinueSendStrategy() = default;

    virtual ~ContinueSendStrategy() = default;
    virtual int32_t ExecuteSendStrategy(const MissionStatus& status, uint8_t &sendType) const = 0;
};

class ContinueSendContext {
public:
    ContinueSendContext() = default;

    void SetStrategy(std::shared_ptr<ContinueSendStrategy> strategy);
    int32_t ExecuteSendStrategy(const MissionStatus& status, uint8_t &sendType) const;
private:
    std::shared_ptr<ContinueSendStrategy> strategy_;
};

class SendStrategyFocused : public ContinueSendStrategy {
public:
    explicit SendStrategyFocused(const std::shared_ptr<DMSContinueSendMgr>& dmsContinueSendMgr)
        : dmsContinueSendMgr_(dmsContinueSendMgr) {};
    int32_t ExecuteSendStrategy(const MissionStatus& status, uint8_t &sendType) const override;
private:
    std::weak_ptr<DMSContinueSendMgr> dmsContinueSendMgr_;
};

class SendStrategyUnfocused : public ContinueSendStrategy {
public:
    explicit SendStrategyUnfocused(const std::shared_ptr<DMSContinueSendMgr>& dmsContinueSendMgr)
        : dmsContinueSendMgr_(dmsContinueSendMgr) {};
    int32_t ExecuteSendStrategy(const MissionStatus& status, uint8_t &sendType) const override;
private:
    std::weak_ptr<DMSContinueSendMgr> dmsContinueSendMgr_;
};

class SendStrategyDestoryed : public ContinueSendStrategy {
public:
    explicit SendStrategyDestoryed(const std::shared_ptr<DMSContinueSendMgr>& dmsContinueSendMgr)
        : dmsContinueSendMgr_(dmsContinueSendMgr) {};
    int32_t ExecuteSendStrategy(const MissionStatus& status, uint8_t &sendType) const override;
private:
    std::weak_ptr<DMSContinueSendMgr> dmsContinueSendMgr_;
};

class SendStrategyActive : public ContinueSendStrategy {
public:
    explicit SendStrategyActive(const std::shared_ptr<DMSContinueSendMgr>& dmsContinueSendMgr)
        : dmsContinueSendMgr_(dmsContinueSendMgr) {};
    int32_t ExecuteSendStrategy(const MissionStatus& status, uint8_t &sendType) const override;
private:
    std::weak_ptr<DMSContinueSendMgr> dmsContinueSendMgr_;
};

class SendStrategyInactive : public ContinueSendStrategy {
public:
    explicit SendStrategyInactive(const std::shared_ptr<DMSContinueSendMgr>& dmsContinueSendMgr)
        : dmsContinueSendMgr_(dmsContinueSendMgr) {};
    int32_t ExecuteSendStrategy(const MissionStatus& status, uint8_t &sendType) const override;
private:
    std::weak_ptr<DMSContinueSendMgr> dmsContinueSendMgr_;
};

class SendStrategyTimeout : public ContinueSendStrategy {
public:
    explicit SendStrategyTimeout(const std::shared_ptr<DMSContinueSendMgr>& dmsContinueSendMgr)
        : dmsContinueSendMgr_(dmsContinueSendMgr) {};
    int32_t ExecuteSendStrategy(const MissionStatus& status, uint8_t &sendType) const override;
private:
    std::weak_ptr<DMSContinueSendMgr> dmsContinueSendMgr_;
};

class SendStrategyMMI : public ContinueSendStrategy {
public:
    explicit SendStrategyMMI(const std::shared_ptr<DMSContinueSendMgr>& dmsContinueSendMgr)
        : dmsContinueSendMgr_(dmsContinueSendMgr) {};
    int32_t ExecuteSendStrategy(const MissionStatus& status, uint8_t &sendType) const override;
private:
    std::weak_ptr<DMSContinueSendMgr> dmsContinueSendMgr_;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DMS_CONTINUE_SEND_STRATEGY_H

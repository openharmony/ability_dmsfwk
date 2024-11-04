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

#ifndef MOCK_DISTRIBUTED_SCHED_ADAPTER_H
#define MOCK_DISTRIBUTED_SCHED_ADAPTER_H

#include <gmock/gmock.h>
#include <string>

#include "distributed_sched_adapter.h"

namespace OHOS {
namespace DistributedSchedule {
class AdapterMock {
public:
    virtual ~AdapterMock() = default;
public:
    virtual int32_t GetLocalMissionSnapshotInfo(const std::string& networkId, int32_t missionId,
        AAFwk::MissionSnapshot& missionSnapshot) = 0;
public:
    static inline std::shared_ptr<AdapterMock> dmsAdapter = nullptr;
};

class MockAdapter : public AdapterMock {
public:
    MOCK_METHOD(int32_t, GetLocalMissionSnapshotInfo, (const std::string& networkId, int32_t missionId,
        AAFwk::MissionSnapshot& missionSnapshot));
};
}
}
#endif //MOCK_DISTRIBUTED_SCHED_ADAPTER_H
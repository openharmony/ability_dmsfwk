/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef DSCHED_SYNC_E2E_MOCK_H
#define DSCHED_SYNC_E2E_MOCK_H

#include <gmock/gmock.h>

#include "mission/dsched_sync_e2e.h"

namespace OHOS {
namespace DistributedSchedule {

class IDmsKvSyncE2E {
public:
    virtual ~IDmsKvSyncE2E() = default;
    virtual bool PushAndPullData() = 0;
    virtual bool PushAndPullData(const std::string &networkId) = 0;
    virtual bool CheckDeviceCfg() = 0;
    virtual bool CheckCtrlRule() = 0;
    virtual bool CheckBundleContinueConfig(const std::string &bundleName) = 0;
public:
    static inline std::shared_ptr<IDmsKvSyncE2E> dmsKvMock = nullptr;
};

class DmsKvSyncE2EMock : public IDmsKvSyncE2E {
public:
    MOCK_METHOD0(PushAndPullData, bool());
    MOCK_METHOD1(PushAndPullData, bool(const std::string &networkId));
    MOCK_METHOD0(CheckDeviceCfg, bool());
    MOCK_METHOD0(CheckCtrlRule, bool());
    MOCK_METHOD1(CheckBundleContinueConfig, bool(const std::string &bundleName));
};
}
}
#endif
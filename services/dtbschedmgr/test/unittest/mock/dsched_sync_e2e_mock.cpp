/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dsched_sync_e2e_mock.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::DistributedSchedule;

bool DmsKvSyncE2E::PushAndPullData()
{
    if (IDmsKvSyncE2E::dmsKvMock == nullptr) {
        return false;
    }
    return IDmsKvSyncE2E::dmsKvMock->PushAndPullData();
}

bool DmsKvSyncE2E::PushAndPullData(const std::string &networkId)
{
    if (IDmsKvSyncE2E::dmsKvMock == nullptr) {
        return false;
    }
    return IDmsKvSyncE2E::dmsKvMock->PushAndPullData(networkId);
}

bool DmsKvSyncE2E::CheckDeviceCfg()
{
    if (IDmsKvSyncE2E::dmsKvMock == nullptr) {
        return false;
    }
    return IDmsKvSyncE2E::dmsKvMock->CheckDeviceCfg();
}

bool DmsKvSyncE2E::CheckCtrlRule()
{
    if (IDmsKvSyncE2E::dmsKvMock == nullptr) {
        return false;
    }
    return IDmsKvSyncE2E::dmsKvMock->CheckCtrlRule();
}

bool DmsKvSyncE2E::CheckBundleContinueConfig(const std::string &bundleName)
{
    if (IDmsKvSyncE2E::dmsKvMock == nullptr) {
        return false;
    }
    return IDmsKvSyncE2E::dmsKvMock->CheckBundleContinueConfig(bundleName);
}

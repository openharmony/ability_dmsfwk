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

#include "dsched_continue_manager.h"

#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DSchedContinueManager";
}

IMPLEMENT_SINGLE_INSTANCE(DSchedContinueManager);

DSchedContinueManager::DSchedContinueManager()
{
}

DSchedContinueManager::~DSchedContinueManager()
{
    HILOGI("DSchedContinueManager delete");
}

int32_t DSchedContinueManager::ContinueMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
    int32_t missionId, const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams)
{
    return ERR_OK;
}

int32_t DSchedContinueManager::ContinueMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
    std::string bundleName, const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams)
{
    return ERR_OK;
}

void DSchedContinueManager::OnDataRecv(std::shared_ptr<DSchedDataBuffer> data)
{
}

void DSchedContinueManager::OnShutDown()
{
}

void DSchedContinueManager::OnBind()
{
}
}  // namespace DistributedSchedule
}  // namespace OHOS
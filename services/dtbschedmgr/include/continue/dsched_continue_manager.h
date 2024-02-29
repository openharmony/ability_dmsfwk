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

#ifndef OHOS_DSCHED_CONTINUE_MANAGER_H
#define OHOS_DSCHED_CONTINUE_MANAGER_H

#include <map>
#include <string>

#include "dsched_data_buffer.h"
#include "dsched_continue.h"
#include "iremote_object.h"
#include "single_instance.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {
class DSchedContinueManager {
DECLARE_SINGLE_INSTANCE_BASE(DSchedContinueManager);
public:
    int32_t ContinueMission(const std::string &srcDeviceId, const std::string &dstDeviceId,
        int32_t missionId, const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams &wantParams);
    int32_t ContinueMission(const std::string &srcDeviceId, const std::string &dstDeviceId,
        std::string bundleName, const sptr<IRemoteObject> &callback, const OHOS::AAFwk::WantParams &wantParams);

    void OnDataRecv(std::shared_ptr<DSchedDataBuffer> data);
    void OnShutDown();
    void OnBind();

private:
    DSchedContinueManager();
    ~DSchedContinueManager();

private:
    std::map<DSchedContinueInfo, std::shared_ptr<DSchedContinue>> continues_;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_CONTINUE_MANAGER_H
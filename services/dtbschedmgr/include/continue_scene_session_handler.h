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

#ifndef OHOS_DISTRIBUTED_CONTINUE_SCENE_SESSION_HANDLER_H
#define OHOS_DISTRIBUTED_CONTINUE_SCENE_SESSION_HANDLER_H

#include <string>

#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {
class ContinueSceneSessionHandler {
public:
    DECLARE_SINGLE_INSTANCE_BASE(ContinueSceneSessionHandler);
public:
    ContinueSceneSessionHandler() = default;
    virtual ~ContinueSceneSessionHandler() = default;
    void UpdateContinueSessionId(const std::string& bundleName, const std::string& abilityName);
    std::string GetContinueSessionId() const;
    void ClearContinueSessionId();
    int32_t GetPersistentId(int32_t& persistentId);
    int32_t GetPersistentId(int32_t& persistentId, std::string &continueSessionId);
private:
    std::string continueSessionId_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_CONTINUE_SCENE_SESSION_HANDLER_H
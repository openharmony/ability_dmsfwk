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

#include "continue_scene_session_handler.h"

#include <chrono>
#include <thread>

#include "dtbschedmgr_log.h"
#include "scene_board_judgement.h"
#include "session_manager_lite.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "ContinueSceneSessionHandler";
constexpr int32_t RETRY_TIMES = 60;
constexpr int32_t SLEEP_TIME = 50;
}

IMPLEMENT_SINGLE_INSTANCE(ContinueSceneSessionHandler);

using OHOS::Rosen::SessionManagerLite;
using OHOS::Rosen::WSError;

void ContinueSceneSessionHandler::UpdateContinueSessionId(const std::string& bundleName, const std::string& abilityName)
{
    HILOGD("Update continueSessionId, bundleName: %{public}s, abilityName: %{public}s",
        bundleName.c_str(), abilityName.c_str());
    auto now = std::chrono::system_clock::now();
    int64_t timeStamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::size_t hash = std::hash<std::string>()(bundleName + abilityName + std::to_string(timeStamp));
    continueSessionId_ = std::to_string(hash);
}

std::string ContinueSceneSessionHandler::GetContinueSessionId() const
{
    return continueSessionId_;
}

void ContinueSceneSessionHandler::ClearContinueSessionId()
{
    HILOGI("%{public}s called", __func__);
    continueSessionId_.clear();
}

int32_t ContinueSceneSessionHandler::GetPersistentId(int32_t& persistentId)
{
    HILOGI("%{public}s called", __func__);
    if (continueSessionId_.empty()) {
        HILOGE("continueSessionId is empty.");
        return INVALID_PARAMETERS_ERR;
    }
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        HILOGE("sceneBoard not available.");
        return INVALID_PARAMETERS_ERR;
    }

    auto sceneSessionManager = SessionManagerLite::GetInstance().GetSceneSessionManagerLiteProxy();
    if (!sceneSessionManager) {
        HILOGE("proxy is nullptr.");
        return INVALID_PARAMETERS_ERR;
    }
    
    int32_t retryTimeout = RETRY_TIMES;
    AAFwk::MissionInfo missionInfo;
    do {
        auto err = sceneSessionManager->GetSessionInfoByContinueSessionId(continueSessionId_, missionInfo);
        if (err == WSError::WS_OK) {
            persistentId = missionInfo.id;
            return ERR_OK;
        }
        HILOGE("Get sessionInfo failed, continueSessionId: %{public}s, errorCode: %{public}d",
            continueSessionId_.c_str(), err);
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    } while (--retryTimeout >= 0);
    
    return INVALID_PARAMETERS_ERR;
}
} // namespace DistributedSchedule
} // namespace OHOS
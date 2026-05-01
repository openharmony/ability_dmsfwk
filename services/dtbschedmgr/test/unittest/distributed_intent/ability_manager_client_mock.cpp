/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ability_manager_client_mock.h"
#include "ability_manager_client.h"
#include "single_instance.h"

namespace OHOS {
namespace AAFwk {

const int ERR_FAIL = -1;

ErrCode ExecuteIntentForDistributed(const Want& want,
    const std::string& srcDeviceId, uint64_t requestCode, uint64_t dAccessToken)
{
    if (IAbilityManagerClient::abilityMock == nullptr) {
        return ERR_FAIL;
    }
    return IAbilityManagerClient::abilityMock->ExecuteIntentForDistributed(want,
        srcDeviceId, requestCode, dAccessToken);
}

} // namespace AAFwk
} // namespace OHOS
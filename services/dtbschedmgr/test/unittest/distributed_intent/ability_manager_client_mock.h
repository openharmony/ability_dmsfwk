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

#ifndef ABILITY_MANAGER_CLIENT_MOCK_H
#define ABILITY_MANAGER_CLIENT_MOCK_H

#include <gmock/gmock.h>
#include <string>
#include "want.h"
#include "errors.h"

namespace OHOS {
namespace AAFwk {

class IAbilityManagerClient {
public:
    virtual ~IAbilityManagerClient() = default;
    virtual ErrCode ExecuteIntentForDistributed(const Want& want, const std::string& srcDeviceId,
        uint64_t requestCode, uint64_t dAccessToken) = 0;
    static inline std::shared_ptr<IAbilityManagerClient> abilityMock = nullptr;
};

class AbilityManagerClientMock : public IAbilityManagerClient {
public:
    MOCK_METHOD4(ExecuteIntentForDistributed, ErrCode(const Want& want, const std::string& srcDeviceId,
        uint64_t requestCode, uint64_t dAccessToken));
};

} // namespace AAFwk
} // namespace OHOS
#endif // ABILITY_MANAGER_CLIENT_MOCK_H
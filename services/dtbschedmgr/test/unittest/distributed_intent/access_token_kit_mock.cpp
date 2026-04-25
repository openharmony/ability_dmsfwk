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

#include "access_token_kit_mock.h"
#include "accesstoken_kit.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(uint32_t token)
{
    if (IAccessTokenKit::tokenMock == nullptr) {
        return TOKEN_INVALID;
    }
    return IAccessTokenKit::tokenMock->GetTokenTypeFlag(token);
}

int32_t AccessTokenKit::GetHapTokenInfo(uint32_t token, HapTokenInfo& hapInfo)
{
    if (IAccessTokenKit::tokenMock == nullptr) {
        return RET_FAILED;
    }
    return IAccessTokenKit::tokenMock->GetHapTokenInfo(token, hapInfo);
}

bool AccessTokenKit::IsSystemAppByFullTokenID(uint64_t fullTokenId)
{
    if (IAccessTokenKit::tokenMock == nullptr) {
        return false;
    }
    return IAccessTokenKit::tokenMock->IsSystemAppByFullTokenID(fullTokenId);
}

int32_t AccessTokenKit::VerifyAccessToken(AccessTokenID token, const std::string& permission)
{
    if (IAccessTokenKit::tokenMock == nullptr) {
        return PERMISSION_DENIED;
    }
    return IAccessTokenKit::tokenMock->VerifyAccessToken(token, permission);
}

uint64_t AccessTokenKit::AllocLocalTokenID(const std::string& sourceDeviceId, uint32_t accessToken)
{
    if (IAccessTokenKit::tokenMock == nullptr) {
        return 0;
    }
    return IAccessTokenKit::tokenMock->AllocLocalTokenID(sourceDeviceId, accessToken);
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
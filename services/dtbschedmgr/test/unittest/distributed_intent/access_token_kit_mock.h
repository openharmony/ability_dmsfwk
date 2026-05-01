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

#ifndef ACCESS_TOKEN_KIT_MOCK_H
#define ACCESS_TOKEN_KIT_MOCK_H

#include <gmock/gmock.h>
#include <string>
#include "accesstoken_kit.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

class IAccessTokenKit {
public:
    virtual ~IAccessTokenKit() = default;
    virtual ATokenTypeEnum GetTokenTypeFlag(uint32_t token) = 0;
    virtual int32_t GetHapTokenInfo(uint32_t token, HapTokenInfo& hapInfo) = 0;
    virtual bool IsSystemAppByFullTokenID(uint64_t fullTokenId) = 0;
    virtual int32_t VerifyAccessToken(uint64_t token, const std::string& permission) = 0;
    virtual uint64_t AllocLocalTokenID(const std::string& sourceDeviceId, uint32_t accessToken) = 0;
public:
    static inline std::shared_ptr<IAccessTokenKit> tokenMock = nullptr;
};

class AccessTokenKitMock : public IAccessTokenKit {
public:
    MOCK_METHOD1(GetTokenTypeFlag, ATokenTypeEnum(uint32_t token));
    MOCK_METHOD2(GetHapTokenInfo, int32_t(uint32_t token, HapTokenInfo& hapInfo));
    MOCK_METHOD1(IsSystemAppByFullTokenID, bool(uint64_t fullTokenId));
    MOCK_METHOD2(VerifyAccessToken, int32_t(uint64_t token, const std::string& permission));
    MOCK_METHOD2(AllocLocalTokenID, uint64_t(const std::string& sourceDeviceId, uint32_t accessToken));
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_TOKEN_KIT_MOCK_H
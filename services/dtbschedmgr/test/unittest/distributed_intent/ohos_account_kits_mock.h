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

#ifndef OHOS_ACCOUNT_KITS_MOCK_H
#define OHOS_ACCOUNT_KITS_MOCK_H

#include <gmock/gmock.h>
#include <memory>
#include "ohos_account_kits.h"
#include "distributed_account_subscribe_callback.h"

namespace OHOS {
namespace AccountSA {

class IOhosAccountKits {
public:
    virtual ~IOhosAccountKits() = default;
    virtual int32_t GetOhosAccountInfo(OhosAccountInfo& info) = 0;
public:
    static inline std::shared_ptr<IOhosAccountKits> ohosAccountMock = nullptr;
};

class OhosAccountKitsMock : public IOhosAccountKits {
public:
    MOCK_METHOD1(GetOhosAccountInfo, int32_t(OhosAccountInfo& info));
};

} // namespace AccountSA
} // namespace OHOS
#endif // OHOS_ACCOUNT_KITS_MOCK_H
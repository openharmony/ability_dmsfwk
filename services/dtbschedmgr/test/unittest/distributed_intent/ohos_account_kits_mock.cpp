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

#include "ohos_account_kits_mock.h"
#include "ohos_account_kits.h"

namespace OHOS {
namespace AccountSA {

const int ERR_FAIL = -1;

int32_t GetOhosAccountInfo(OhosAccountInfo& info)
{
    if (IOhosAccountKits::ohosAccountMock == nullptr) {
        return ERR_FAIL;
    }
    return IOhosAccountKits::ohosAccountMock->GetOhosAccountInfo(info);
}

} // namespace AccountSA
} // namespace OHOS

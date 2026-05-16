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

class MockOhosAccountKits : public OhosAccountKits {
public:
    std::pair<bool, OhosAccountInfo> QueryOhosAccountInfo() override
    {
        return {false, {}};
    }

    ErrCode GetOhosAccountInfo(OhosAccountInfo& accountInfo) override
    {
        if (IOhosAccountKits::ohosAccountMock == nullptr) {
            return ERR_FAIL;
        }
        return IOhosAccountKits::ohosAccountMock->GetOhosAccountInfo(accountInfo);
    }

    ErrCode GetOsAccountDistributedInfo(int32_t localId, OhosAccountInfo& accountInfo) override
    {
        return ERR_FAIL;
    }

    std::pair<bool, OhosAccountInfo> QueryOsAccountDistributedInfo(std::int32_t localId) override
    {
        return {false, {}};
    }

    ErrCode UpdateOhosAccountInfo(const std::string& accountName, const std::string& uid,
        const std::string& eventStr) override
    {
        return ERR_FAIL;
    }

    ErrCode SetOhosAccountInfo(const OhosAccountInfo& ohosAccountInfo,
    const std::string& eventStr) override
    {
        return ERR_FAIL;
    }

    ErrCode SetOsAccountDistributedInfo(
        const int32_t localId, const OhosAccountInfo& ohosAccountInfo, const std::string& eventStr) override
    {
        return ERR_FAIL;
    }

    ErrCode QueryDeviceAccountId(std::int32_t& accountId) override
    {
        return ERR_FAIL;
    }

    ErrCode GetDeviceAccountIdByUID(std::int32_t& uid) override
    {
        return ERR_FAIL;
    }

    ErrCode SubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const std::shared_ptr<DistributedAccountSubscribeCallback>& callback) override
    {
        return ERR_FAIL;
    }

    ErrCode UnsubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const std::shared_ptr<DistributedAccountSubscribeCallback>& callback) override
    {
        return ERR_FAIL;
    }
};

static MockOhosAccountKits g_mockOhosAccountKits;

OhosAccountKits& OhosAccountKits::GetInstance()
{
    return g_mockOhosAccountKits;
}

} // namespace AccountSA
} // namespace OHOS

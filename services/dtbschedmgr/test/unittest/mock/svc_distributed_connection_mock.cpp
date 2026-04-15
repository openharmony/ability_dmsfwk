/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "svc_distributed_connection_mock.h"

namespace OHOS {
namespace DistributedSchedule {
ErrCode SvcDistributedConnection::ConnectDExtAbility(AAFwk::Want &want, int32_t userId, bool isCleanCalled,
    const std::string& delegatee, bool &isDelay)
{
    return ISvcDistributedConnection::connMock->ConnectDExtAbility(want, userId, isCleanCalled, delegatee, isDelay);
}

sptr<IDExtension> SvcDistributedConnection::GetDistributedExtProxy()
{
    return ISvcDistributedConnection::connMock->GetDistributedExtProxy();
}

bool SvcDistributedConnection::IsExtAbilityConnected()
{
    return isConnected_.load();
}

void SvcDistributedConnection::SetCallback(std::function<void(const std::string &&)> callConnected)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    callConnected_ = callConnected;
}

void SvcDistributedConnection::RegisterEventListener()
{
    // No-op in test
}

void SvcDistributedConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    // No-op in test
}

void SvcDistributedConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    // No-op in test
}

ErrCode SvcDistributedConnection::DisconnectDistributedExtAbility()
{
    return ERR_OK;
}

void SvcDistributedConnection::PublishDExtensionNotification(const std::string &deviceId,
    const std::string &bundleName, const int32_t userId,
    const std::string &deviceName, AppExecFwk::BundleResourceInfo &bundleResourceInfo)
{
    // No-op in test
}

void SvcDistributedConnection::EndTaskFunction()
{
    // No-op in test
}
}
}

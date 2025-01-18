/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_SVC_DISTRIBUTED_CONNECTION_H
#define OHOS_SVC_DISTRIBUTED_CONNECTION_H

#include "ability_connect_callback_stub.h"
#include "i_distributed_extension.h"

namespace OHOS {
namespace DistributedSchedule {
class SvcDistributedConnection : public AAFwk::AbilityConnectionStub {
public:
    /**
     * @brief This method is called back to receive the connection result after an ability calls the
     * ConnectAbility method to connect it to an extension ability.
     *
     * @param element: Indicates information about the connected extension ability.
     * @param remote: Indicates the remote proxy object of the extension ability.
     * @param resultCode: Indicates the connection result code. The value 0 indicates a successful connection, and any
     * other value indicates a connection failure.
     */
    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject,
        int resultCode) override;

    /**
     * @brief This method is called back to receive the disconnection result after the connected extension ability
     * crashes or is killed. If the extension ability exits unexpectedly, all its connections are disconnected, and
     * each ability previously connected to it will call onAbilityDisconnectDone.
     *
     * @param element: Indicates information about the disconnected extension ability.
     * @param resultCode: Indicates the disconnection result code. The value 0 indicates a successful disconnection,
     * and any other value indicates a disconnection failure.
     */
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;

    /**
     * @brief connect remote ability of ExtBackup.
     */
    ErrCode ConnectDExtAbility(AAFwk::Want &want, int32_t userId, bool isCleanCalled);

    /**
     * @brief disconnect remote ability of ExtBackup.
     */
    ErrCode DisconnectDistributedExtAbility();

    /**
     * @brief check whether connected to remote extension ability.
     *
     * @return bool true if connected, otherwise false.
     */
    bool IsExtAbilityConnected();

    /**
     * @brief get the proxy of backup extension ability.
     *
     * @return the proxy of backup extension ability.
     */
    sptr<IDExtension> GetDistributedExtProxy();

public:
    SvcDistributedConnection(std::string bundleNameIndexInfo)
        : bundleNameIndexInfo_(bundleNameIndexInfo)
    {
    }
    ~SvcDistributedConnection() override {};

private:
    std::mutex mutex_;
    std::condition_variable condition_;
    std::atomic<bool> isConnected_ = {false};
    std::atomic<bool> isCleanCalled_ = {false};
    std::atomic<bool> isConnectCalled_ = {false};
    sptr<IDExtension> distributedProxy_;

    std::string bundleNameIndexInfo_;
};
}
}

#endif // OHOS_SVC_DISTRIBUTED_CONNECTION_H

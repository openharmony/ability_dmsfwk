
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
 
#ifndef OHOS_DSCHED_COLLAB_ABILITY_CONNECTION_SESSION_ILISTENER_H
#define OHOS_DSCHED_COLLAB_ABILITY_CONNECTION_SESSION_ILISTENER_H
#include "av_trans_stream_data.h"
#include "channel_common_definition.h"
#include <memory>
 
namespace OHOS {
namespace DistributedCollab {
class IAbilityConnectionSessionListener {
public:
    IAbilityConnectionSessionListener() = default;
    virtual ~IAbilityConnectionSessionListener() = default;
    virtual void OnConnect(const int32_t sessionId) const;
    virtual void OnDisConnect(const int32_t sessionId) const;
    virtual void OnMessage(const int32_t sessionId, const std::string& message) const;
    virtual void OnData(const int32_t sessionId, const std::shared_ptr<AVTransDataBuffer>& buffer) const;
    virtual void OnError(const int32_t sessionId, const int32_t errorCode) const;
    virtual void OnSendFile(const int32_t sessionId, const FileInfo& info) const;
    virtual void OnRecvFile(const int32_t sessionId, const FileInfo& info) const;
    virtual const char* GetRecvPath(const int32_t sessionId) const;
};
}
}
#endif
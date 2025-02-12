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
#include "av_receiver_filter_listener.h"
#include "dtbcollabmgr_log.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
    static const std::string TAG = "AVReceiverFilterListener";
}

AVReceiverFilterListener::~AVReceiverFilterListener()
{
    HILOGI("AVReceiverFilterListener destroyed");
}

void AVReceiverFilterListener::OnConnect(const int32_t channelId) const { }

void AVReceiverFilterListener::OnDisConnect(const int32_t channelId) const { }

void AVReceiverFilterListener::OnMessage(const int32_t channelId,
    const std::shared_ptr<AVTransDataBuffer>& buffer) const { }

void AVReceiverFilterListener::OnError(const int32_t channelId, const int32_t errorCode) const
{
    if (auto ptr = filter_.lock()) {
        ptr->OnError(errorCode);
    }
}

void AVReceiverFilterListener::OnStream(const int32_t channelId,
    const std::shared_ptr<AVTransStreamData>& stream) const
{
    if (auto ptr = filter_.lock()) {
        ptr->OnStream(stream);
    }
}

void AVReceiverFilterListener::OnBytes(const int32_t channelId,
    const std::shared_ptr<AVTransDataBuffer>& buffer) const
{
    if (auto ptr = filter_.lock()) {
        ptr->OnBytes(buffer);
    }
}

void AVReceiverFilterListener::OnSendFile(const int32_t channelId, const FileInfo& info) const
{
}

void AVReceiverFilterListener::OnRecvFile(const int32_t channelId, const FileInfo& info) const
{
}

const char* AVReceiverFilterListener::GetRecvPath(const int32_t channelId) const
{
    return nullptr;
}
} // namespace DistributedCollab
} // namespace OHOS
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

#ifndef OHOS_DSCHED_SOFTBUS_SESSION_H
#define OHOS_DSCHED_SOFTBUS_SESSION_H

#include "dsched_data_buffer.h"

namespace OHOS {
namespace DistributedSchedule {
class DSchedSoftbusSession {
public:
    DSchedSoftbusSession();
    ~DSchedSoftbusSession();
    int32_t HandleBytesReceived(int32_t sessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer);
    int32_t SendData(std::shared_ptr<DSchedDataBuffer> dataBuffer);

private:
    enum {
        FRAG_NULL = 0,
        FRAG_START,
        FRAG_MID,
        FRAG_END,
        FRAG_START_END,
    };

    struct SessionDataHeader {
        uint16_t version;
        uint8_t fragFlag;
        uint32_t dataType;
        uint32_t seqNum;
        uint32_t totalLen;
        uint16_t subSeq;
        uint32_t dataLen;
    };

    void PackRecvData(std::shared_ptr<DSchedDataBuffer> dataBuffer);
    void AssembleNoFrag(std::shared_ptr<DSchedDataBuffer> buffer, SessionDataHeader &headerPara);
    void AssembleFrag(std::shared_ptr<DSchedDataBuffer> buffer, SessionDataHeader &headerPara);
    int32_t UnPackSendData(std::shared_ptr<DSchedDataBuffer> buffer);

private:
    int32_t sessionId_ = 0;
    std::string myDeviceId_;
    std::string peerDeviceId_;
    std::string sessionName_;
    int32_t refCount_;
    bool isServer_ = false;
    int32_t maxSendBytesSize_ = 0;
    int32_t maxQos_ = 0;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_SOFTBUS_SESSION_H
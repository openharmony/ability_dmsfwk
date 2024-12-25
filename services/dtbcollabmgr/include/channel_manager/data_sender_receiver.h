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

#ifndef OHOS_DSCHED_COLLAB_DATA_SENDER_RECEIVER_H
#define OHOS_DSCHED_COLLAB_DATA_SENDER_RECEIVER_H

#include "av_trans_data_buffer.h"
#include "av_trans_stream_data.h"
#include "session_data_header.h"
#include <atomic>
#include <memory>

namespace OHOS {
namespace DistributedCollab {

    class DataSenderReceiver {
    public:
        explicit DataSenderReceiver(const int32_t socketId)
            : socketId_(socketId) {};
        ~DataSenderReceiver() = default;

        int32_t SendBytesData(const std::shared_ptr<AVTransDataBuffer>& sendData);
        int32_t PackRecvPacketData(const uint8_t* header, const uint32_t dataLen);
        std::shared_ptr<AVTransDataBuffer> GetPacketedData();

        int32_t SendStreamData(const std::shared_ptr<AVTransStreamData>& sendData);
        int32_t SendMessageData(const std::shared_ptr<AVTransDataBuffer>& sendData);

    private:
        int32_t SendUnpackData(const std::shared_ptr<AVTransDataBuffer>& sendData, const int32_t dataType);
        int32_t SendAllPackets(const std::shared_ptr<AVTransDataBuffer> sendData, const int32_t dataType);
        int32_t DoSendPacket(SessionDataHeader& headerPara, const uint8_t* dataHeader, const uint32_t dataLen);

        int32_t CheckRecvSessionHeader(const SessionDataHeader& headerPara);
        int32_t ProcessAllPacketRecv(const uint8_t* data, const uint32_t dataLen,
            const SessionDataHeader& headerPara);
        int32_t ProcessStartPacketRecv(const uint8_t* data, const uint32_t dataLen,
            const SessionDataHeader& headerPara);
        int32_t ProcessMidPacketRecv(const uint8_t* data, const uint32_t dataLen,
            const SessionDataHeader& headerPara);
        int32_t ProcessEndPacketRecv(const uint8_t* data, const uint32_t dataLen,
            const SessionDataHeader& headerPara);
        int32_t WriteRecvBytesDataToBuffer(const uint8_t* data, const uint32_t dataLen,
            const SessionDataHeader& headerPara);

        bool isDataReady();
        int64_t GetNowTimeStampUs();
        void ResetFlag();

    private:
        static constexpr uint32_t MAX_SEND_MESSAGE_SIZE = 4 * 1024;

    private:
        int32_t socketId_ = 0;
        // waiting for packet with end flag
        bool isWaiting_ = false;
        uint32_t nowSeqNum_ = 0;
        uint32_t nowSubSeq_ = 0;
        uint32_t nowTotalLen_ = 0;
        std::unique_ptr<AVTransDataBuffer> packBuffer_ = nullptr;
        uint8_t* currentPos;
    };
} // namespace DistributedCollab
} // namespace OHOS
#endif
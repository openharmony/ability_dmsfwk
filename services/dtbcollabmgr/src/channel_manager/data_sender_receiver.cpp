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

#include "data_sender_receiver.h"
#include "channel_common_definition.h"
#include "dtbcollabmgr_log.h"
#include "session.h"
#include "session_data_header.h"
#include "socket.h"
#include <chrono>
#include <map>
#include <memory>
#include "securec.h"
#include "softbus_error_code.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
    static constexpr uint16_t PROTOCOL_VERSION = 1;
    static const std::string TAG = "DSchedCollabDataSenderReceiver";
#define GET_SOFTBUS_SESSION_OPTION(socketId, value, valueSize)                                            \
do {                                                                                                  \
    int32_t ret = GetSessionOption(socketId, SESSION_OPTION_MAX_SENDBYTES_SIZE, &(value), valueSize); \
    if (ret != ERR_OK) {                                                                              \
        HILOGE("GetSessionOption failed, ret: %{public}d, session: %{public}d",                       \
            ret, socketId);                                                                           \
        return GET_SESSION_OPTION_FAILED;                                                             \
    }                                                                                                 \
    HILOGD("GetSessionOption succeeded, session: %{public}d, value: %{public}d",                      \
        socketId, value);                                                                             \
} while (0)

}

int32_t DataSenderReceiver::SendStreamData(const std::shared_ptr<AVTransStreamData>& sendData)
{
    const StreamData data = {
        .buf = reinterpret_cast<char*>(sendData->StreamData()->Data()),
        .bufLen = sendData->StreamData()->Size()
    };
    cJSON* extInfo = sendData->SerializeStreamDataExt();
    char* jsonString = cJSON_PrintUnformatted(extInfo);
    const StreamData ext = {
        .buf = jsonString,
        .bufLen = strlen(jsonString)
    };
    const StreamFrameInfo info = {
        .frameType = 0,
        .timeStamp = GetNowTimeStampUs(),
        .seqNum = 0,
        .seqSubNum = 0,
        .level = 0,
        .bitMap = 0,
        .tvCount = 0
    };
    int32_t ret = SendStream(socketId_, &data, &ext, &info);
    if (ret != SOFTBUS_OK) {
        HILOGE("send stream data failed, %{public}d", socketId_);
        cJSON_Delete(extInfo);
        cJSON_free(jsonString);
        return ret;
    }
    cJSON_Delete(extInfo);
    cJSON_free(jsonString);
    return ERR_OK;
}

int32_t DataSenderReceiver::SendMessageData(const std::shared_ptr<AVTransDataBuffer>& sendData)
{
    if (sendData->Size() > MAX_SEND_MESSAGE_SIZE) {
        HILOGE("too large send message");
        return DATA_SIZE_EXCEED_LIMIT;
    }
    return SendMessage(socketId_, sendData->Data(), sendData->Size());
}

int32_t DataSenderReceiver::SendBytesData(const std::shared_ptr<AVTransDataBuffer>& sendData)
{
    int32_t dataType = static_cast<int32_t>(ChannelDataType::BYTES);
    return SendUnpackData(sendData, dataType);
}

int32_t DataSenderReceiver::SendUnpackData(const std::shared_ptr<AVTransDataBuffer>& sendData,
    const int32_t dataType)
{
    HILOGI("start to send bytes");
    uint32_t maxSendSize = 0;
    GET_SOFTBUS_SESSION_OPTION(socketId_, maxSendSize, static_cast<uint32_t>(sizeof(maxSendSize)));

    if (sendData->Size() + SessionDataHeader::HEADER_LEN <= maxSendSize) {
        return SendAllPackets(sendData, dataType);
    }
    const uint8_t* dataHeader = sendData->Data();
    const uint8_t* const dataEnd = sendData->Data() + sendData->Size();
    uint8_t* current = const_cast<uint8_t*>(dataHeader);
    uint32_t totalLen = sendData->Size();
    uint32_t packetLen = maxSendSize;
    uint32_t payloadLen = packetLen - SessionDataHeader::HEADER_LEN;
    uint16_t seqNum = 0;
    uint16_t subSeq = 0;
    SessionDataHeader headerPara(
        PROTOCOL_VERSION,
        FRAG_TYPE::FRAG_START,
        dataType,
        seqNum,
        totalLen,
        packetLen,
        payloadLen,
        subSeq);

    int32_t ret = DoSendPacket(headerPara, current, payloadLen);
    if (ret != ERR_OK) {
        return ret;
    }
    current += payloadLen;
    while (current < dataEnd) {
        GET_SOFTBUS_SESSION_OPTION(socketId_, maxSendSize, static_cast<uint32_t>(sizeof(maxSendSize)));
        headerPara.packetLen_ = maxSendSize;
        headerPara.payloadLen_ = maxSendSize - SessionDataHeader::HEADER_LEN;
        headerPara.fragFlag_ = dataEnd - current > payloadLen ? FRAG_TYPE::FRAG_MID : FRAG_TYPE::FRAG_END;
        headerPara.subSeq_++;
        ret = DoSendPacket(headerPara, current, payloadLen);
        if (ret != ERR_OK) {
            return ret;
        }
        current += payloadLen;
    }
    HILOGI("finish send all bytes by packet");
    return ERR_OK;
}

int32_t DataSenderReceiver::SendAllPackets(const std::shared_ptr<AVTransDataBuffer> sendData,
    const int32_t dataType)
{
    HILOGI("send all data");
    uint8_t* current = sendData->Data();
    uint32_t totalLen = sendData->Size() + SessionDataHeader::HEADER_LEN;
    uint32_t packetLen = sendData->Size() + SessionDataHeader::HEADER_LEN;
    uint32_t payloadLen = packetLen - SessionDataHeader::HEADER_LEN;
    uint16_t subSeq = 0;
    uint16_t seqNum = 0;

    int32_t ret = ERR_OK;
    SessionDataHeader headerPara(
        PROTOCOL_VERSION,
        FRAG_TYPE::FRAG_START_END,
        dataType,
        seqNum,
        totalLen,
        packetLen,
        payloadLen,
        subSeq
    );
    ret = DoSendPacket(headerPara, current, payloadLen);
    if (ret != ERR_OK) {
        return ret;
    }
    HILOGI("finish send all bytes");
    return ERR_OK;
}

int32_t DataSenderReceiver::DoSendPacket(SessionDataHeader& headerPara,
    const uint8_t* dataHeader, const uint32_t dataLen)
{
    HILOGI("start to send packet by softbus");
    auto headerBuffer = headerPara.Serialize();
    auto sendBuffer = std::make_unique<AVTransDataBuffer>(SessionDataHeader::HEADER_LEN + dataLen);
    uint8_t* header = sendBuffer->Data();

    int32_t ret = ERR_OK;
    // copy header
    ret = memcpy_s(header, sendBuffer->Size(),
        headerBuffer->Data(), SessionDataHeader::HEADER_LEN);
    if (ret != EOK) {
        HILOGE("Write header failed");
        return WRITE_SESSION_HEADER_FAILED;
    }
    // copy data
    ret = memcpy_s(header + SessionDataHeader::HEADER_LEN,
        sendBuffer->Size() - SessionDataHeader::HEADER_LEN,
            dataHeader, dataLen);
    if (ret != EOK) {
        HILOGE("Write data failed");
        return WRITE_SEND_DATA_BUFFER_FAILED;
    }
    ret = SendBytes(socketId_, sendBuffer->Data(), sendBuffer->Size());
    if (ret != SOFTBUS_OK) {
        HILOGE("Send data buffer failed");
        return SEND_DATA_BY_SOFTBUS_FAILED;
    }
    return ret;
}

inline int64_t DataSenderReceiver::GetNowTimeStampUs()
{
    std::chrono::microseconds nowUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch());
    return nowUs.count();
}

int32_t DataSenderReceiver::PackRecvPacketData(const uint8_t* header, const uint32_t dataLen)
{
    auto headerPara = SessionDataHeader::Deserialize(header, dataLen);
    if (!headerPara) {
        HILOGE("read session header from buffer failed");
        return WRITE_SESSION_HEADER_FAILED;
    }
    SessionDataHeader& sessionHeader = *headerPara;
    int32_t ret = CheckRecvSessionHeader(sessionHeader);
    if (ret != ERR_OK) {
        HILOGE("check session header failed");
        return ret;
    }
    // pack recv data
    uint8_t* dataHeader = const_cast<uint8_t*>(header);
    switch (sessionHeader.fragFlag_) {
        case FRAG_TYPE::FRAG_START_END:
            ret = ProcessAllPacketRecv(dataHeader, dataLen, sessionHeader);
            break;
        case FRAG_TYPE::FRAG_START:
            ret = ProcessStartPacketRecv(dataHeader, dataLen, sessionHeader);
            break;
        case FRAG_TYPE::FRAG_MID:
            ret = ProcessMidPacketRecv(dataHeader, dataLen, sessionHeader);
            break;
        case FRAG_TYPE::FRAG_END:
            ret = ProcessEndPacketRecv(dataHeader, dataLen, sessionHeader);
            break;
        default:
            HILOGE("invalid flag type, %{public}d", static_cast<uint32_t>(sessionHeader.fragFlag_));
            return INVALID_SESSION_HEADER_FLAG_TYPE;
    }
    return ret;
}

int32_t DataSenderReceiver::CheckRecvSessionHeader(const SessionDataHeader& headerPara)
{
    if (nowSeqNum_ != headerPara.seqNum_) {
        HILOGE("seq error, nowSeq: %{public}d, actualSeq: %{public}d, sessionId: %{public}d",
            nowSeqNum_, headerPara.seqNum_, socketId_);
        return INVALID_SESSION_HEADER_SEQ_NUM;
    }
    if (nowSubSeq_ == 0 && headerPara.subSeq_ == 0) {
        return ERR_OK;
    }
    if (nowSubSeq_ + 1 != headerPara.subSeq_) {
        HILOGE("subSeq error, nowSeq: %{public}d, actualSeq: %{public}d, sessionId: %{public}d",
            nowSubSeq_, headerPara.subSeq_, socketId_);
        return INVALID_SESSION_HEADER_SUB_SEQ;
    }
    return ERR_OK;
}

int32_t DataSenderReceiver::ProcessAllPacketRecv(const uint8_t* data, const uint32_t dataLen,
    const SessionDataHeader& headerPara)
{
    if (packBuffer_ != nullptr || isWaiting_) {
        HILOGE("recv start data packet but buffer not empty or still waiting");
        ResetFlag();
        return FLAG_TYPE_NOT_MATCH_BUFFER_STATE;
    }
    int32_t ret = WriteRecvBytesDataToBuffer(data, dataLen, headerPara);
    if (ret != ERR_OK) {
        HILOGE("write payload to buffer failed");
        ResetFlag();
        return WRITE_PAYLOAD_TO_BUFFER_FAILED;
    }
    return ERR_OK;
}

int32_t DataSenderReceiver::ProcessStartPacketRecv(const uint8_t* data, const uint32_t dataLen,
    const SessionDataHeader& headerPara)
{
    if (packBuffer_ != nullptr || isWaiting_) {
        HILOGE("recv start data packet but buffer not empty or still waiting");
        ResetFlag();
        return FLAG_TYPE_NOT_MATCH_BUFFER_STATE;
    }
    int32_t ret = WriteRecvBytesDataToBuffer(data, dataLen, headerPara);
    if (ret != ERR_OK) {
        ResetFlag();
        return ret;
    }
    isWaiting_ = true;
    nowSeqNum_ = headerPara.seqNum_;
    nowSubSeq_ = headerPara.subSeq_;
    return ERR_OK;
}

int32_t DataSenderReceiver::ProcessMidPacketRecv(const uint8_t* data,
    const uint32_t dataLen, const SessionDataHeader& headerPara)
{
    if (packBuffer_ == nullptr || !isWaiting_) {
        HILOGE("recv mid data packet but buffer empty or end waiting");
        ResetFlag();
        return FLAG_TYPE_NOT_MATCH_BUFFER_STATE;
    }
    int32_t ret = WriteRecvBytesDataToBuffer(data, dataLen, headerPara);
    if (ret != ERR_OK) {
        ResetFlag();
        return ret;
    }
    nowSeqNum_ = headerPara.seqNum_;
    nowSubSeq_ = headerPara.subSeq_;
    return ERR_OK;
}

int32_t DataSenderReceiver::ProcessEndPacketRecv(const uint8_t* data,
    const uint32_t dataLen, const SessionDataHeader& headerPara)
{
    if (packBuffer_ == nullptr || !isWaiting_) {
        HILOGE("recv end data packet but buffer empty or end waiting");
        ResetFlag();
        return FLAG_TYPE_NOT_MATCH_BUFFER_STATE;
    }
    int32_t ret = WriteRecvBytesDataToBuffer(data, dataLen, headerPara);
    if (ret != ERR_OK) {
        ResetFlag();
        return ret;
    }
    isWaiting_ = false;
    return ret;
}

int32_t DataSenderReceiver::WriteRecvBytesDataToBuffer(const uint8_t* data,
    const uint32_t dataLen, const SessionDataHeader& headerPara)
{
    uint8_t* header = const_cast<uint8_t*>(data);
    uint8_t* dataHeader = header + (headerPara.packetLen_ - headerPara.payloadLen_);
    if (packBuffer_ == nullptr) {
        packBuffer_ = std::make_unique<AVTransDataBuffer>(headerPara.totalLen_);
        currentPos = packBuffer_->Data();
    } else if (packBuffer_->Size() != headerPara.totalLen_) {
        HILOGE("recv session header totalLen inconsistent");
        return INVALID_SESSION_HEADER_TOTAL_LEN;
    }

    int32_t ret = memcpy_s(currentPos,
        packBuffer_->Size() - (currentPos - packBuffer_->Data()),
        dataHeader, headerPara.payloadLen_);
    if (ret != EOK) {
        HILOGE("write payload to buffer failed");
        return WRITE_PAYLOAD_TO_BUFFER_FAILED;
    }
    currentPos += headerPara.payloadLen_;
    return ret;
}

std::shared_ptr<AVTransDataBuffer> DataSenderReceiver::GetPacketedData()
{
    if (isDataReady()) {
        packBuffer_->SetRange(0, currentPos - packBuffer_->Data());
        auto bytesData = std::shared_ptr<AVTransDataBuffer>(std::move(packBuffer_));
        ResetFlag();
        return bytesData;
    }
    return nullptr;
}

inline bool DataSenderReceiver::isDataReady()
{
    return !isWaiting_ && packBuffer_ != nullptr;
}

inline void DataSenderReceiver::ResetFlag()
{
    isWaiting_ = false;
    nowSeqNum_ = 0;
    nowSubSeq_ = 0;
    nowTotalLen_ = 0;
    packBuffer_ = nullptr;
    currentPos = nullptr;
}
} // namespace DistributedCollab
} // namespace OHOS
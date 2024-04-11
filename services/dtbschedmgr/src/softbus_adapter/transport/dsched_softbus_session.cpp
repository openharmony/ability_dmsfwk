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

#include "dsched_softbus_session.h"

#include <chrono>

#include "adapter/dnetwork_adapter.h"
#include "distributed_sched_adapter.h"
#include "dsched_transport_softbus_adapter.h"
#include "dtbschedmgr_log.h"
#include "session.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DSchedSoftbusSession";
}

DSchedSoftbusSession::DSchedSoftbusSession()
{
    sessionId_ = 0;
    refCount_ = COUNT_INIT_NUM;
    isServer_ = false;
    maxSendBytesSize_ = 0;
    maxQos_ = 0;
}

DSchedSoftbusSession::DSchedSoftbusSession(SessionInfo &info)
{
    sessionId_ = info.sessionId;
    myDeviceId_ = info.myDeviceId;
    peerDeviceId_ = info.peerDeviceId;
    sessionName_ = info.sessionName;
    isServer_ = info.isServer;
    refCount_ = COUNT_INIT_NUM;
    maxSendBytesSize_ = 0;
    maxQos_ = 0;
}

DSchedSoftbusSession::~DSchedSoftbusSession()
{
}

void DSchedSoftbusSession::OnConnect()
{
    refCount_++;
    HILOGI("session %d current ref cnt: %d", sessionId_, refCount_.load());
}

bool DSchedSoftbusSession::OnDisconnect()
{
    refCount_--;
    HILOGI("session %d current ref cnt: %d", sessionId_, refCount_.load());
    if (refCount_ <= 0) {
        HILOGI("session: %d not in use, clear resource", sessionId_);
        return true;
    }
    return false;
}

int32_t DSchedSoftbusSession::OnBytesReceived(std::shared_ptr<DSchedDataBuffer> buffer)
{
    HILOGD("called");
    PackRecvData(buffer);
    return ERR_OK;
}

int32_t DSchedSoftbusSession::SendData(std::shared_ptr<DSchedDataBuffer> buffer, int32_t dataType)
{
    HILOGD("called");
    UnPackSendData(buffer, dataType);
    return ERR_OK;
}

std::string DSchedSoftbusSession::GetPeerDeviceId()
{
    return peerDeviceId_;
}

void DSchedSoftbusSession::PackRecvData(std::shared_ptr<DSchedDataBuffer> buffer)
{
    uint64_t bufferSize;
    if (buffer->Size() < BINARY_HEADER_FRAG_LEN) {
        bufferSize = static_cast<uint64_t>(buffer->Size());
        HILOGE("pack recv data error, size: %" PRIu64", session id: %d", bufferSize, sessionId_);
        return;
    }
    uint8_t *ptrPacket = buffer->Data();
    SessionDataHeader headerPara;
    GetFragDataHeader(ptrPacket, headerPara);
    if (buffer->Size() != (headerPara.dataLen + BINARY_HEADER_FRAG_LEN) || headerPara.dataLen > headerPara.totalLen ||
        headerPara.dataLen > BINARY_DATA_MAX_LEN || headerPara.totalLen > BINARY_DATA_MAX_TOTAL_LEN) {
        bufferSize = static_cast<uint64_t>(buffer->Size());
        HILOGE("pack recv data failed, size: %" PRIu64", dataLen: %d, totalLen: %d session id:"
            " %d", bufferSize, headerPara.dataLen, headerPara.totalLen, sessionId_);
        return;
    }
    bufferSize = static_cast<uint64_t>(buffer->Size());
    HILOGD("pack recv data Assemble, size: %" PRIu64", dataLen: %d, totalLen: %d, nowTime: "
        "%" PRId64" start", bufferSize, headerPara.dataLen, headerPara.totalLen, GetNowTimeStampUs());
    if (headerPara.fragFlag == FRAG_START_END) {
        AssembleNoFrag(buffer, headerPara);
    } else {
        AssembleFrag(buffer, headerPara);
    }
    bufferSize = static_cast<uint64_t>(buffer->Size());
    HILOGD("pack recv data Assemble, size: %" PRIu64", dataLen: %d, totalLen: %d, nowTime: "
        "%" PRId64" end", bufferSize, headerPara.dataLen, headerPara.totalLen, GetNowTimeStampUs());
}

void DSchedSoftbusSession::GetFragDataHeader(uint8_t *ptrPacket, SessionDataHeader& headerPara)
{
    uint32_t i = 0;
    uint16_t ret = 0;
    while (i < BINARY_HEADER_FRAG_LEN) {
        ret = ReadTlvToHeader(ptrPacket + i, headerPara);
        if (ret < 0) {
            HILOGE("ReadTlvToHeader failed, ret: %d", ret);
            break;
        }
        i += ret;
    }
    return;
}

uint16_t DSchedSoftbusSession::ReadTlvToHeader(uint8_t *ptrPacket, SessionDataHeader& headerPara)
{
    uint8_t *ptr = ptrPacket;
    uint16_t type = U16Get(ptr);
    ptr += sizeof(type);
    uint16_t len = U16Get(ptr);
    ptr += sizeof(len);

    bool ret = false;
    switch (type) {
        case TLV_TYPE_VERSION:
            ret = memcpy_s(&headerPara.version, sizeof(headerPara.version), ptr, len);
            break;
        case TLV_TYPE_FRAG_FLAG:
            ret = memcpy_s(&headerPara.fragFlag, sizeof(headerPara.fragFlag), ptr, len);
            break;
        case TLV_TYPE_DATA_TYPE:
            ret = memcpy_s(&headerPara.dataType, sizeof(headerPara.dataType), ptr, len);
            break;
        case TLV_TYPE_SEQ_NUM:
            ret = memcpy_s(&headerPara.seqNum, sizeof(headerPara.seqNum), ptr, len);
            break;
        case TLV_TYPE_TOTAL_LEN:
            ret = memcpy_s(&headerPara.totalLen, sizeof(headerPara.totalLen), ptr, len);
            break;
        case TLV_TYPE_SUB_SEQ:
            ret = memcpy_s(&headerPara.subSeq, sizeof(headerPara.subSeq), ptr, len);
            break;
        case TLV_TYPE_DATA_LEN:
            ret = memcpy_s(&headerPara.dataLen, sizeof(headerPara.dataLen), ptr, len);
            break;
        default:
            HILOGE("invalid type: %d!", type);
            ret = INVALID_PARAMETERS_ERR;
            break;
    }

    if (ret != ERR_OK) {
        HILOGE("memcpy_s value of type %d failed!", type);
        return -1;
    }
    /* returns value lenth */
    return sizeof(type) + sizeof(len) + len;
}

uint16_t DSchedSoftbusSession::U16Get(const uint8_t *ptr)
{
    return (ptr[0] << DSCHED_SHIFT_8) | ptr[1];
}

void DSchedSoftbusSession::AssembleNoFrag(std::shared_ptr<DSchedDataBuffer> buffer, SessionDataHeader& headerPara)
{
    if (headerPara.dataLen != headerPara.totalLen) {
        HILOGE("error, header lenth not match, dataLen: %d, totalLen: %d, session id: %d peerNetworkId: %s",
            headerPara.dataLen, headerPara.totalLen, sessionId_,
            DnetworkAdapter::AnonymizeNetworkId(peerDeviceId_).c_str());
        return;
    }
    std::shared_ptr<DSchedDataBuffer> postData = std::make_shared<DSchedDataBuffer>(headerPara.dataLen);
    int32_t ret = memcpy_s(postData->Data(), postData->Size(), buffer->Data() + BINARY_HEADER_FRAG_LEN,
        buffer->Size() - BINARY_HEADER_FRAG_LEN);
    if (ret != ERR_OK) {
        HILOGE("memcpy_s failed, ret: %d, session id: %d peerNetworkId: %s",
            ret, sessionId_, DnetworkAdapter::AnonymizeNetworkId(peerDeviceId_).c_str());
        return;
    }
    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(sessionId_, postData, headerPara.dataType);
}

void DSchedSoftbusSession::AssembleFrag(std::shared_ptr<DSchedDataBuffer> buffer, SessionDataHeader& headerPara)
{
    if (headerPara.fragFlag == FRAG_START) {
        isWaiting_ = true;
        nowSeq_ = headerPara.seqNum;
        nowSubSeq_ = headerPara.subSeq;
        offset_ = 0;
        totalLen_ = headerPara.totalLen;
        packBuffer_ = std::make_shared<DSchedDataBuffer>(headerPara.totalLen);
        int32_t ret = memcpy_s(packBuffer_->Data(), packBuffer_->Size(), buffer->Data() + BINARY_HEADER_FRAG_LEN,
            buffer->Size() - BINARY_HEADER_FRAG_LEN);
        if (ret != ERR_OK) {
            HILOGE("FRAG_START memcpy_s failed, ret: %d session id: %d peerNetworkId: %s",
                ret, sessionId_, DnetworkAdapter::AnonymizeNetworkId(peerDeviceId_).c_str());
            ResetAssembleFrag();
            return;
        }
        offset_ += headerPara.dataLen;
    }

    if (headerPara.fragFlag == FRAG_MID || headerPara.fragFlag == FRAG_END) {
        int32_t ret = CheckUnPackBuffer(headerPara);
        if (ret != ERR_OK) {
            ResetAssembleFrag();
            return;
        }

        nowSubSeq_ = headerPara.subSeq;
        ret = memcpy_s(packBuffer_->Data() + offset_, packBuffer_->Size() - offset_,
            buffer->Data() + BINARY_HEADER_FRAG_LEN, buffer->Size() - BINARY_HEADER_FRAG_LEN);
        if (ret != ERR_OK) {
            HILOGE("memcpy_s failed, ret: %d session id: %d peerNetworkId: %s",
                ret, sessionId_, DnetworkAdapter::AnonymizeNetworkId(peerDeviceId_).c_str());
            ResetAssembleFrag();
            return;
        }
        offset_ += headerPara.dataLen;
    }

    if (headerPara.fragFlag == FRAG_END) {
        DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(sessionId_, packBuffer_, headerPara.dataType);
        ResetAssembleFrag();
    }
}

int32_t DSchedSoftbusSession::CheckUnPackBuffer(SessionDataHeader& headerPara)
{
    if (!isWaiting_) {
        HILOGE("failed, not waiting, session id: %d peerNetworkId: %s", sessionId_,
            DnetworkAdapter::AnonymizeNetworkId(peerDeviceId_).c_str());
        return INVALID_PARAMETERS_ERR;
    }

    if (nowSeq_ != headerPara.seqNum) {
        HILOGE("seq error, nowSeq: %d actualSeq: %d, session id: %d peerNetworkId: %s",
            nowSeq_, headerPara.seqNum, sessionId_, DnetworkAdapter::AnonymizeNetworkId(peerDeviceId_).c_str());
        return INVALID_PARAMETERS_ERR;
    }

    if (nowSubSeq_ + 1 != headerPara.subSeq) {
        HILOGE("subSeq error, nowSeq: %d actualSeq: %d, session id: %d peerNetworkId: %s",
            nowSubSeq_, headerPara.subSeq, sessionId_, DnetworkAdapter::AnonymizeNetworkId(peerDeviceId_).c_str());
        return INVALID_PARAMETERS_ERR;
    }

    if (totalLen_ < headerPara.dataLen + offset_) {
        HILOGE("data len error cap: %d size: %d, dataLen: %d, session id: %d peerNetworkId: %s", totalLen_,
            offset_, headerPara.dataLen, sessionId_, DnetworkAdapter::AnonymizeNetworkId(peerDeviceId_).c_str());
        return INVALID_PARAMETERS_ERR;
    }
    return ERR_OK;
}

void DSchedSoftbusSession::ResetAssembleFrag()
{
    isWaiting_ = false;
    nowSeq_ = 0;
    nowSubSeq_ = 0;
    offset_ = 0;
    totalLen_ = 0;
    packBuffer_ = nullptr;
}

int32_t DSchedSoftbusSession::UnPackSendData(std::shared_ptr<DSchedDataBuffer> buffer, int32_t dataType)
{
    uint32_t maxSendSize = 0;
    int32_t ret = GetSessionOption(sessionId_, SESSION_OPTION_MAX_SENDBYTES_SIZE, &maxSendSize, sizeof(maxSendSize));
    if (ret != ERR_OK) {
        HILOGE("GetSessionOption get max SendBytes size failed, ret: %d, session: %d", ret, sessionId_);
        return ret;
    }
    HILOGD("GetSessionOption get max SendBytes size: %u, session: %d", maxSendSize, sessionId_);

    if (buffer->Size() <= maxSendSize) {
        return UnPackStartEndData(buffer, dataType);
    }

    uint16_t subSeq = 0;
    uint32_t totalLen = buffer->Size();
    uint32_t offset = 0;
    uint64_t bufferSize = 0;
    SessionDataHeader headPara = { PROTOCOL_VERSION, FRAG_START, dataType, 0, totalLen, subSeq };

    while (totalLen > offset) {
        SetHeadParaDataLen(headPara, totalLen, offset, maxSendSize);
        bufferSize = static_cast<uint64_t>(buffer->Size());
        HILOGD("size: %" PRIu64", dataLen: %d, totalLen: %d, nowTime: %" PRId64" start:", bufferSize, headPara.dataLen,
            headPara.totalLen, GetNowTimeStampUs());

        auto unpackData = std::make_shared<DSchedDataBuffer>(headPara.dataLen + BINARY_HEADER_FRAG_LEN);
        MakeFragDataHeader(headPara, unpackData->Data(), BINARY_HEADER_FRAG_LEN);
        int32_t ret = memcpy_s(unpackData->Data() + BINARY_HEADER_FRAG_LEN,
            unpackData->Size() - BINARY_HEADER_FRAG_LEN, buffer->Data() + offset, headPara.dataLen);
        if (ret != ERR_OK) {
            HILOGE("memcpy_s failed, ret: %d, session: %d", ret, sessionId_);
            return ret;
        }

        ret = DSchedTransportSoftbusAdapter::GetInstance().SendBytesBySoftbus(sessionId_, unpackData);
        if (ret != ERR_OK) {
            HILOGE("sendData failed, ret: %d, session: %d", ret, sessionId_);
            return ret;
        }
        HILOGD("size: %" PRIu64", dataLen: %d, totalLen: %d, nowTime: %" PRId64" end:", bufferSize, headPara.dataLen,
            headPara.totalLen, GetNowTimeStampUs());

        headPara.subSeq++;
        headPara.fragFlag = FRAG_MID;
        offset += headPara.dataLen;

        ret = GetSessionOption(sessionId_, SESSION_OPTION_MAX_SENDBYTES_SIZE, &maxSendSize, sizeof(maxSendSize));
        if (ret != ERR_OK) {
            HILOGE("GetSessionOption get max SendBytes size failed, ret: %d, session: %d", ret, sessionId_);
            return ret;
        }
        HILOGD("GetSessionOption get next SendBytes size: %u, session: %d", maxSendSize, sessionId_);
    }
    return ERR_OK;
}

int32_t DSchedSoftbusSession::UnPackStartEndData(std::shared_ptr<DSchedDataBuffer> buffer, int32_t dataType)
{
    SessionDataHeader headPara = { PROTOCOL_VERSION, FRAG_START_END, dataType, 0, buffer->Size(), 0 };

    uint32_t maxSendSize = 0;
    int32_t ret = GetSessionOption(sessionId_, SESSION_OPTION_MAX_SENDBYTES_SIZE, &maxSendSize, sizeof(maxSendSize));
    if (ret != ERR_OK) {
        HILOGE("GetSessionOption get max SendBytes size failed, ret: %d, session: %d", ret, sessionId_);
        return ret;
    }
    HILOGD("GetSessionOption get max SendBytes size: %u, session: %d", maxSendSize, sessionId_);

    headPara.dataLen = buffer->Size();
    auto unpackData = std::make_shared<DSchedDataBuffer>(buffer->Size() + BINARY_HEADER_FRAG_LEN);
    MakeFragDataHeader(headPara, unpackData->Data(), BINARY_HEADER_FRAG_LEN);
    ret = memcpy_s(unpackData->Data() + BINARY_HEADER_FRAG_LEN, unpackData->Size() - BINARY_HEADER_FRAG_LEN,
        buffer->Data(), buffer->Size());
    if (ret != ERR_OK) {
        HILOGE("START_END memcpy_s failed, ret: %d, session: %d", ret, sessionId_);
        return ret;
    }
    return DSchedTransportSoftbusAdapter::GetInstance().SendBytesBySoftbus(sessionId_, unpackData);
}

void DSchedSoftbusSession::SetHeadParaDataLen(SessionDataHeader& headPara, const uint32_t totalLen,
    const uint32_t offset, const uint32_t maxSendSize)
{
    if (totalLen - offset > maxSendSize) {
        headPara.dataLen = maxSendSize - BINARY_DATA_PACKET_RESERVED_BUFFER;
    } else {
        headPara.fragFlag = FRAG_END;
        headPara.dataLen = totalLen - offset;
    }
}

int64_t DSchedSoftbusSession::GetNowTimeStampUs()
{
    std::chrono::microseconds nowUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch());
    return nowUs.count();
}

void DSchedSoftbusSession::MakeFragDataHeader(const SessionDataHeader& headPara, uint8_t *header, uint32_t len)
{
    uint32_t headerLen = (sizeof(uint16_t) + sizeof(uint16_t)) * HEADER_TLV_NUM  +
        sizeof(uint8_t) * HEADER_UINT8_NUM + sizeof(uint16_t) * HEADER_UINT16_NUM +
        sizeof(uint32_t) * HEADER_UINT32_NUM;
    if (headerLen > len) {
        HILOGE("MakeFragDataHeader %d over len %d", headerLen, len);
        return;
    }

    uint32_t i = 0;
    uint32_t capacity = len;
    uint32_t offset = TlvItem::HEADER_TYPE_BYTES + TlvItem::HEADER_LEN_BYTES;
    TlvItem version = { TLV_TYPE_VERSION, sizeof(uint16_t), headPara.version };
    WriteTlvToBuffer(version, &header[i], capacity);
    capacity -= offset + sizeof(uint16_t);
    i += offset + sizeof(uint16_t);

    TlvItem fragFlag = { TLV_TYPE_FRAG_FLAG, sizeof(uint8_t), headPara.fragFlag };
    WriteTlvToBuffer(fragFlag, &header[i], capacity);
    capacity -= offset + sizeof(uint8_t);
    i += offset + sizeof(uint8_t);

    TlvItem dataType = { TLV_TYPE_DATA_TYPE, sizeof(uint32_t), headPara.dataType };
    WriteTlvToBuffer(dataType, &header[i], capacity);
    capacity -= offset + sizeof(uint32_t);
    i += offset + sizeof(uint32_t);

    TlvItem seqNum = { TLV_TYPE_SEQ_NUM, sizeof(uint32_t), headPara.seqNum };
    WriteTlvToBuffer(seqNum, &header[i], capacity);
    capacity -= offset + sizeof(uint32_t);
    i += offset + sizeof(uint32_t);

    TlvItem totalLen = { TLV_TYPE_TOTAL_LEN, sizeof(uint32_t), headPara.totalLen };
    WriteTlvToBuffer(totalLen, &header[i], capacity);
    capacity -= offset + sizeof(uint32_t);
    i += offset + sizeof(uint32_t);

    TlvItem subSeq = { TLV_TYPE_SUB_SEQ, sizeof(uint16_t), headPara.subSeq };
    WriteTlvToBuffer(subSeq, &header[i], capacity);
    capacity -= offset + sizeof(uint16_t);
    i += offset + sizeof(uint16_t);

    TlvItem dataLen = { TLV_TYPE_DATA_LEN, sizeof(uint32_t), headPara.dataLen };
    WriteTlvToBuffer(dataLen, &header[i], capacity);
}

void DSchedSoftbusSession::WriteTlvToBuffer(const TlvItem& tlvItem, uint8_t *buffer,  uint32_t bufLen)
{
    uint32_t tlvLen = TlvItem::HEADER_TYPE_BYTES + TlvItem::HEADER_LEN_BYTES + tlvItem.len;
    if (bufLen < tlvLen) {
        HILOGE("tlv len %d over buffer len %d", tlvLen, bufLen);
        return;
    }
    uint32_t i = 0;
    buffer[i++] = tlvItem.type >> DSCHED_SHIFT_8;
    buffer[i++] = tlvItem.type & UINT16_SHIFT_MASK_0;
    buffer[i++] = tlvItem.len >> DSCHED_SHIFT_8;
    buffer[i++] = tlvItem.len & UINT16_SHIFT_MASK_0;
    int32_t ret = memcpy_s(&buffer[i], bufLen - TlvItem::HEADER_TYPE_BYTES + TlvItem::HEADER_LEN_BYTES,
        &tlvItem.value, tlvItem.len);
    if (ret != ERR_OK) {
        HILOGE("copy tlv value failed!, ret %d", ret);
    }
    return;
}
}  // namespace DistributedSchedule
}  // namespace OHOS

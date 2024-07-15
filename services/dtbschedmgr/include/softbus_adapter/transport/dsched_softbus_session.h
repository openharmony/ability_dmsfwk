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

#include <memory>
#include <mutex>

#include "dsched_data_buffer.h"

namespace OHOS {
namespace DistributedSchedule {
struct SessionInfo {
    int32_t sessionId = 0;
    std::string myDeviceId;
    std::string peerDeviceId;
    std::string sessionName;
    bool isServer = false;
};

class DSchedSoftbusSession {
public:
    DSchedSoftbusSession();
    DSchedSoftbusSession(SessionInfo &info);
    ~DSchedSoftbusSession();

    void OnConnect();
    bool OnDisconnect();
    int32_t OnBytesReceived(std::shared_ptr<DSchedDataBuffer> buffer);
    int32_t SendData(std::shared_ptr<DSchedDataBuffer> dataBuffer, int32_t dataType);
    std::string GetPeerDeviceId();

private:
    enum {
        FRAG_NULL = 0,
        FRAG_START,
        FRAG_MID,
        FRAG_END,
        FRAG_START_END,
    };

    enum {
        TLV_TYPE_NULL = 0,
        TLV_TYPE_VERSION = 1001,
        TLV_TYPE_FRAG_FLAG = 1002,
        TLV_TYPE_DATA_TYPE = 1003,
        TLV_TYPE_SEQ_NUM = 1004,
        TLV_TYPE_TOTAL_LEN = 1005,
        TLV_TYPE_SUB_SEQ = 1006,
        TLV_TYPE_DATA_LEN = 1007,
    };

    enum {
        DATA_TYPE_NULL = 0,
        DATA_TYPE_CONTINUE,
    };

    static const uint32_t BINARY_DATA_MAX_TOTAL_LEN = 100 * 1024 * 1024;
    static const uint32_t BINARY_DATA_MAX_LEN = 4 * 1024 * 1024;
    static const uint32_t BINARY_DATA_PACKET_RESERVED_BUFFER = 512;
    static const uint16_t PROTOCOL_VERSION = 1;
    static const uint16_t HEADER_UINT8_NUM = 1;
    static const uint16_t HEADER_UINT16_NUM = 2;
    static const uint16_t HEADER_UINT32_NUM = 4;
    static const uint16_t HEADER_TLV_NUM = 7;
    static const uint16_t BINARY_HEADER_FRAG_LEN = 49;

    const uint32_t DSCHED_SHIFT_8 = 8;
    const uint32_t COUNT_INIT_NUM = 1;
    const uint16_t UINT16_SHIFT_MASK_0 = 0x00ff;

    struct SessionDataHeader {
        uint16_t version;
        uint8_t fragFlag;
        uint32_t dataType;
        uint32_t seqNum;
        uint32_t totalLen;
        uint16_t subSeq;
        uint32_t dataLen;
    };

    struct TlvItem {
        uint16_t type = 0;
        uint16_t len = 0;
        uint32_t value = 0;

        static const uint16_t HEADER_TYPE_BYTES = sizeof(type);
        static const uint16_t HEADER_LEN_BYTES = sizeof(len);
    };

    void PackRecvData(std::shared_ptr<DSchedDataBuffer> buffer);
    void AssembleNoFrag(std::shared_ptr<DSchedDataBuffer> buffer, SessionDataHeader &headerPara);
    void AssembleFrag(std::shared_ptr<DSchedDataBuffer> buffer, SessionDataHeader &headerPara);
    int32_t UnPackSendData(std::shared_ptr<DSchedDataBuffer> buffer, int32_t dataType);
    void GetFragDataHeader(uint8_t *ptrPacket, SessionDataHeader& headerPara);
    int32_t UnPackStartEndData(std::shared_ptr<DSchedDataBuffer> buffer, int32_t dataType);
    int32_t CheckUnPackBuffer(SessionDataHeader& headerPara);
    void ResetAssembleFrag();
    void MakeFragDataHeader(const SessionDataHeader& headPara, uint8_t *header, uint32_t len);
    int32_t ReadTlvToHeader(uint8_t *ptrPacket, SessionDataHeader& headerPara, uint16_t& index);
    void WriteTlvToBuffer(const TlvItem& tlvItem, uint8_t *buffer,  uint32_t bufLen);
    void SetHeadParaDataLen(SessionDataHeader& headPara, const uint32_t totalLen, const uint32_t offset,
        const uint32_t maxSendSize);
    int64_t GetNowTimeStampUs();
    uint16_t U16Get(const uint8_t *ptr);
    std::shared_ptr<DSchedDataBuffer> packBuffer_;
    bool isWaiting_;
    uint32_t nowSeq_;
    uint32_t nowSubSeq_;
    uint32_t offset_;
    uint32_t totalLen_;

private:
    int32_t sessionId_ = 0;
    std::string myDeviceId_;
    std::string peerDeviceId_;
    std::string sessionName_;
    std::atomic<int32_t> refCount_ = 0;
    bool isServer_ = false;
    int32_t maxSendBytesSize_ = 0;
    int32_t maxQos_ = 0;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_SOFTBUS_SESSION_H

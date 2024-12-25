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

#ifndef OHOS_DSCHED_COLLAB_SESSSION_HEADER_H
#define OHOS_DSCHED_COLLAB_SESSSION_HEADER_H

#include "av_trans_data_buffer.h"
#include <map>
#include <memory>

namespace OHOS {
namespace DistributedCollab {
    enum class FRAG_TYPE : uint8_t {
        FRAG_NULL = 0,
        FRAG_START,
        FRAG_MID,
        FRAG_END,
        FRAG_START_END,
    };

    enum class TLV_TYPE : uint16_t {
        TLV_TYPE_NULL = 0,
        TLV_TYPE_VERSION = 1001,
        TLV_TYPE_FRAG_FLAG = 1002,
        TLV_TYPE_DATA_TYPE = 1003,
        TLV_TYPE_SEQ_NUM = 1004,
        TLV_TYPE_TOTAL_LEN = 1005,
        TLV_TYPE_SUB_SEQ = 1006,
        TLV_TYPE_PAYLOAD_LEN = 1007,
        TLV_TYPE_PACKET_LEN = 1008
    };

    struct TlvItem {
        TLV_TYPE type = TLV_TYPE::TLV_TYPE_NULL;
        uint16_t len = 0;
        uint32_t value = 0;

        static constexpr uint16_t HEADER_TYPE_BYTES = sizeof(type);
        static constexpr uint16_t HEADER_LEN_BYTES = sizeof(len);
    };

    class SessionDataHeader {
    public:
        static std::optional<SessionDataHeader> Deserialize(const uint8_t* buffer, const size_t bufLen);

    public:
        explicit SessionDataHeader() = default;
        explicit SessionDataHeader(
            uint16_t version,
            FRAG_TYPE fragFlag,
            uint32_t dataType,
            uint32_t seqNum,
            uint32_t totalLen,
            uint32_t packetLen,
            uint32_t payloadLen,
            uint16_t subSeq)
            : version_(version),
            fragFlag_(fragFlag),
            dataType_(dataType),
            seqNum_(seqNum),
            totalLen_(totalLen),
            packetLen_(packetLen),
            payloadLen_(payloadLen),
            subSeq_(subSeq) {};
        ~SessionDataHeader() = default;
        std::unique_ptr<AVTransDataBuffer> Serialize();

    public:
        static constexpr uint16_t PROTOCOL_VERSION = 1;
        static constexpr uint16_t HEADER_TLV_NUM = 8;
        static constexpr uint16_t HEADER_UINT8_NUM = 1;
        static constexpr uint16_t HEADER_UINT16_NUM = 2;
        static constexpr uint16_t HEADER_UINT32_NUM = 5;
        static constexpr uint32_t HEADER_LEN = 2 * sizeof(uint16_t) * HEADER_TLV_NUM
            + sizeof(uint16_t) * HEADER_UINT16_NUM
            + sizeof(uint32_t) * HEADER_UINT32_NUM
            + sizeof(uint8_t) * HEADER_UINT8_NUM;
        static constexpr uint32_t BINARY_DATA_MAX_TOTAL_LEN = 100 * 1024 * 1024;
        static constexpr uint32_t BINARY_PAYLOAD_MAX_LEN = 4 * 1024 * 1024;

    public:
        uint16_t version_ = PROTOCOL_VERSION;
        FRAG_TYPE fragFlag_;
        uint32_t dataType_;
        uint32_t seqNum_;
        // assign whole data size
        uint32_t totalLen_;
        uint32_t packetLen_;
        uint32_t payloadLen_;
        // assign packet num
        uint16_t subSeq_;

    private:
        static constexpr uint32_t BASE_HEADER_LEN = 2 * sizeof(uint16_t) * HEADER_TLV_NUM
            + sizeof(uint16_t) * HEADER_UINT16_NUM
            + sizeof(uint32_t) * HEADER_UINT32_NUM
            + sizeof(uint8_t) * HEADER_UINT8_NUM;

    private:
        int32_t WriteTlvItemToBuffer(const TlvItem& tlvItem, uint8_t* header, 
            const uint32_t bufLen);
        uint32_t WriteVersion(uint8_t* header, const uint32_t bufLen);
        uint32_t WriteFragFlag(uint8_t* header, const uint32_t bufLen);
        uint32_t WriteDataType(uint8_t* header, const uint32_t bufLen);
        uint32_t WriteSeqNum(uint8_t* header, const uint32_t bufLen);
        uint32_t WriteTotalLen(uint8_t* header, const uint32_t bufLen);
        uint32_t WritePacketLen(uint8_t* header, const uint32_t bufLen);
        uint32_t WritePayloadLen(uint8_t* header, const uint32_t bufLen);
        uint32_t WriteSubSeq(uint8_t* header, const uint32_t bufLen);

        int32_t ReadTlvItemFromBuffer(TlvItem& tlvItem, SessionDataHeader& sessionHeader,
            const uint8_t* header, const uint8_t* end);
        uint16_t ReadUint16(const uint8_t* header);
        int32_t ReadVersionFromBuffer(SessionDataHeader&, const uint8_t* header, const uint32_t len);
        int32_t ReadFragFlagFromBuffer(SessionDataHeader&, const uint8_t* header, const uint32_t len);
        int32_t ReadDataTypeFromBuffer(SessionDataHeader&, const uint8_t* header, const uint32_t len);
        int32_t ReadSeqNumFromBuffer(SessionDataHeader&, const uint8_t* header, const uint32_t len);
        int32_t ReadTotalLenFromBuffer(SessionDataHeader&, const uint8_t* header, const uint32_t len);
        int32_t ReadPacketLenFromBuffer(SessionDataHeader&, const uint8_t* header, const uint32_t len);
        int32_t ReadPayloadLenFromBuffer(SessionDataHeader&, const uint8_t* header, const uint32_t len);
        int32_t ReadSubSeqFromBuffer(SessionDataHeader&, const uint8_t* header, const uint32_t len);
    };
} // namespace DistributedCollab
} // namespace OHOS
#endif

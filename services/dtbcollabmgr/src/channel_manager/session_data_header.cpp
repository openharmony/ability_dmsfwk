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

#include "session_data_header.h"
#include "dtbcollabmgr_log.h"
#include <optional>

namespace OHOS {
namespace DistributedCollab {
    namespace {
        static constexpr uint32_t DSCHED_SHIFT_8 = 8;
        static constexpr uint16_t UINT16_SHIFT_MASK_0 = 0x00ff;
        static const std::string TAG = "DSchedCollabSessionDataHeader";
        const std::map<uint16_t, uint32_t> HEADER_LEN_VERSION_MAP = {
            { SessionDataHeader::PROTOCOL_VERSION, SessionDataHeader::HEADER_LEN }
        };
    }

    std::unique_ptr<AVTransDataBuffer> SessionDataHeader::Serialize()
    {
        std::unique_ptr<AVTransDataBuffer> buffer = std::make_unique<AVTransDataBuffer>(HEADER_LEN);

        uint8_t* header = buffer->Data();
        uint32_t bufLen = HEADER_LEN;
        uint32_t itemCapacity = 0;

        itemCapacity = WriteVersion(header, bufLen);
        header += itemCapacity;
        bufLen -= itemCapacity;

        itemCapacity = WriteFragFlag(header, bufLen);
        header += itemCapacity;
        bufLen -= itemCapacity;

        itemCapacity = WriteDataType(header, bufLen);
        header += itemCapacity;
        bufLen -= itemCapacity;

        itemCapacity = WriteSeqNum(header, bufLen);
        header += itemCapacity;
        bufLen -= itemCapacity;

        itemCapacity = WriteTotalLen(header, bufLen);
        header += itemCapacity;
        bufLen -= itemCapacity;

        itemCapacity = WritePacketLen(header, bufLen);
        header += itemCapacity;
        bufLen -= itemCapacity;

        itemCapacity = WritePayloadLen(header, bufLen);
        header += itemCapacity;
        bufLen -= itemCapacity;

        itemCapacity = WriteSubSeq(header, bufLen);
        return buffer;
    }

    inline uint32_t SessionDataHeader::WriteVersion(uint8_t* header, const uint32_t bufLen)
    {
        TlvItem item = { TLV_TYPE::TLV_TYPE_VERSION, sizeof(version_), version_ };
        WriteTlvItemToBuffer(item, header, bufLen);
        return TlvItem::HEADER_TYPE_BYTES + TlvItem::HEADER_LEN_BYTES + sizeof(version_);
    }

    inline uint32_t SessionDataHeader::WriteFragFlag(uint8_t* header, const uint32_t bufLen)
    {
        TlvItem item = { TLV_TYPE::TLV_TYPE_FRAG_FLAG, sizeof(fragFlag_), static_cast<uint8_t>(fragFlag_) };
        WriteTlvItemToBuffer(item, header, bufLen);
        return TlvItem::HEADER_TYPE_BYTES + TlvItem::HEADER_LEN_BYTES + sizeof(fragFlag_);
    }

    inline uint32_t SessionDataHeader::WriteDataType(uint8_t* header, const uint32_t bufLen)
    {
        TlvItem item = { TLV_TYPE::TLV_TYPE_DATA_TYPE, sizeof(dataType_), dataType_ };
        WriteTlvItemToBuffer(item, header, bufLen);
        return TlvItem::HEADER_TYPE_BYTES + TlvItem::HEADER_LEN_BYTES + sizeof(dataType_);
    }

    inline uint32_t SessionDataHeader::WriteSeqNum(uint8_t* header, const uint32_t bufLen)
    {
        TlvItem item = { TLV_TYPE::TLV_TYPE_SEQ_NUM, sizeof(seqNum_), seqNum_ };
        WriteTlvItemToBuffer(item, header, bufLen);
        return TlvItem::HEADER_TYPE_BYTES + TlvItem::HEADER_LEN_BYTES + sizeof(seqNum_);
    }

    inline uint32_t SessionDataHeader::WriteTotalLen(uint8_t* header, const uint32_t bufLen)
    {
        TlvItem item = { TLV_TYPE::TLV_TYPE_TOTAL_LEN, sizeof(totalLen_), totalLen_ };
        WriteTlvItemToBuffer(item, header, bufLen);
        return TlvItem::HEADER_TYPE_BYTES + TlvItem::HEADER_LEN_BYTES + sizeof(totalLen_);
    }

    inline uint32_t SessionDataHeader::WriteSubSeq(uint8_t* header, const uint32_t bufLen)
    {
        TlvItem item = { TLV_TYPE::TLV_TYPE_SUB_SEQ, sizeof(subSeq_), subSeq_ };
        WriteTlvItemToBuffer(item, header, bufLen);
        return TlvItem::HEADER_TYPE_BYTES + TlvItem::HEADER_LEN_BYTES + sizeof(subSeq_);
    }

    inline uint32_t SessionDataHeader::WritePayloadLen(uint8_t* header, const uint32_t bufLen)
    {
        TlvItem item = { TLV_TYPE::TLV_TYPE_PAYLOAD_LEN, sizeof(payloadLen_), payloadLen_ };
        WriteTlvItemToBuffer(item, header, bufLen);
        return TlvItem::HEADER_TYPE_BYTES + TlvItem::HEADER_LEN_BYTES + sizeof(payloadLen_);
    }

    inline uint32_t SessionDataHeader::WritePacketLen(uint8_t* header, const uint32_t bufLen)
    {
        TlvItem item = { TLV_TYPE::TLV_TYPE_PACKET_LEN, sizeof(packetLen_), packetLen_ };
        WriteTlvItemToBuffer(item, header, bufLen);
        return TlvItem::HEADER_TYPE_BYTES + TlvItem::HEADER_LEN_BYTES + sizeof(packetLen_);
    }

    inline int32_t SessionDataHeader::WriteTlvItemToBuffer(const TlvItem& tlvItem, uint8_t* header, const uint32_t bufLen)
    {
        uint8_t* current = header;
        uint16_t typeInt = static_cast<uint16_t>(tlvItem.type);
        *current++ = typeInt >> DSCHED_SHIFT_8;
        *current++ = typeInt & UINT16_SHIFT_MASK_0;
        *current++ = tlvItem.len >> DSCHED_SHIFT_8;
        *current++ = tlvItem.len & UINT16_SHIFT_MASK_0;

        int32_t ret = memcpy_s(current, bufLen - (current - header), &tlvItem.value, tlvItem.len);
        if (ret != ERR_OK) {
            HILOGE("copy tlv value failed!, ret %{public}d", ret);
            return WRITE_TLV_ITEM_TO_BUFFER_FAILED;
        }
        return ERR_OK;
    }

    std::optional<SessionDataHeader> SessionDataHeader::Deserialize(const uint8_t* buffer, const size_t bufLen)
    {
        if (buffer == nullptr || bufLen < HEADER_LEN) {
            HILOGE("invalid buffer to deserialize");
            return std::nullopt;
        }
        SessionDataHeader sessionHeader;
        uint8_t* header = const_cast<uint8_t*>(buffer);
        uint8_t* current = header;
        uint8_t* end = header + BASE_HEADER_LEN;
        // move pointer to read each tlv item by base session header
        TlvItem item;
        while (current + TlvItem::HEADER_LEN_BYTES + TlvItem::HEADER_TYPE_BYTES < end) {
            if (sessionHeader.ReadTlvItemFromBuffer(item, sessionHeader, current, end) != ERR_OK) {
                HILOGE("read tlv item failed");
                return std::nullopt;
            }
            // move pointer by each item
            current += (TlvItem::HEADER_LEN_BYTES + TlvItem::HEADER_TYPE_BYTES);
            current += item.len;
        }
        if (sessionHeader.payloadLen_ > SessionDataHeader::BINARY_PAYLOAD_MAX_LEN 
            || sessionHeader.packetLen_ > SessionDataHeader::BINARY_DATA_MAX_TOTAL_LEN) {
            HILOGE("invalid param");
            return std::nullopt;
        }
        if (sessionHeader.totalLen_ < sessionHeader.packetLen_) {
            HILOGE("totalLen too small");
            return std::nullopt;
        }
        // verify header, maybe higher version
        uint32_t headerLen = 0;
        auto versionIt = HEADER_LEN_VERSION_MAP.find(sessionHeader.version_);
        if (versionIt == HEADER_LEN_VERSION_MAP.end()) {
            HILOGW("recv data version higher, %{public}d", sessionHeader.version_);
            // Get header len with max version
            auto maxIt = HEADER_LEN_VERSION_MAP.rbegin();
            headerLen = maxIt->second;
        } else {
            headerLen = versionIt->second;
        }
        if (sessionHeader.packetLen_ < sessionHeader.payloadLen_ + headerLen) {
            HILOGE("invalid header, no match version");
            return std::nullopt;
        }
        // deserialize other variables with matching version
        return sessionHeader;
    }

    inline int32_t SessionDataHeader::ReadTlvItemFromBuffer(TlvItem& tlvItem, SessionDataHeader& sessionHeader,
        const uint8_t* header, const uint8_t* end)
    {
        // assign item format
        uint8_t* current = const_cast<uint8_t*>(header);
        tlvItem.type = static_cast<TLV_TYPE>(ReadUint16(current));
        current += TlvItem::HEADER_TYPE_BYTES;
        tlvItem.len = ReadUint16(current);
        current += TlvItem::HEADER_LEN_BYTES;

        if (current + tlvItem.len > end) {
            HILOGE("reserverd bytes not sufficient");
            return READ_TLV_ITEM_FROM_BUFFER_FAILED;
        }

        // assign session current by len
        int32_t ret = ERR_OK;
        switch (tlvItem.type) {
            case TLV_TYPE::TLV_TYPE_VERSION:
                ret = ReadVersionFromBuffer(sessionHeader, current, tlvItem.len);
                break;

            case TLV_TYPE::TLV_TYPE_FRAG_FLAG:
                ret = ReadFragFlagFromBuffer(sessionHeader, current, tlvItem.len);
                break;

            case TLV_TYPE::TLV_TYPE_DATA_TYPE:
                ret = ReadDataTypeFromBuffer(sessionHeader, current, tlvItem.len);
                break;

            case TLV_TYPE::TLV_TYPE_SEQ_NUM:
                ret = ReadSeqNumFromBuffer(sessionHeader, current, tlvItem.len);
                break;

            case TLV_TYPE::TLV_TYPE_TOTAL_LEN:
                ret = ReadTotalLenFromBuffer(sessionHeader, current, tlvItem.len);
                break;

            case TLV_TYPE::TLV_TYPE_SUB_SEQ:
                ret = ReadSubSeqFromBuffer(sessionHeader, current, tlvItem.len);
                break;

            case TLV_TYPE::TLV_TYPE_PAYLOAD_LEN:
                ret = ReadPayloadLenFromBuffer(sessionHeader, current, tlvItem.len);
                break;

            case TLV_TYPE::TLV_TYPE_PACKET_LEN:
                ret = ReadPacketLenFromBuffer(sessionHeader, current, tlvItem.len);
                break;

            default:
                HILOGE("invalid data type: %{public}d", static_cast<uint16_t>(tlvItem.type));
                return READ_TLV_ITEM_FROM_BUFFER_FAILED;
        }

        return ret;
    }

    inline uint16_t SessionDataHeader::ReadUint16(const uint8_t* header)
    {
        return (header[0] << DSCHED_SHIFT_8) | header[1];
    }

    inline int32_t SessionDataHeader::ReadVersionFromBuffer(SessionDataHeader& sessionHeader, 
        const uint8_t* header, const uint32_t len)
    {
        int32_t ret = memcpy_s(&sessionHeader.version_, sizeof(sessionHeader.version_), header, len);
        if (ret != ERR_OK) {
            HILOGE("Set Version failed");
            return READ_TLV_ITEM_FROM_BUFFER_FAILED;
        }
        return ERR_OK;
    }

    inline int32_t SessionDataHeader::ReadFragFlagFromBuffer(SessionDataHeader& sessionHeader, 
        const uint8_t* header, const uint32_t len)
    {
        int32_t ret = memcpy_s(&sessionHeader.fragFlag_, sizeof(sessionHeader.fragFlag_), header, len);
        if (ret != ERR_OK) {
            HILOGE("Set FragFlag failed");
            return READ_TLV_ITEM_FROM_BUFFER_FAILED;
        }
        return ERR_OK;
    }

    inline int32_t SessionDataHeader::ReadDataTypeFromBuffer(SessionDataHeader& sessionHeader, 
        const uint8_t* header, const uint32_t len)
    {
        int32_t ret = memcpy_s(&sessionHeader.dataType_, sizeof(sessionHeader.dataType_), header, len);
        if (ret != ERR_OK) {
            HILOGE("Set DataType failed");
            return READ_TLV_ITEM_FROM_BUFFER_FAILED;
        }
        return ERR_OK;
    }

    inline int32_t SessionDataHeader::ReadSeqNumFromBuffer(SessionDataHeader& sessionHeader, 
        const uint8_t* header, const uint32_t len)
    {
        int32_t ret = memcpy_s(&sessionHeader.seqNum_, sizeof(sessionHeader.seqNum_), header, len);
        if (ret != ERR_OK) {
            HILOGE("Set SeqNum failed");
            return READ_TLV_ITEM_FROM_BUFFER_FAILED;
        }
        return ERR_OK;
    }

    inline int32_t SessionDataHeader::ReadTotalLenFromBuffer(SessionDataHeader& sessionHeader, 
        const uint8_t* header, const uint32_t len)
    {
        int32_t ret = memcpy_s(&sessionHeader.totalLen_, sizeof(sessionHeader.totalLen_), header, len);
        if (ret != ERR_OK) {
            HILOGE("Set TotalLen failed");
            return READ_TLV_ITEM_FROM_BUFFER_FAILED;
        }
        return ERR_OK;
    }

    inline int32_t SessionDataHeader::ReadSubSeqFromBuffer(SessionDataHeader& sessionHeader, 
        const uint8_t* header, const uint32_t len)
    {
        int32_t ret = memcpy_s(&sessionHeader.subSeq_, sizeof(sessionHeader.subSeq_), header, len);
        if (ret != ERR_OK) {
            HILOGE("Set SubSeq failed");
            return READ_TLV_ITEM_FROM_BUFFER_FAILED;
        }
        return ERR_OK;
    }

    inline int32_t SessionDataHeader::ReadPayloadLenFromBuffer(SessionDataHeader& sessionHeader, 
        const uint8_t* header, const uint32_t len)
    {
        int32_t ret = memcpy_s(&sessionHeader.payloadLen_, sizeof(sessionHeader.payloadLen_), header, len);
        if (ret != ERR_OK) {
            HILOGE("Set DataLen failed");
            return READ_TLV_ITEM_FROM_BUFFER_FAILED;
        }
        return ERR_OK;
    }

    inline int32_t SessionDataHeader::ReadPacketLenFromBuffer(SessionDataHeader& sessionHeader, 
        const uint8_t* header, const uint32_t len)
    {
        int32_t ret = memcpy_s(&sessionHeader.packetLen_, sizeof(sessionHeader.packetLen_), header, len);
        if (ret != ERR_OK) {
            HILOGE("Set DataLen failed");
            return READ_TLV_ITEM_FROM_BUFFER_FAILED;
        }
        return ERR_OK;
    }
} // namespace DistributedCollab
} // namespace OHOS
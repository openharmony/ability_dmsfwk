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

#include "message_data_header.h"
#include "dtbcollabmgr_log.h"
#include <optional>

namespace OHOS {
namespace DistributedCollab {
namespace {
    static constexpr uint32_t DSCHED_SHIFT_8 = 8;
    static constexpr uint16_t UINT16_SHIFT_MASK_0 = 0x00ff;
    static const std::string TAG = "DSchedCollabMessageDataHeader";
    const std::map<uint16_t, uint32_t> HEADER_LEN_VERSION_MAP = {
        { MessageDataHeader::PROTOCOL_VERSION, MessageDataHeader::HEADER_LEN }
    };
}

std::unique_ptr<AVTransDataBuffer> MessageDataHeader::Serialize()
{
    std::unique_ptr<AVTransDataBuffer> buffer = std::make_unique<AVTransDataBuffer>(HEADER_LEN);

    uint8_t* header = buffer->Data();
    uint32_t bufLen = HEADER_LEN;
    uint32_t itemCapacity = 0;

    itemCapacity = WriteVersion(header, bufLen);
    header += itemCapacity;
    bufLen -= itemCapacity;

    itemCapacity = WriteDataType(header, bufLen);
    header += itemCapacity;
    bufLen -= itemCapacity;

    itemCapacity = WriteTotalLen(header, bufLen);
    return buffer;
}

uint32_t MessageDataHeader::WriteVersion(uint8_t* header, const uint32_t bufLen)
{
    MessageTlvItem item = { MESSAGE_TLV_TYPE::TLV_TYPE_VERSION, sizeof(version_), version_ };
    WriteTlvItemToBuffer(item, header, bufLen);
    return MessageTlvItem::HEADER_TYPE_BYTES + MessageTlvItem::HEADER_LEN_BYTES + sizeof(version_);
}

uint32_t MessageDataHeader::WriteDataType(uint8_t* header, const uint32_t bufLen)
{
    MessageTlvItem item = { MESSAGE_TLV_TYPE::TLV_TYPE_DATA_TYPE, sizeof(dataType_), dataType_ };
    WriteTlvItemToBuffer(item, header, bufLen);
    return MessageTlvItem::HEADER_TYPE_BYTES + MessageTlvItem::HEADER_LEN_BYTES + sizeof(dataType_);
}

uint32_t MessageDataHeader::WriteTotalLen(uint8_t* header, const uint32_t bufLen)
{
    MessageTlvItem item = { MESSAGE_TLV_TYPE::TLV_TYPE_TOTAL_LEN, sizeof(totalLen_), totalLen_ };
    WriteTlvItemToBuffer(item, header, bufLen);
    return MessageTlvItem::HEADER_TYPE_BYTES + MessageTlvItem::HEADER_LEN_BYTES + sizeof(totalLen_);
}

int32_t MessageDataHeader::WriteTlvItemToBuffer(const MessageTlvItem& tlvItem,
    uint8_t* header, const uint32_t bufLen)
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

std::optional<MessageDataHeader> MessageDataHeader::Deserialize(const uint8_t* buffer, const size_t bufLen)
{
    if (buffer == nullptr || bufLen < HEADER_LEN) {
        HILOGE("invalid buffer to deserialize");
        return std::nullopt;
    }

    MessageDataHeader messageHeader;
    uint8_t* header = const_cast<uint8_t*>(buffer);
    uint8_t* current = header;
    uint8_t* end = header + BASE_HEADER_LEN;

    MessageTlvItem item;
    while (current + MessageTlvItem::HEADER_LEN_BYTES + MessageTlvItem::HEADER_TYPE_BYTES < end) {
        if (messageHeader.ReadTlvItemFromBuffer(item, messageHeader, current, end) != ERR_OK) {
            HILOGE("read tlv item failed");
            return std::nullopt;
        }
        current += (MessageTlvItem::HEADER_LEN_BYTES + MessageTlvItem::HEADER_TYPE_BYTES);
        current += item.len;
    }

    return messageHeader;
}

int32_t MessageDataHeader::ReadTlvItemFromBuffer(MessageTlvItem& tlvItem, MessageDataHeader& messageHeader,
    const uint8_t* header, const uint8_t* end)
{
    // assign item format
    uint8_t* current = const_cast<uint8_t*>(header);
    tlvItem.type = static_cast<MESSAGE_TLV_TYPE>(ReadUint16(current));
    current += MessageTlvItem::HEADER_TYPE_BYTES;
    tlvItem.len = ReadUint16(current);
    current += MessageTlvItem::HEADER_LEN_BYTES;

    if (current + tlvItem.len > end) {
        HILOGE("reserverd bytes not sufficient");
        return READ_TLV_ITEM_FROM_BUFFER_FAILED;
    }

    // assign session current by len
    int32_t ret = ERR_OK;
    switch (tlvItem.type) {
        case MESSAGE_TLV_TYPE::TLV_TYPE_VERSION:
            ret = ReadVersionFromBuffer(messageHeader, current, tlvItem.len);
            break;

        case MESSAGE_TLV_TYPE::TLV_TYPE_DATA_TYPE:
            ret = ReadDataTypeFromBuffer(messageHeader, current, tlvItem.len);
            break;

        case MESSAGE_TLV_TYPE::TLV_TYPE_TOTAL_LEN:
            ret = ReadTotalLenFromBuffer(messageHeader, current, tlvItem.len);
            break;

        default:
            HILOGE("invalid data type: %{public}d", static_cast<uint16_t>(tlvItem.type));
            return READ_TLV_ITEM_FROM_BUFFER_FAILED;
        }

    return ret;
}

uint16_t MessageDataHeader::ReadUint16(const uint8_t* header)
{
    return (header[0] << DSCHED_SHIFT_8) | header[1];
}

int32_t MessageDataHeader::ReadVersionFromBuffer(MessageDataHeader& messageHeader,
    const uint8_t* header, const uint32_t len)
{
    int32_t ret = memcpy_s(&messageHeader.version_, sizeof(messageHeader.version_), header, len);
    if (ret != ERR_OK) {
        HILOGE("Set Version failed");
        return READ_TLV_ITEM_FROM_BUFFER_FAILED;
    }
    return ERR_OK;
}

int32_t MessageDataHeader::ReadDataTypeFromBuffer(MessageDataHeader& messageHeader,
    const uint8_t* header, const uint32_t len)
{
    int32_t ret = memcpy_s(&messageHeader.dataType_, sizeof(messageHeader.dataType_), header, len);
    if (ret != ERR_OK) {
        HILOGE("Set DataType failed");
        return READ_TLV_ITEM_FROM_BUFFER_FAILED;
    }
    return ERR_OK;
}

int32_t MessageDataHeader::ReadTotalLenFromBuffer(MessageDataHeader& messageHeader,
    const uint8_t* header, const uint32_t len)
{
    int32_t ret = memcpy_s(&messageHeader.totalLen_, sizeof(messageHeader.totalLen_), header, len);
    if (ret != ERR_OK) {
        HILOGE("Set TotalLen failed");
        return READ_TLV_ITEM_FROM_BUFFER_FAILED;
    }
    return ERR_OK;
}
} // namespace DistributedCollab
} // namespace OHOS
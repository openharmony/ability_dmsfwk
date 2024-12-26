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

#ifndef OHOS_DSCHED_COLLAB_MESSAGE_DATA_HEADER_H
#define OHOS_DSCHED_COLLAB_MESSAGE_DATA_HEADER_H

#include "av_trans_data_buffer.h"

#include <map>
#include <memory>

namespace OHOS {
namespace DistributedCollab {
    enum class MESSAGE_TLV_TYPE : uint16_t {
        TLV_TYPE_NULL = 0,
        TLV_TYPE_VERSION = 1001,
        TLV_TYPE_DATA_TYPE = 1002,
        TLV_TYPE_TOTAL_LEN = 1003,
    };

    struct MessageTlvItem {
        MESSAGE_TLV_TYPE type = MESSAGE_TLV_TYPE::TLV_TYPE_NULL;
        uint16_t len = 0;
        uint32_t value = 0;

        static constexpr uint16_t HEADER_TYPE_BYTES = sizeof(type);
        static constexpr uint16_t HEADER_LEN_BYTES = sizeof(len);
    };

    class MessageDataHeader {
    public:
        static std::optional<MessageDataHeader> Deserialize(const uint8_t* buffer, const size_t bufLen);

    public:
        explicit MessageDataHeader() = default;
        explicit MessageDataHeader(
            uint16_t version,
            uint32_t dataType,
            uint32_t totalLen)
            : version_(version),
            dataType_(dataType),
            totalLen_(totalLen) {};
        ~MessageDataHeader() = default;
        std::unique_ptr<AVTransDataBuffer> Serialize();

    public:
        static constexpr uint16_t PROTOCOL_VERSION = 1;
        static constexpr uint16_t HEADER_TLV_NUM = 3;
        static constexpr uint16_t HEADER_UINT16_NUM = 1;
        static constexpr uint16_t HEADER_UINT32_NUM = 2;
        static constexpr uint32_t HEADER_LEN = 2 * sizeof(uint16_t) * HEADER_TLV_NUM +
            sizeof(uint16_t) * HEADER_UINT16_NUM + sizeof(uint32_t) * HEADER_UINT32_NUM;
        static constexpr uint32_t BINARY_DATA_MAX_TOTAL_LEN = 100 * 1024 * 1024;
        static constexpr uint32_t BINARY_PAYLOAD_MAX_LEN = 4 * 1024 * 1024;

    public:
        uint16_t version_ = PROTOCOL_VERSION;
        uint32_t dataType_;
        uint32_t totalLen_;

    private:
        static constexpr uint32_t BASE_HEADER_LEN = 2 * sizeof(uint16_t) * HEADER_TLV_NUM +
            sizeof(uint16_t) * HEADER_UINT16_NUM + sizeof(uint32_t) * HEADER_UINT32_NUM;

    private:
        int32_t WriteTlvItemToBuffer(const MessageTlvItem& tlvItem, uint8_t* header, const uint32_t bufLen);
        uint32_t WriteVersion(uint8_t* header, const uint32_t bufLen);
        uint32_t WriteDataType(uint8_t* header, const uint32_t bufLen);
        uint32_t WriteTotalLen(uint8_t* header, const uint32_t bufLen);

        int32_t ReadTlvItemFromBuffer(MessageTlvItem& tlvItem, MessageDataHeader& sessionHeader,
            const uint8_t* header, const uint8_t* end);
        uint16_t ReadUint16(const uint8_t* header);
        int32_t ReadVersionFromBuffer(MessageDataHeader&, const uint8_t* header, const uint32_t len);
        int32_t ReadDataTypeFromBuffer(MessageDataHeader&, const uint8_t* header, const uint32_t len);
        int32_t ReadTotalLenFromBuffer(MessageDataHeader&, const uint8_t* header, const uint32_t len);
    };
} // namespace DistributedCollab
} // namespace OHOS
#endif
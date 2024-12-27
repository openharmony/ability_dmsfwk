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
#ifndef DISTRIBUTED_COLLAB_SESSION_DATA_HEADER_TEST_H
#define DISTRIBUTED_COLLAB_SESSION_DATA_HEADER_TEST_H

#include "session_data_header.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace DistributedCollab {
class SessionDataHeaderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    uint16_t version;
    FRAG_TYPE fragFlag;
    uint32_t dataType;
    uint32_t seqNum;
    uint32_t totalLen;
    uint32_t packetLen;
    uint32_t payloadLen;
    uint16_t subSeq;

    std::unique_ptr<SessionDataHeader> header;
};

} // namespace DistributedCollab
} // namespace OHOS
#endif
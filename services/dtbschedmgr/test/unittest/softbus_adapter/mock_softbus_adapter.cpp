/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "mock_softbus_adapter.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
SoftbusMock *SoftbusMock::gMock;

SoftbusMock::SoftbusMock()
{
    gMock = this;
}

SoftbusMock::~SoftbusMock()
{
    gMock = nullptr;
}

SoftbusMock& SoftbusMock::GetMock()
{
    return *gMock;
}

extern "C" {
int GetSessionOption(int sessionId, SessionOption option, void* optionValue, uint32_t valueSize)
{
    return SoftbusMock::GetMock().GetSessionOption(sessionId,
        option, optionValue, valueSize);
}
}
} // namespace DistributedSchedule
} // namespace OHOS

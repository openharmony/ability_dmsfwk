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

#ifndef OHOS_DSCHED_DATA_BUFFER_H
#define OHOS_DSCHED_DATA_BUFFER_H

#include <string>

namespace OHOS {
namespace DistributedSchedule {
class DSchedDataBuffer {
public:
    explicit DSchedDataBuffer(size_t capacity);
    ~DSchedDataBuffer();

    size_t Size();
    size_t Offset();
    size_t Capacity();
    uint8_t *Data();
    int32_t SetRange(size_t offset, size_t size);

private:
    static const uint32_t DSCHED_MAX_BUFFER_SIZE = 80 * 1024 * 1024;

    size_t capacity_ = 0;
    size_t rangeOffset_ = 0;
    size_t rangeLength_ = 0;
    uint8_t *data_ = nullptr;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_DATA_BUFFER_H

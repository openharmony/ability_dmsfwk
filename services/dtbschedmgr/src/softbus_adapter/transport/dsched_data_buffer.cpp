/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "dsched_data_buffer.h"

#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
DSchedDataBuffer::DSchedDataBuffer(size_t capacity)
{
    if (capacity != 0 && capacity < DSCHED_MAX_BUFFER_SIZE) {
        data_ = new uint8_t[capacity] {0};
        if (data_ != nullptr) {
            capacity_ = capacity;
            rangeLength_ = capacity;
        }
    }
}

DSchedDataBuffer::~DSchedDataBuffer()
{
    if (data_ != nullptr) {
        delete[] data_;
        data_ = nullptr;
    }
}

size_t DSchedDataBuffer::Size()
{
    return rangeLength_;
}

size_t DSchedDataBuffer::Offset()
{
    return rangeOffset_;
}

size_t DSchedDataBuffer::Capacity()
{
    return capacity_;
}

uint8_t *DSchedDataBuffer::Data()
{
    if (data_ == nullptr) {
        return nullptr;
    }
    return data_ + rangeOffset_;
}

int32_t DSchedDataBuffer::SetRange(size_t offset, size_t size)
{
    if (!(offset <= capacity_) || !(offset + size <= capacity_)) {
        return -1;
    }

    rangeOffset_ = offset;
    rangeLength_ = size;
    return ERR_OK;
}
}
}
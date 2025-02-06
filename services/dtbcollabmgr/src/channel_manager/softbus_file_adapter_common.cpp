/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "softbus_file_adapter.h"
#include "dtbcollabmgr_log.h"
#include <string>

namespace OHOS {
namespace DistributedCollab {
IMPLEMENT_SINGLE_INSTANCE(SoftbusFileAdpater);
namespace {
    static const std::string TAG = "SoftbusFileAdpaterCommon";
}

int32_t SoftbusFileAdpater::SetFileSchema(int32_t socketId)
{
    HILOGI("common empty SoftbusFileAdpater::SetFileSchema");
    return ERR_OK;
}

int32_t SoftbusFileAdpater::Open(const char* filename, int32_t flag, int32_t mode)
{
    HILOGI("common empty SoftbusFileAdpater::Open");
    return ERR_OK;
}

int32_t SoftbusFileAdpater::Close(int32_t fd)
{
    HILOGI("common empty SoftbusFileAdpater::Close");
    return ERR_OK;
}

int32_t SoftbusFileAdpater::Remove(const char* filename)
{
    HILOGI("common empty SoftbusFileAdpater::Remove");
    return ERR_OK;
}
}
}
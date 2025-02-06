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

#ifndef OHOS_DSCHED_COLLAB_SOFTBUS_FILE_ADAPTER_H
#define OHOS_DSCHED_COLLAB_SOFTBUS_FILE_ADAPTER_H

#include "single_instance.h"
#include <stdint.h>

namespace OHOS {
namespace DistributedCollab {
class SoftbusFileAdpater {
    DECLARE_SINGLE_INSTANCE(SoftbusFileAdpater);

public:
    int32_t SetFileSchema(int32_t socketId);
    int32_t Open(const char* filename, int32_t flag, int32_t mode);
    int32_t Close(int32_t fd);
    int32_t Remove(const char* filename);
}
}
#endif
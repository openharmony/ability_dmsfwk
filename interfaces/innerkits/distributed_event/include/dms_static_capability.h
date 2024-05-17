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
#ifndef DMS_STATIC_CAPABILITY_H
#define DMS_STATIC_CAPABILITY_H

#include "single_instance.h"
#include "i_static_capability_collector.h"


#ifndef API_EXPORT
#define API_EXPORT __attribute__((visibility("default")))
#endif

namespace OHOS {
namespace DistributedSchedule {
class DmsStaticCapability : public DistributedDeviceProfile::IStaticCapabilityCollector {
DECLARE_SINGLE_INSTANCE_BASE(DmsStaticCapability);
public:
    DmsStaticCapability() = default;
    ~DmsStaticCapability() = default;
    API_EXPORT bool IsSupportCapability() override;
};

#ifdef __cplusplus
extern "C" {
#endif
API_EXPORT DistributedDeviceProfile::IStaticCapabilityCollector* GetStaticCapabilityCollector();
#ifdef __cplusplus
}
#endif
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DMS_STATIC_CAPABILITY_H
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

#ifndef OHOS_APPMGMT_I_DISTRIBUTED_EXTENSION_H
#define OHOS_APPMGMT_I_DISTRIBUTED_EXTENSION_H

#include "iremote_broker.h"
#include "want.h"
#include "errors.h"

namespace OHOS {
namespace DistributedSchedule {
enum class IDExtensionInterfaceCode {
    CMD_ON_CREATE = 1,
    CMD_ON_DESTORY,
    CMD_ON_COLLAB_REQUEST,
};

class IDExtension : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.AppManagement.Distributed.IExtension");

public:
    virtual ~IDExtension() = default;
    virtual int32_t TriggerOnCreate(AAFwk::Want &want) = 0;
    virtual int32_t TriggerOnDestroy() = 0;
    virtual int32_t TriggerOnCollaborate(AAFwk::WantParams &wantParam) = 0;
};
}
}

#endif // OHOS_APPMGMT_I_DISTRIBUTED_EXTENSION_H

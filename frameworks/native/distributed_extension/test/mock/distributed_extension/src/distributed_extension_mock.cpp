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

#include "distributed_extension_mock.h"

namespace OHOS::DistributedSchedule {
using namespace std;

void DistributedExtension::Init(const shared_ptr<AbilityRuntime::AbilityLocalRecord> &record,
    const shared_ptr<AbilityRuntime::OHOSApplication> &application,
    shared_ptr<AbilityRuntime::AbilityHandler> &handler, const sptr<IRemoteObject> &token)
{
    TDExtension::tDExtension->Init(record, application, handler, token);
}

void DistributedExtension::OnStart(const AAFwk::Want &want)
{
    TDExtension::tDExtension->OnStart(want);
}

void DistributedExtension::OnCommand(const AAFwk::Want &want, bool restart, int startId)
{
    TDExtension::tDExtension->OnCommand(want, restart, startId);
}

sptr<IRemoteObject> DistributedExtension::OnConnect(const AAFwk::Want &want)
{
    return TDExtension::tDExtension->OnConnect(want);
}

void DistributedExtension::OnDisconnect(const AAFwk::Want &want)
{
    TDExtension::tDExtension->OnDisconnect(want);
}

int32_t DistributedExtension::TriggerOnCreate(AAFwk::Want& want)
{
    return TDExtension::tDExtension->OnCreate(want);
}

int32_t DistributedExtension::TriggerOnDestroy()
{
    return TDExtension::tDExtension->OnDestroy();
}

int32_t DistributedExtension::TriggerOnCollaborate(AAFwk::WantParams &wantParam)
{
    return TDExtension::tDExtension->OnCollabRequest(wantParam);
}
} // namespace OHOS::DistributedSchedule

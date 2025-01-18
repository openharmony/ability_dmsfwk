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

#include "distributed_extension.h"

#include "distributed_extension_js.h"
#include "distributed_extension_service.h"
#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DistributedExtension";

using namespace std;

void DistributedExtension::Init(const shared_ptr<AbilityRuntime::AbilityLocalRecord> &record,
    const shared_ptr<AbilityRuntime::OHOSApplication> &application,
    shared_ptr<AbilityRuntime::AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    HILOG_INFO("Init the DistributedExtensionAbility(Base)");
    AbilityRuntime::ExtensionBase<DistributedExtensionContext>::Init(record, application, handler, token);
}

DistributedExtension *DistributedExtension::Create(const unique_ptr<AbilityRuntime::Runtime> &runtime)
{
    if (!runtime) {
        HILOG_DEBUG("Create as BackupExtensionAbility(base)");
        return new DistributedExtension();
    }

    switch (runtime->GetLanguage()) {
        case AbilityRuntime::Runtime::Language::JS:
            HILOG_INFO("Create as DistributedExtensionAbility(JS)");
            return DistributedExtensionJs::Create(runtime);

        default:
            HILOG_INFO("Create as DistributedExtensionAbility(base)");
            return new DistributedExtension();
    }
}

void DistributedExtension::OnStart(const AAFwk::Want &want)
{
    HILOG_INFO("DistributedExtensionAbility was started");
    Extension::OnStart(want);
}

void DistributedExtension::OnCommand(const AAFwk::Want &want, bool restart, int startId)
{
    HILOG_INFO("DistributedExtensionAbility was invoked. restart=%{public}d, startId=%{public}d", restart, startId);
}

sptr<IRemoteObject> DistributedExtension::OnConnect(const AAFwk::Want &want)
{
    try {
        HILOG_INFO("DistributedExtension::OnConnect begin connect");
        Extension::OnConnect(want);

        auto remoteObject = sptr<DistributedExtensionService>(
            new DistributedExtensionService(std::static_pointer_cast<DistributedExtension>(shared_from_this()),
            want.GetBundle()));
        return remoteObject->AsObject();
    } catch (const exception &e) {
        HILOG_ERROR("%{public}s", e.what());
        return nullptr;
    } catch (...) {
        HILOG_ERROR("");
        return nullptr;
    }
}

void DistributedExtension::OnDisconnect(const AAFwk::Want &want)
{
    try {
        HILOG_INFO("begin disconnect");
        sptr<DistributedExtensionService> distributedExtensionService = distributedExtensionService_.promote();
        if (distributedExtensionService != nullptr) {
            distributedExtensionService->Clear();
        }
        Extension::OnDisconnect(want);
        HILOG_INFO("end");
    } catch (const exception &e) {
        HILOG_ERROR("%{public}s", e.what());
        return;
    } catch (...) {
        HILOG_ERROR("");
        return;
    }
}

void DistributedExtension::SetDistributedExtensionService(
    const wptr<DistributedExtensionService> &distributedExtensionService)
{
    distributedExtensionService_ = distributedExtensionService;
}

int32_t DistributedExtension::TriggerOnCreate(AAFwk::Want& want)
{
    HILOG_INFO("jDistributedExtension::TriggerOnCreate");
    return ERR_OK;
}

int32_t DistributedExtension::TriggerOnDestroy()
{
    HILOG_INFO("DistributedExtension::TriggerOnDestroy");
    return ERR_OK;
}

int32_t DistributedExtension::TriggerOnCollaborate(AAFwk::WantParams &wantParam)
{
    HILOG_INFO("DistributedExtension::TriggerOnCollaborate");
    return ERR_OK;
}
}
}

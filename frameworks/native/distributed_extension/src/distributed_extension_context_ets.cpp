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
#include "distributed_extension_context_ets.h"
#include "distributed_extension.h"
#include "dtbschedmgr_log.h"
#include "ets_context_utils.h"
#include "ets_error_utils.h"
#include "ets_extension_context.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DistributedExtensionContextETS";
constexpr const char *DISTRIBUTED_EXTENSION_CONTEXT_CLASS_NAME =
    "@ohos.application.DistributedExtensionContext.DistributedExtensionContext";
constexpr const char *CLEANER_CLASS_NAME = "@ohos.application.DistributedExtensionContext.Cleaner";
bool BindNativeMethods(ani_env *env, ani_class &cls)
{
    ani_status status = ANI_ERROR;
    ani_class cleanerCls = nullptr;
    status = env->FindClass(CLEANER_CLASS_NAME, &cleanerCls);
    if (status != ANI_OK || cleanerCls == nullptr) {
        HILOG_ERROR("Failed to find class, status: %{public}d", status);
        return false;
    }
    std::array CleanerMethods = {
        ani_native_function { "clean", nullptr, reinterpret_cast<void *>(DistributedExtensionContextETS::Finalizer) },
    };
    if ((status = env->Class_BindNativeMethods(cleanerCls, CleanerMethods.data(), CleanerMethods.size())) != ANI_OK
        && status != ANI_ALREADY_BINDED) {
        HILOG_ERROR("bind method status: %{public}d", status);
        return false;
    }
    return true;
}

ani_object CreateDistributedExtensionContextETS(ani_env *env, std::shared_ptr<DistributedExtensionContext> &context)
{
    HILOG_INFO("CreateDistributedExtensionContextETS call");
    if (env == nullptr || context == nullptr) {
        HILOG_ERROR("null env or context");
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(DISTRIBUTED_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK || cls == nullptr) {
        HILOG_ERROR("Failed to find class, status: %{public}d", status);
        return nullptr;
    }
    if (!BindNativeMethods(env, cls)) {
        HILOG_ERROR("Failed to BindNativeMethods");
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "l:", &method)) != ANI_OK || method == nullptr) {
        HILOG_ERROR("Failed to find constructor, status : %{public}d", status);
        return nullptr;
    }
    std::unique_ptr<DistributedExtensionContextETS> workContext = std::make_unique<DistributedExtensionContextETS>(
        context);
    if (workContext == nullptr) {
        HILOG_ERROR("Failed to create DistributedExtensionContextETS");
        return nullptr;
    }
    auto distributeContextPtr = new std::weak_ptr<DistributedExtensionContext> (workContext->GetAbilityContext());
    if (distributeContextPtr == nullptr) {
        HILOG_ERROR("distributeContextPtr is nullptr");
        return nullptr;
    }
    ani_object contextObj = nullptr;
    if ((status = env->Object_New(cls, method, &contextObj, (ani_long)workContext.release())) != ANI_OK ||
        contextObj == nullptr) {
        HILOG_ERROR("Failed to create object, status : %{public}d", status);
        delete distributeContextPtr;
        distributeContextPtr = nullptr;
        return nullptr;
    }
    if (!ContextUtil::SetNativeContextLong(env, contextObj, (ani_long)(distributeContextPtr))) {
        HILOG_ERROR("Failed to setNativeContextLong ");
        delete distributeContextPtr;
        distributeContextPtr = nullptr;
        return nullptr;
    }
    ContextUtil::CreateEtsBaseContext(env, cls, contextObj, context);
    CreateEtsExtensionContext(env, cls, contextObj, context, context->GetAbilityInfo());
    return contextObj;
}

void DistributedExtensionContextETS::Finalizer(ani_env *env, ani_object obj)
{
    HILOG_INFO("Finalizer");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    ani_long nativeEtsContextPtr;
    if (env->Object_GetFieldByName_Long(obj, "nativeEtsContext", &nativeEtsContextPtr) != ANI_OK) {
        HILOG_ERROR("Failed to get nativeEtsContext");
        return;
    }
    if (nativeEtsContextPtr != 0) {
        delete reinterpret_cast<DistributedExtensionContextETS *>(nativeEtsContextPtr);
    }
}
} // namespace DistributedSchedule
} // namespace OHOS
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

#include "distributed_extension_js.h"

#include "distributed_extension_context_js.h"
#include "dtbschedmgr_log.h"
#include "napi_common_want.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace std;

constexpr size_t ARGC_ONE = 1;
static std::mutex g_distributedExtensionValidLock;
static int32_t g_distributedExtensionCount = 0;

static string GetSrcPath(const AppExecFwk::AbilityInfo &info)
{
    using AbilityRuntime::Extension;
    stringstream ss;

    if (!info.srcEntrance.empty()) {
        ss << info.moduleName << '/' << string(info.srcEntrance, 0, info.srcEntrance.rfind(".")) << ".abc";
        return ss.str();
    }
    return "";
}

napi_value AttachDistributedExtensionContext(napi_env env, void *value, void *)
{
    HILOG_INFO("AttachDistributedExtensionContext");
    if (value == nullptr || env == nullptr) {
        HILOG_WARN("invalid parameter.");
        return nullptr;
    }
    auto ptr = reinterpret_cast<std::weak_ptr<DistributedExtensionContext> *>(value)->lock();
    if (ptr == nullptr) {
        HILOG_ERROR("invalid context.");
        return nullptr;
    }
    auto object = CreateDistributedExtensionContextJS(env, ptr);
    if (object == nullptr) {
        HILOG_ERROR("Failed to get js distributed extension context");
        return nullptr;
    }
    auto contextRef = AbilityRuntime::JsRuntime::LoadSystemModuleByEngine(env,
        "application.DistributedExtensionContext", &object, 1);
    if (contextRef == nullptr) {
        HILOG_ERROR("Failed to load BackupExtensionContext.");
        return nullptr;
    }
    napi_value contextObj = contextRef->GetNapiValue();
    napi_coerce_to_native_binding_object(env, contextObj, AbilityRuntime::DetachCallbackFunc,
                                         AttachDistributedExtensionContext, value, nullptr);

    auto workContext = new (std::nothrow) std::weak_ptr<DistributedExtensionContext>(ptr);
    if (workContext == nullptr) {
        HILOG_ERROR("Failed to get backup extension context");
        return nullptr;
    }
    napi_status status = napi_wrap(
        env, contextObj, workContext,
        [](napi_env, void *data, void *) {
            HILOG_DEBUG("Finalizer for weak_ptr base context is called");
            delete static_cast<std::weak_ptr<DistributedExtensionContext> *>(data);
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        HILOG_DEBUG("Failed to wrap js instance");
        delete workContext;
        workContext = nullptr;
    }
    return contextObj;
}

void DistributedExtensionJs::Init(const shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
    const shared_ptr<AppExecFwk::OHOSApplication> &application,
    shared_ptr<AppExecFwk::AbilityHandler> &handler, const sptr<IRemoteObject> &token)
{
    HILOG_INFO("Init the DistributedExtensionAbility(JS)");
    try {
        DistributedExtension::Init(record, application, handler, token);
        if (abilityInfo_ == nullptr) {
            HILOG_ERROR("Invalid abilityInfo_");
            return;
        }
        const AppExecFwk::AbilityInfo &info = *abilityInfo_;
        string bundleName = info.bundleName;
        string moduleName(info.moduleName + "::" + info.name);
        string modulePath = GetSrcPath(info);
        int moduleType = static_cast<int>(info.type);
        HILOG_INFO("Try to load %{public}s's %{public}s(type %{public}d) from %{public}s", bundleName.c_str(),
            moduleName.c_str(), moduleType, modulePath.c_str());

        AbilityRuntime::HandleScope handleScope(jsRuntime_);
        jsObj_ = jsRuntime_.LoadModule(moduleName, modulePath, info.hapPath,
                                       abilityInfo_->compileMode == AbilityRuntime::CompileMode::ES_MODULE);
        if (jsObj_ == nullptr) {
            HILOG_WARN("Oops! There's no custom DistributedExtensionAbility");
            return;
        }
        HILOG_INFO("Wow! Here's a custsom DistributedExtensionAbility");
        ExportJsContext();
    } catch (const exception &e) {
        HILOG_ERROR("%{public}s", e.what());
    }
}

DistributedExtensionJs::DistributedExtensionJs(AbilityRuntime::JsRuntime &jsRuntime) : jsRuntime_(jsRuntime)
{
    std::lock_guard<std::mutex> lock(g_distributedExtensionValidLock);
    g_distributedExtensionCount += 1;
    HILOG_INFO("DistributedExtensionJs::DistributedExtensionJs, count=%{public}d.", g_distributedExtensionCount);
}

DistributedExtensionJs::~DistributedExtensionJs()
{
    jsRuntime_.FreeNativeReference(std::move(jsObj_));
    std::lock_guard<std::mutex> lock(g_distributedExtensionValidLock);
    g_distributedExtensionCount -= 1;
    HILOG_INFO("DistributedExtensionJs::~DistributedExtensionJs, count=%{public}d.", g_distributedExtensionCount);
}

void DistributedExtensionJs::ExportJsContext(void)
{
    auto env = jsRuntime_.GetNapiEnv();
    if (jsObj_ == nullptr) {
        HILOG_ERROR("Failed to get js object.");
        return;
    }
    napi_value obj = jsObj_->GetNapiValue();
    if (obj == nullptr) {
        HILOG_ERROR("Failed to get DistributedExtensionAbility object");
        return;
    }

    auto context = GetContext();
    if (context == nullptr) {
        HILOG_ERROR("Failed to get context");
        return;
    }

    HILOG_INFO("CreateDistributedExtensionContextJS");
    napi_value contextObj = CreateDistributedExtensionContextJS(env, context);
    auto contextRef = jsRuntime_.LoadSystemModule("application.DistributedExtensionContext", &contextObj, ARGC_ONE);
    if (!contextRef) {
        HILOG_ERROR("context is nullptr");
        return;
    }
    contextObj = contextRef->GetNapiValue();
    HILOG_INFO("Bind context");
    context->Bind(jsRuntime_, contextRef.release());
    napi_set_named_property(env, obj, "context", contextObj);

    auto workContext = new (std::nothrow) std::weak_ptr<DistributedExtensionContext>(context);
    if (workContext == nullptr) {
        HILOG_ERROR("Failed to create DistributedExtensionContext.");
        return;
    }
    napi_coerce_to_native_binding_object(env, contextObj, AbilityRuntime::DetachCallbackFunc,
                                         AttachDistributedExtensionContext, workContext, nullptr);
    HILOG_INFO("Set backup extension ability context pointer is nullptr: %{public}d", context.get() == nullptr);
    napi_status status = napi_wrap(
        env, contextObj, workContext,
        [](napi_env, void *data, void *) {
            HILOG_INFO("Finalizer for weak_ptr base context is called");
            delete static_cast<std::weak_ptr<DistributedExtensionContext> *>(data);
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        HILOG_INFO("Failed to wrap js instance");
        delete workContext;
        workContext = nullptr;
    }
}

DistributedExtensionJs *DistributedExtensionJs::Create(const unique_ptr<AbilityRuntime::Runtime> &runtime)
{
    HILOG_INFO("Create as an DistributedExtensionAbility(JS)");
    return new DistributedExtensionJs(static_cast<AbilityRuntime::JsRuntime &>(*runtime));
}

int32_t DistributedExtensionJs::TriggerOnCreate(AAFwk::Want& want)
{
    HILOG_INFO("DistributedExtensionAbility(JS) TriggerOnCreate ex");
    want_ = want;
    if (jsObj_ == nullptr) {
        HILOG_ERROR("The app does not provide the TriggerOnCreate interface.");
    }

    return CallJsOnCreate();
}

int32_t DistributedExtensionJs::CallJsOnCreate()
{
    HILOG_INFO("Start call app js method onCreate");
    auto errCode = CallJsMethod("onCreate", jsRuntime_, jsObj_.get(), ParseCreateInfo(), nullptr);
    if (errCode != ERR_OK) {
        HILOG_ERROR("CallJsMethod error, code:%{public}d.", errCode);
    }
    return errCode;
}

std::function<bool(napi_env env, std::vector<napi_value> &argv)> DistributedExtensionJs::ParseCreateInfo()
{
    auto onCreateFun = [want(want_)](napi_env env, vector<napi_value> &argv) -> bool {
        napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
        argv.push_back(napiWant);
        return true;
    };
    return onCreateFun;
}

int32_t DistributedExtensionJs::TriggerOnDestroy()
{
    HILOG_INFO("DistributedExtensionAbility(JS) TriggerOnDestroy ex");
    if (jsObj_ == nullptr) {
        HILOG_ERROR("The app does not provide the TriggerOnDestroy interface.");
    }

    return CallJsOnDestroy();
}

int32_t DistributedExtensionJs::CallJsOnDestroy()
{
    HILOG_INFO("Start call app js method onDestroy");
    auto errCode = CallJsMethod("onDestroy", jsRuntime_, jsObj_.get(), nullptr, nullptr);
    if (errCode != ERR_OK) {
        HILOG_ERROR("CallJsMethod error, code:%{public}d.", errCode);
    }
    return errCode;
}

int32_t DistributedExtensionJs::TriggerOnCollaborate(AAFwk::WantParams &wantParam)
{
    HILOG_INFO("jDistributedExtensionAbility(JS) TriggerOnCollaborate ex");
    wantParam_ = wantParam;
    if (jsObj_ == nullptr) {
        HILOG_ERROR("The app does not provide the TriggerOnCollaborate interface.");
    }

    return CallJsOnCollaborate();
}

int32_t DistributedExtensionJs::CallJsOnCollaborate()
{
    HILOG_INFO("Start call app js method OnCollaborate");
    auto retParser = [jsRuntime{ &jsRuntime_ }](napi_env env,
        napi_value result) -> bool {
        uint32_t value;
        if (napi_get_value_uint32(env, result, &value) != napi_ok) {
            HILOG_ERROR("Can not get uint32 value");
            return false;
        }

        HILOG_INFO("CallJsOnCollaborate result = %{public}d.", value);
        return true;
    };
    auto errCode = CallJsMethod("onCollaborate", jsRuntime_, jsObj_.get(), ParseCollabInfo(), retParser);
    if (errCode != ERR_OK) {
        HILOG_ERROR("CallJsMethod error, code:%{public}d.", errCode);
    }
    return errCode;
}

std::function<bool(napi_env env, std::vector<napi_value> &argv)> DistributedExtensionJs::ParseCollabInfo()
{
    auto onCollabFun = [wantParam(wantParam_)](napi_env env, vector<napi_value> &argv) -> bool {
        napi_value napiWantParam = AppExecFwk::WrapWantParams(env, wantParam);
        argv.push_back(napiWantParam);
        return true;
    };
    return onCollabFun;
}

static int InvokeJsMethod(CallJsParam *param, AbilityRuntime::HandleEscape& handleEscape, napi_env env,
    napi_handle_scope& scope, vector<napi_value>& argv)
{
    HILOG_INFO("InvokeJsMethod start");
    if (param == nullptr || param->jsObj == nullptr) {
        HILOG_ERROR("param or jsObj is nullptr");
        return EINVAL;
    }
    napi_value value = param->jsObj->GetNapiValue();
    if (value == nullptr) {
        HILOG_ERROR("failed to get napi value object.");
        return EINVAL;
    }
    napi_status status;
    napi_value method;
    status = napi_get_named_property(env, value, param->funcName.c_str(), &method);
    if (status != napi_ok) {
        HILOG_ERROR("napi_get_named_property failed.");
        return EINVAL;
    }
    napi_value result;
    HILOG_INFO("Extension start do call current js method, methodName:%{public}s", param->funcName.c_str());
    if (napi_call_function(env, value, method, argv.size(), argv.data(), &result) != napi_ok) {
        HILOG_ERROR("napi call function failed");
    }
    if (param->retParser != nullptr) {
        if (!param->retParser(env, handleEscape.Escape(result))) {
            HILOG_ERROR("Parser js result fail.");
            return EINVAL;
        }
    }
    HILOG_INFO("InvokeJsMethod end");
    return ERR_OK;
}

static int DoCallJsMethod(CallJsParam *param)
{
    HILOG_INFO("DoCallJsMethod enter");
    if (param == nullptr) {
        HILOG_ERROR("param is nullptr");
        return EINVAL;
    }
    AbilityRuntime::JsRuntime *jsRuntime = param->jsRuntime;
    HILOG_INFO("Start execute DoCallJsMethod");
    if (jsRuntime == nullptr) {
        HILOG_ERROR("failed to get jsRuntime");
        return EINVAL;
    }
    AbilityRuntime::HandleEscape handleEscape(*jsRuntime);
    auto env = jsRuntime->GetNapiEnv();
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    if (scope == nullptr) {
        HILOG_ERROR("scope is nullptr");
        return EINVAL;
    }
    vector<napi_value> argv = {};
    if (param->argParser != nullptr) {
        if (!param->argParser(env, argv)) {
            HILOG_ERROR("failed to get params.");
            napi_close_handle_scope(env, scope);
            return EINVAL;
        }
    }
    auto ret = InvokeJsMethod(param, handleEscape, env, scope, argv);
    napi_close_handle_scope(env, scope);
    HILOG_INFO("End execute DoCallJsMethod");
    return ret;
}

int32_t DistributedExtensionJs::CallJsMethod(const std::string &funcName, AbilityRuntime::JsRuntime &jsRuntime,
    NativeReference *jsObj, InputArgsParser argParser, ResultValueParser retParser)
{
    HILOG_INFO("DistributedExtensionJs::CallJsMethod enter");
    uv_loop_s *loop = nullptr;
    napi_status status = napi_get_uv_event_loop(jsRuntime.GetNapiEnv(), &loop);
    if (status != napi_ok) {
        HILOG_ERROR("failed to get uv event loop.");
        return EINVAL;
    }
    auto param = std::make_shared<CallJsParam>(funcName, &jsRuntime, jsObj, argParser, retParser);
    if (param == nullptr) {
        HILOG_ERROR("failed to new param.");
        return EINVAL;
    }

    auto work = std::make_shared<uv_work_t>();
    if (work == nullptr) {
        HILOG_ERROR("failed to new uv_work_t.");
        return EINVAL;
    }

    work->data = reinterpret_cast<void *>(param.get());
    int ret = uv_queue_work(
        loop, work.get(), [](uv_work_t *work) {
            HILOG_INFO("Enter, %{public}zu", (size_t)work);
        },
        [](uv_work_t *work, int status) {
            HILOG_INFO("AsyncWork Enter, %{public}zu", (size_t)work);
            CallJsParam *param = reinterpret_cast<CallJsParam *>(work->data);
            do {
                if (param == nullptr) {
                    HILOG_ERROR("failed to get CallJsParam.");
                    break;
                }
                HILOG_INFO("Start call current js method");
                if (DoCallJsMethod(param) != ERR_OK) {
                    HILOG_ERROR("failed to call DoCallJsMethod.");
                }
            } while (false);
            HILOG_INFO("will notify current thread info");
            std::unique_lock<std::mutex> lock(param->distributedOperateMutex);
            param->isReady.store(true);
            param->distributedOperateCondition.notify_all();
        });
    if (ret != 0) {
        HILOG_ERROR("failed to exec uv_queue_work.");
        return EINVAL;
    }
    std::unique_lock<std::mutex> lock(param->distributedOperateMutex);
    param->distributedOperateCondition.wait(lock, [param]() { return param->isReady.load(); });
    HILOG_INFO("End do call current js method");
    return ERR_OK;
}
}
}

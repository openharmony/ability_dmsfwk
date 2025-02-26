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

#ifndef OHOS_APPMGMT_DISTRIBUTED_EXTENSION_JS_H
#define OHOS_APPMGMT_DISTRIBUTED_EXTENSION_JS_H

#include <vector>

#include "distributed_extension.h"
#include "js_runtime.h"
#include "native_reference.h"
#include "native_value.h"

namespace OHOS {
namespace DistributedSchedule {
using InputArgsParser = std::function<bool(napi_env, std::vector<napi_value> &)>;
using ResultValueParser = std::function<bool(napi_env, napi_value)>;

struct CallJsParam {
    std::mutex distributedOperateMutex;
    std::condition_variable distributedOperateCondition;
    std::atomic<bool> isReady {false};
    std::string funcName;
    AbilityRuntime::JsRuntime *jsRuntime;
    NativeReference *jsObj;
    InputArgsParser argParser;
    ResultValueParser retParser;

    CallJsParam(const std::string &funcNameIn,
                AbilityRuntime::JsRuntime *jsRuntimeIn,
                NativeReference *jsObjIn,
                InputArgsParser &argParserIn,
                ResultValueParser &retParserIn)
        : funcName(funcNameIn), jsRuntime(jsRuntimeIn), jsObj(jsObjIn), argParser(argParserIn), retParser(retParserIn)
    {
    }
};

class DistributedExtensionJs : public DistributedExtension {
public:
    void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
              const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
              std::shared_ptr<AppExecFwk::AbilityHandler> &handler,
              const sptr<IRemoteObject> &token) override;

public:
    static DistributedExtensionJs *Create(const std::unique_ptr<AbilityRuntime::Runtime> &runtime);

    virtual int32_t TriggerOnCreate(AAFwk::Want& want) override;
    virtual int32_t TriggerOnDestroy() override;
    virtual int32_t TriggerOnCollaborate(AAFwk::WantParams &wantParam) override;

public:
    explicit DistributedExtensionJs(AbilityRuntime::JsRuntime &jsRuntime);
    ~DistributedExtensionJs();
private:
    int32_t CallJsMethod(const std::string &funcName,
                     AbilityRuntime::JsRuntime &jsRuntime,
                     NativeReference *jsObj,
                     InputArgsParser argParser,
                     ResultValueParser retParser);
    int32_t CallJsOnCreate();
    std::function<bool(napi_env env, std::vector<napi_value> &argv)> ParseCreateInfo();
    int32_t CallJsOnDestroy();
    int32_t CallJsOnCollaborate();
    std::function<bool(napi_env env, std::vector<napi_value> &argv)> ParseCollabInfo();

    void ExportJsContext(void);

    AbilityRuntime::JsRuntime &jsRuntime_;
    std::unique_ptr<NativeReference> jsObj_;

    OHOS::AAFwk::Want want_;
    AAFwk::WantParams wantParam_;
};
}
}

#endif // OHOS_APPMGMT_DISTRIBUTED_EXTENSION_JS_H

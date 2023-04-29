/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_ABILITY_BASE_DISTRIBUTED_WANT_PARAMS_WRAPPER_H
#define OHOS_ABILITY_BASE_DISTRIBUTED_WANT_PARAMS_WRAPPER_H
#include "base_def.h"
#include "base_object.h"
#include "distributed_want_params.h"
namespace OHOS {
namespace AAFwk {
class DistributedWantParams;
INTERFACE(IDistributedWantParams, a75b9db6 - 9813 - 4371 - 8848 - d2966ce6ec68)
{
    inline static IDistributedWantParams* Query(IInterface* object)
    {
        if (object == nullptr) {
            return nullptr;
        }
        return static_cast<IDistributedWantParams*>(object->Query(g_IID_IDistributedWantParams));
    }

    virtual ErrCode GetValue(DistributedWantParams& value) = 0;
};
class DistributedWantParamWrapper final : public Object, public IDistributedWantParams {
public:
    inline DistributedWantParamWrapper(const DistributedWantParams& value) : wantParams_(value)
    {}
    /**
     * @brief Constructor for move semantics
     */
    inline DistributedWantParamWrapper(DistributedWantParams&& value) : wantParams_(std::move(value))
    {}

    inline ~DistributedWantParamWrapper()
    {}

    IINTERFACE_DECL();

    ErrCode GetValue(DistributedWantParams& value) override;

    bool Equals(IObject& other) override;

    std::string ToString() override;

    static sptr<IDistributedWantParams> Box(const DistributedWantParams& value);
    /**
     * @brief Wrap a wantParam into a DistributedWantParamWrapper using move semantics and return the wrapper.
     *
     * @param value
     * @return sptr<IDistributedWantParams>
     */
    static sptr<IDistributedWantParams> Box(DistributedWantParams&& value);

    static DistributedWantParams Unbox(IDistributedWantParams* object);

    static bool ValidateStr(const std::string& str);

    static sptr<IDistributedWantParams> Parse(const std::string& str);

    static DistributedWantParams ParseWantParams(const std::string& str);

    static constexpr char SIGNATURE = 'W';

private:
    DistributedWantParams wantParams_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_BASE_DISTRIBUTED_WANT_PARAMS_WRAPPER_H
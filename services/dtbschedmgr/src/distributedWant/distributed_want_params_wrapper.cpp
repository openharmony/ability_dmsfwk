/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "distributed_want_params_wrapper.h"

#include <algorithm>

using namespace OHOS::AAFwk;
namespace OHOS {
namespace DistributedSchedule {
constexpr int32_t DISTRIBUTEDWANT_PARAM_WRAPPER_TWO = 2;

IINTERFACE_IMPL_1(DistributedWantParamWrapper, Object, IDistributedWantParams);
const InterfaceID g_IID_IDistributedWantParams = {
    0xa75b9db6, 0x9813, 0x4371, 0x8848, {0xd, 0x2, 0x9, 0x6, 0x6, 0xc, 0xe, 0x6, 0xe, 0xc, 0x6, 0x8}
};
ErrCode DistributedWantParamWrapper::GetValue(DistributedWantParams& value)
{
    value = wantParams_;
    return ERR_OK;
}

bool DistributedWantParamWrapper::Equals(IObject& other)
{
    DistributedWantParamWrapper* otherObj =
        static_cast<DistributedWantParamWrapper*>(IDistributedWantParams::Query(&other));
    return otherObj != nullptr && otherObj->wantParams_ == wantParams_;
}

std::string DistributedWantParamWrapper::ToString()
{
    std::string result;
    if (wantParams_.Size() != 0) {
        result += "{";
        for (auto it : wantParams_.GetParams()) {
            int dTypeId = DistributedWantParams::GetDataType(it.second);
            result = result + "\"" + it.first + "\":{\"" + std::to_string(dTypeId) + "\":";
            if (IDistributedWantParams::Query(it.second) != nullptr) {
                result = result +
                    static_cast<DistributedWantParamWrapper*>(IDistributedWantParams::Query(it.second))->ToString();
            } else {
                result = result + "\"" + DistributedWantParams::GetStringByType(it.second, dTypeId) + "\"";
            }
            if (it == *wantParams_.GetParams().rbegin()) {
                result += "}";
            } else {
                result += "},";
            }
        }
        result += "}";
    } else {
        result = "{}";
    }
    return result;
}

sptr<IDistributedWantParams> DistributedWantParamWrapper::Box(const DistributedWantParams& value)
{
    sptr<IDistributedWantParams> object = new (std::nothrow)DistributedWantParamWrapper(value);
    return object;
}

sptr<IDistributedWantParams> DistributedWantParamWrapper::Box(DistributedWantParams&& value)
{
    sptr<IDistributedWantParams> object = new (std::nothrow) DistributedWantParamWrapper(std::move(value));
    return object;
}

DistributedWantParams DistributedWantParamWrapper::Unbox(IDistributedWantParams* object)
{
    DistributedWantParams value;
    if (object != nullptr) {
        object->GetValue(value);
    }
    return value;
}
bool DistributedWantParamWrapper::ValidateStr(const std::string& str)
{
    if (str == "" || str == "{}" || str == "{\"\"}") {
        return false;
    }
    if (count(str.begin(), str.end(), '\"') % DISTRIBUTEDWANT_PARAM_WRAPPER_TWO != 0) {
        return false;
    }
    if (count(str.begin(), str.end(), '{') != count(str.begin(), str.end(), '}')) {
        return false;
    }
    int counter = 0;
    for (auto it : str) {
        if (it == '{') {
            counter++;
        }
        if (it == '}') {
            counter--;
        }
        if (counter < 0) {
            return false;
        }
    }
    return true;
}

sptr<IDistributedWantParams> DistributedWantParamWrapper::Parse(const std::string& str)
{
    DistributedWantParams wantParams;
    if (ValidateStr(str)) {
        std::string strKey = "";
        int typeId = 0;
        for (size_t strnum = 0; strnum < str.size(); strnum++) {
            if (str[strnum] == '{' && strKey != "" && typeId == DistributedWantParams::VALUE_TYPE_WANTPARAMS) {
                size_t num;
                int count = 0;
                for (num = strnum; num < str.size(); num++) {
                    if (str[num] == '{') {
                        count++;
                    } else if (str[num] == '}') {
                        count--;
                    }
                    if (count == 0) {
                        break;
                    }
                }
                wantParams.SetParam(strKey, DistributedWantParamWrapper::Parse(str.substr(strnum, num - strnum + 1)));
                strKey = "";
                typeId = 0;
                strnum = num + 1;
            } else if (str[strnum] == '"') {
                if (strKey == "") {
                    strnum++;
                    strKey = str.substr(strnum, str.find('"', strnum) - strnum);
                    strnum = str.find('"', strnum);
                } else if (typeId == 0) {
                    strnum++;
                    typeId = atoi(str.substr(strnum, str.find('"', strnum) - strnum).c_str());
                    if (errno == ERANGE) {
                        return nullptr;
                    }
                    strnum = str.find('"', strnum);
                } else {
                    strnum++;
                    wantParams.SetParam(strKey,
                        DistributedWantParams::GetInterfaceByType(typeId,
                            str.substr(strnum, str.find('"', strnum) - strnum)));
                    strnum = str.find('"', strnum);
                    typeId = 0;
                    strKey = "";
                }
            }
        }
    }
    sptr<IDistributedWantParams> iwantParams = new (std::nothrow) DistributedWantParamWrapper(wantParams);
    return iwantParams;
}
DistributedWantParams DistributedWantParamWrapper::ParseWantParams(const std::string& str)
{
    DistributedWantParams wantParams;
    std::string key = "";
    int typeId = 0;
    if (!ValidateStr(str)) {
        return wantParams;
    }
    for (size_t strnum = 0; strnum < str.size(); strnum++) {
        if (str[strnum] == '{' && key != "" && typeId == DistributedWantParams::VALUE_TYPE_WANTPARAMS) {
            size_t num;
            int counter = 0;
            for (num = strnum; num < str.size(); num++) {
                if (str[num] == '{') {
                    counter++;
                } else if (str[num] == '}') {
                    counter--;
                }
                if (counter == 0) {
                    break;
                }
            }
            wantParams.SetParam(key, DistributedWantParamWrapper::Parse(str.substr(strnum, num - strnum)));
            key = "";
            typeId = 0;
            strnum = num + 1;
        } else if (str[strnum] == '"') {
            if (key == "") {
                strnum++;
                key = str.substr(strnum, str.find('"', strnum) - strnum);
                strnum = str.find('"', strnum);
            } else if (typeId == 0) {
                strnum++;
                typeId = atoi(str.substr(strnum, str.find('"', strnum) - strnum).c_str());
                if (errno == ERANGE) {
                    return wantParams;
                }
                strnum = str.find('"', strnum);
            } else {
                strnum++;
                wantParams.SetParam(key,
                    DistributedWantParams::GetInterfaceByType(typeId,
                        str.substr(strnum, str.find('"', strnum) - strnum)));
                strnum = str.find('"', strnum);
                typeId = 0;
                key = "";
            }
        }
    }
    return wantParams;
}
} // namespace DistributedSchedule
} // namespace OHOS
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

#include "distributed_want.h"

#include <algorithm>
#include <climits>
#include <cstdlib>
#include <regex>
#include <securec.h>

#include "array_wrapper.h"
#include "base_obj.h"
#include "bool_wrapper.h"
#include "byte_wrapper.h"
#include "double_wrapper.h"
#include "float_wrapper.h"
#include "int_wrapper.h"
#include "long_wrapper.h"
#include "parcel_macro_base.h"
#include "remote_object_wrapper.h"
#include "short_wrapper.h"
#include "string_ex.h"
#include "string_wrapper.h"
#include "zchar_wrapper.h"

#include "distributed_operation_builder.h"
#include "distributed_want_params_wrapper.h"
#include "dtbschedmgr_log.h"

using namespace OHOS::AppExecFwk;
using OHOS::AppExecFwk::ElementName;
namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::regex NUMBER_REGEX("^[-+]?([0-9]+)([.]([0-9]+))?$");
const std::string TAG = "DistributedWant";
const char* TYPE_PROPERTY = "type";
};  // namespace
const std::string DistributedWant::ACTION_PLAY("action.system.play");
const std::string DistributedWant::ACTION_HOME("action.system.home");

const std::string DistributedWant::ENTITY_HOME("entity.system.home");
const std::string DistributedWant::ENTITY_VIDEO("entity.system.video");
const std::string DistributedWant::FLAG_HOME_INTENT_FROM_SYSTEM("flag.home.intent.from.system");
const std::string DistributedWant::ENTITY_MUSIC("entity.app.music");
const std::string DistributedWant::ENTITY_EMAIL("entity.app.email");
const std::string DistributedWant::ENTITY_CONTACTS("entity.app.contacts");
const std::string DistributedWant::ENTITY_MAPS("entity.app.maps");
const std::string DistributedWant::ENTITY_BROWSER("entity.app.browser");
const std::string DistributedWant::ENTITY_CALENDAR("entity.app.calendar");
const std::string DistributedWant::ENTITY_MESSAGING("entity.app.messaging");
const std::string DistributedWant::ENTITY_FILES("entity.app.files");
const std::string DistributedWant::ENTITY_GALLERY("entity.app.gallery");

const std::string DistributedWant::OCT_EQUALSTO("075");   // '='
const std::string DistributedWant::OCT_SEMICOLON("073");  // ';'
const std::string DistributedWant::MIME_TYPE("mime-type");
const std::string DistributedWant::WANT_HEADER("#Intent;");

const std::string DistributedWant::PARAM_RESV_WINDOW_MODE("ohos.aafwk.param.windowMode");
const std::string DistributedWant::PARAM_RESV_DISPLAY_ID("ohos.aafwk.param.displayId");
const std::string DistributedWant::PARAM_RESV_CALLER_TOKEN("ohos.aafwk.param.callerToken");
const std::string DistributedWant::PARAM_RESV_CALLER_UID("ohos.aafwk.param.callerUid");
const std::string DistributedWant::PARAM_RESV_CALLER_PID("ohos.aafwk.param.callerPid");

DistributedWant::DistributedWant()
{}

DistributedWant::~DistributedWant()
{}

DistributedWant::DistributedWant(const DistributedWant& other)
{
    operation_ = other.operation_;
    parameters_ = other.parameters_;
}

DistributedWant& DistributedWant::operator=(const DistributedWant& other)
{
    operation_ = other.operation_;
    parameters_ = other.parameters_;
    return *this;
}

DistributedWant::DistributedWant(const AAFwk::Want& want)
{
    DistributedOperationBuilder builder;
    builder.WithAbilityName(want.GetElement().GetAbilityName());
    builder.WithBundleName(want.GetElement().GetBundleName());
    builder.WithDeviceId(want.GetElement().GetDeviceID());
    builder.WithAction(want.GetAction());
    builder.WithEntities(want.GetEntities());
    builder.WithFlags(want.GetFlags());
    builder.WithUri(want.GetUri());
    std::shared_ptr<DistributedOperation> op = builder.build();
    operation_ = *op;
    std::map<std::string, sptr<AAFwk::IInterface>> data = want.GetParams().GetParams();
    for (auto it = data.begin(); it != data.end(); it++) {
        auto tp = AAFwk::WantParams::GetDataType(it->second);
        if ((tp == DistributedWantParams::VALUE_TYPE_BOOLEAN) ||
            (tp == DistributedWantParams::VALUE_TYPE_BYTE) ||
            (tp == DistributedWantParams::VALUE_TYPE_CHAR) ||
            (tp == DistributedWantParams::VALUE_TYPE_SHORT) ||
            (tp == DistributedWantParams::VALUE_TYPE_INT) ||
            (tp == DistributedWantParams::VALUE_TYPE_LONG) ||
            (tp == DistributedWantParams::VALUE_TYPE_FLOAT) ||
            (tp == DistributedWantParams::VALUE_TYPE_DOUBLE) ||
            (tp == DistributedWantParams::VALUE_TYPE_STRING) ||
            (tp == DistributedWantParams::VALUE_TYPE_ARRAY) ||
            (tp == DistributedWantParams::VALUE_TYPE_REMOTE_OBJECT) ||
            (tp == DistributedWantParams::VALUE_TYPE_WANTPARAMS)) {
            parameters_.SetParam(it->first, it->second);
        }
    }
}

std::shared_ptr<AAFwk::Want> DistributedWant::ToWant()
{
    auto want = std::make_shared<AAFwk::Want>();
    want->SetFlags(GetFlags());
    want->SetElement(GetElement());
    want->SetUri(GetUri());
    want->SetAction(GetAction());
    want->SetBundle(GetBundle());
    want->SetType(GetType());
    std::vector<std::string> ents = GetEntities();
    for (auto it = ents.begin(); it != ents.end(); it++) {
        want->AddEntity(*it);
    }
    want->SetParams(parameters_.ToWantParams());
    return want;
}

unsigned int DistributedWant::GetFlags() const
{
    return operation_.GetFlags();
}

DistributedWant& DistributedWant::SetFlags(unsigned int flags)
{
    operation_.SetFlags(flags);
    return *this;
}

DistributedWant& DistributedWant::AddFlags(unsigned int flags)
{
    operation_.AddFlags(flags);
    return *this;
}

void DistributedWant::RemoveFlags(unsigned int flags)
{
    operation_.RemoveFlags(flags);
}

OHOS::AppExecFwk::ElementName DistributedWant::GetElement() const
{
    return ElementName(operation_.GetDeviceId(), operation_.GetBundleName(), operation_.GetAbilityName());
}

DistributedWant& DistributedWant::SetElementName(const std::string& bundleName, const std::string& abilityName)
{
    operation_.SetBundleName(bundleName);
    operation_.SetAbilityName(abilityName);
    return *this;
}

DistributedWant& DistributedWant::SetElementName(const std::string& deviceId, const std::string& bundleName,
                                                 const std::string& abilityName)
{
    operation_.SetDeviceId(deviceId);
    operation_.SetBundleName(bundleName);
    operation_.SetAbilityName(abilityName);
    return *this;
}

DistributedWant& DistributedWant::SetElement(const OHOS::AppExecFwk::ElementName& element)
{
    operation_.SetDeviceId(element.GetDeviceID());
    operation_.SetBundleName(element.GetBundleName());
    operation_.SetAbilityName(element.GetAbilityName());
    return *this;
}

const std::vector<std::string>& DistributedWant::GetEntities() const
{
    return operation_.GetEntities();
}

DistributedWant& DistributedWant::AddEntity(const std::string& entity)
{
    operation_.AddEntity(entity);
    return *this;
}

void DistributedWant::RemoveEntity(const std::string& entity)
{
    operation_.RemoveEntity(entity);
}

bool DistributedWant::HasEntity(const std::string& entity) const
{
    return operation_.HasEntity(entity);
}

int DistributedWant::CountEntities()
{
    return operation_.CountEntities();
}

std::string DistributedWant::GetBundle() const
{
    return operation_.GetBundleName();
}

DistributedWant& DistributedWant::SetBundle(const std::string& bundleName)
{
    operation_.SetBundleName(bundleName);
    return *this;
}

std::string DistributedWant::GetType() const
{
    auto value = parameters_.GetParam(MIME_TYPE);
    AAFwk::IString* ao = AAFwk::IString::Query(value);
    if (ao != nullptr) {
        return AAFwk::String::Unbox(ao);
    }
    return std::string();
}

DistributedWant& DistributedWant::SetType(const std::string& type)
{
    sptr<AAFwk::IString> valueObj = AAFwk::String::Parse(type);
    parameters_.SetParam(MIME_TYPE, valueObj);
    return *this;
}

Uri DistributedWant::GetLowerCaseScheme(const Uri& uri)
{
    std::string dStrUri = const_cast<Uri&>(uri).ToString();
    std::string schemeStr = const_cast<Uri&>(uri).GetScheme();
    if (dStrUri.empty() || schemeStr.empty()) {
        return uri;
    }

    std::string lowSchemeStr = schemeStr;
    std::transform(lowSchemeStr.begin(), lowSchemeStr.end(), lowSchemeStr.begin(), [](unsigned char c) {
        return std::tolower(c);
    });

    if (schemeStr == lowSchemeStr) {
        return uri;
    }

    std::size_t pos = dStrUri.find_first_of(schemeStr, 0);
    if (pos != std::string::npos) {
        dStrUri.replace(pos, schemeStr.length(), lowSchemeStr);
    }

    return Uri(dStrUri);
}

std::string DistributedWant::GetAction() const
{
    return operation_.GetAction();
}

DistributedWant& DistributedWant::SetAction(const std::string& action)
{
    operation_.SetAction(action);
    return *this;
}

const std::string DistributedWant::GetScheme() const
{
    return operation_.GetUri().GetScheme();
}

const DistributedWantParams& DistributedWant::GetParams() const
{
    return parameters_;
}

DistributedWant& DistributedWant::SetParams(const DistributedWantParams& wantParams)
{
    parameters_ = wantParams;
    return *this;
}

bool DistributedWant::GetBoolParam(const std::string& key, bool defaultValue) const
{
    auto value = parameters_.GetParam(key);
    AAFwk::IBoolean* bo = AAFwk::IBoolean::Query(value);
    if (bo != nullptr) {
        return AAFwk::Boolean::Unbox(bo);
    }
    return defaultValue;
}

std::vector<bool> DistributedWant::GetBoolArrayParam(const std::string& key) const
{
    std::vector<bool> array;
    auto value = parameters_.GetParam(key);
    AAFwk::IArray* ao = AAFwk::IArray::Query(value);
    if (ao != nullptr && AAFwk::Array::IsBooleanArray(ao)) {
        auto func = [&](AAFwk::IInterface* object) {
            if (object != nullptr) {
                AAFwk::IBoolean* value = AAFwk::IBoolean::Query(object);
                if (value != nullptr) {
                    array.push_back(AAFwk::Boolean::Unbox(value));
                }
            }
        };
        AAFwk::Array::ForEach(ao, func);
    }
    return array;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, const sptr<IRemoteObject>& remoteObject)
{
    DistributedWantParams wp;
    wp.SetParam(TYPE_PROPERTY, AAFwk::String::Box(AAFwk::REMOTE_OBJECT));
    wp.SetParam(AAFwk::VALUE_PROPERTY, AAFwk::RemoteObjectWrap::Box(remoteObject));
    parameters_.SetParam(key, DistributedWantParamWrapper::Box(wp));
    return *this;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, bool value)
{
    parameters_.SetParam(key, AAFwk::Boolean::Box(value));
    return *this;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, const std::vector<bool>& value)
{
    std::size_t size = value.size();
    sptr<AAFwk::IArray> ao(new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IBoolean));
    if (ao != nullptr) {
        for (std::size_t i = 0; i < size; i++) {
            ao->Set(i, AAFwk::Boolean::Box(value[i]));
        }
        parameters_.SetParam(key, ao);
    }
    return *this;
}

AAFwk::byte DistributedWant::GetByteParam(const std::string& key, const AAFwk::byte defaultValue) const
{
    auto value = parameters_.GetParam(key);
    AAFwk::IByte* bo = AAFwk::IByte::Query(value);
    if (bo != nullptr) {
        return AAFwk::Byte::Unbox(bo);
    }
    return defaultValue;
}

std::vector<AAFwk::byte> DistributedWant::GetByteArrayParam(const std::string& key) const
{
    std::vector<AAFwk::byte> array;
    auto value = parameters_.GetParam(key);
    AAFwk::IArray* ao = AAFwk::IArray::Query(value);
    if (ao != nullptr && AAFwk::Array::IsByteArray(ao)) {
        auto func = [&](AAFwk::IInterface* object) {
            if (object != nullptr) {
                AAFwk::IByte* value = AAFwk::IByte::Query(object);
                if (value != nullptr) {
                    array.push_back(AAFwk::Byte::Unbox(value));
                }
            }
        };
        AAFwk::Array::ForEach(ao, func);
    }
    return array;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, AAFwk::byte value)
{
    parameters_.SetParam(key, AAFwk::Byte::Box(value));
    return *this;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, const std::vector<AAFwk::byte>& value)
{
    std::size_t size = value.size();
    sptr<AAFwk::IArray> ao(new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IByte));
    if (ao == nullptr) {
        return *this;
    }
    for (std::size_t i = 0; i < size; i++) {
        ao->Set(i, AAFwk::Byte::Box(value[i]));
    }
    parameters_.SetParam(key, ao);
    return *this;
}

AAFwk::zchar DistributedWant::GetCharParam(const std::string& key, AAFwk::zchar defaultValue) const
{
    auto value = parameters_.GetParam(key);
    AAFwk::IChar* ao = AAFwk::IChar::Query(value);
    if (ao != nullptr) {
        return AAFwk::Char::Unbox(ao);
    }
    return defaultValue;
}

std::vector<AAFwk::zchar> DistributedWant::GetCharArrayParam(const std::string& key) const
{
    std::vector<AAFwk::zchar> array;
    auto value = parameters_.GetParam(key);
    AAFwk::IArray* ao = AAFwk::IArray::Query(value);
    if (ao != nullptr && AAFwk::Array::IsCharArray(ao)) {
        auto func = [&](AAFwk::IInterface* object) {
            if (object != nullptr) {
                AAFwk::IChar* value = AAFwk::IChar::Query(object);
                if (value != nullptr) {
                    array.push_back(AAFwk::Char::Unbox(value));
                }
            }
        };
        AAFwk::Array::ForEach(ao, func);
    }
    return array;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, AAFwk::zchar value)
{
    parameters_.SetParam(key, AAFwk::Char::Box(value));
    return *this;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, const std::vector<AAFwk::zchar>& value)
{
    std::size_t size = value.size();
    sptr<AAFwk::IArray> ao(new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IChar));
    if (ao == nullptr) {
        return *this;
    }
    for (std::size_t i = 0; i < size; i++) {
        ao->Set(i, AAFwk::Char::Box(value[i]));
    }
    parameters_.SetParam(key, ao);
    return *this;
}

int DistributedWant::GetIntParam(const std::string& key, const int defaultValue) const
{
    auto value = parameters_.GetParam(key);
    AAFwk::IInteger* ao = AAFwk::IInteger::Query(value);
    if (ao != nullptr) {
        return AAFwk::Integer::Unbox(ao);
    }
    return defaultValue;
}

std::vector<int> DistributedWant::GetIntArrayParam(const std::string& key) const
{
    std::vector<int> array;
    auto value = parameters_.GetParam(key);
    AAFwk::IArray* ao = AAFwk::IArray::Query(value);
    if (ao != nullptr && AAFwk::Array::IsIntegerArray(ao)) {
        auto func = [&](AAFwk::IInterface* object) {
            if (object != nullptr) {
                AAFwk::IInteger* value = AAFwk::IInteger::Query(object);
                if (value != nullptr) {
                    array.push_back(AAFwk::Integer::Unbox(value));
                }
            }
        };
        AAFwk::Array::ForEach(ao, func);
    }
    return array;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, int value)
{
    parameters_.SetParam(key, AAFwk::Integer::Box(value));
    return *this;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, const std::vector<int>& value)
{
    std::size_t size = value.size();
    sptr<AAFwk::IArray> ao(new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IInteger));
    if (ao == nullptr) {
        return *this;
    }
    for (std::size_t i = 0; i < size; i++) {
        ao->Set(i, AAFwk::Integer::Box(value[i]));
    }
    parameters_.SetParam(key, ao);
    return *this;
}

double DistributedWant::GetDoubleParam(const std::string& key, double defaultValue) const
{
    auto value = parameters_.GetParam(key);
    AAFwk::IDouble* ao = AAFwk::IDouble::Query(value);
    if (ao != nullptr) {
        return AAFwk::Double::Unbox(ao);
    }
    return defaultValue;
}

std::vector<double> DistributedWant::GetDoubleArrayParam(const std::string& key) const
{
    std::vector<double> array;
    auto value = parameters_.GetParam(key);
    AAFwk::IArray* ao = AAFwk::IArray::Query(value);
    if (ao != nullptr && AAFwk::Array::IsDoubleArray(ao)) {
        auto func = [&](AAFwk::IInterface* object) {
            if (object != nullptr) {
                AAFwk::IDouble* value = AAFwk::IDouble::Query(object);
                if (value != nullptr) {
                    array.push_back(AAFwk::Double::Unbox(value));
                }
            }
        };
        AAFwk::Array::ForEach(ao, func);
    }
    return array;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, double value)
{
    parameters_.SetParam(key, AAFwk::Double::Box(value));
    return *this;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, const std::vector<double>& value)
{
    std::size_t size = value.size();
    sptr<AAFwk::IArray> ao(new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IDouble));
    if (ao == nullptr) {
        return *this;
    }
    for (std::size_t i = 0; i < size; i++) {
        ao->Set(i, AAFwk::Double::Box(value[i]));
    }
    parameters_.SetParam(key, ao);
    return *this;
}

float DistributedWant::GetFloatParam(const std::string& key, float defaultValue) const
{
    auto value = parameters_.GetParam(key);
    AAFwk::IFloat* ao = AAFwk::IFloat::Query(value);
    if (ao != nullptr) {
        return AAFwk::Float::Unbox(ao);
    }
    return defaultValue;
}

std::vector<float> DistributedWant::GetFloatArrayParam(const std::string& key) const
{
    std::vector<float> array;
    auto value = parameters_.GetParam(key);
    AAFwk::IArray* ao = AAFwk::IArray::Query(value);
    if (ao != nullptr && AAFwk::Array::IsFloatArray(ao)) {
        auto func = [&](AAFwk::IInterface* object) {
            if (object != nullptr) {
                AAFwk::IFloat* value = AAFwk::IFloat::Query(object);
                if (value != nullptr) {
                    array.push_back(AAFwk::Float::Unbox(value));
                }
            }
        };
        AAFwk::Array::ForEach(ao, func);
    }
    return array;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, float value)
{
    parameters_.SetParam(key, AAFwk::Float::Box(value));
    return *this;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, const std::vector<float>& value)
{
    std::size_t size = value.size();
    sptr<AAFwk::IArray> ao(new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IFloat));
    if (ao == nullptr) {
        return *this;
    }

    for (std::size_t i = 0; i < size; i++) {
        ao->Set(i, AAFwk::Float::Box(value[i]));
    }
    parameters_.SetParam(key, ao);
    return *this;
}

long DistributedWant::GetLongParam(const std::string& key, long defaultValue) const
{
    auto value = parameters_.GetParam(key);
    if (AAFwk::ILong::Query(value) != nullptr) {
        return AAFwk::Long::Unbox(AAFwk::ILong::Query(value));
    } else if (AAFwk::IString::Query(value) != nullptr) {
        // Marshalling
        std::string str = AAFwk::String::Unbox(AAFwk::IString::Query(value));
        if (std::regex_match(str, NUMBER_REGEX)) {
            return std::atoll(str.c_str());
        }
    }

    return defaultValue;
}

void ArrayAddData(AAFwk::IInterface* object, std::vector<long>& array)
{
    if (object == nullptr) {
        return;
    }

    AAFwk::IString* o = AAFwk::IString::Query(object);
    if (o != nullptr) {
        std::string str = AAFwk::String::Unbox(o);
        if (std::regex_match(str, NUMBER_REGEX)) {
            array.push_back(std::atoll(str.c_str()));
        }
    }
}

std::vector<long> DistributedWant::GetLongArrayParam(const std::string& key) const
{
    std::vector<long> array;
    auto value = parameters_.GetParam(key);
    AAFwk::IArray* ao = AAFwk::IArray::Query(value);
    if (ao != nullptr && AAFwk::Array::IsLongArray(ao)) {
        auto func = [&](AAFwk::IInterface* object) {
            if (object != nullptr) {
                AAFwk::ILong* value = AAFwk::ILong::Query(object);
                if (value != nullptr) {
                    array.push_back(AAFwk::Long::Unbox(value));
                }
            }
        };
        AAFwk::Array::ForEach(ao, func);
    } else if (ao != nullptr && AAFwk::Array::IsStringArray(ao)) {
        // Marshalling
        auto func = [&](AAFwk::IInterface* object) { ArrayAddData(object, array); };
        AAFwk::Array::ForEach(ao, func);
    }
    return array;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, long value)
{
    parameters_.SetParam(key, AAFwk::Long::Box(value));
    return *this;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, const std::vector<long>& value)
{
    std::size_t size = value.size();
    sptr<AAFwk::IArray> ao(new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_ILong));
    if (ao == nullptr) {
        return *this;
    }
    for (std::size_t i = 0; i < size; i++) {
        ao->Set(i, AAFwk::Long::Box(value[i]));
    }
    parameters_.SetParam(key, ao);
    return *this;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, long long value)
{
    parameters_.SetParam(key, AAFwk::Long::Box(value));
    return *this;
}

short DistributedWant::GetShortParam(const std::string& key, short defaultValue) const
{
    auto value = parameters_.GetParam(key);
    AAFwk::IShort* ao = AAFwk::IShort::Query(value);
    if (ao != nullptr) {
        return AAFwk::Short::Unbox(ao);
    }
    return defaultValue;
}

std::vector<short> DistributedWant::GetShortArrayParam(const std::string& key) const
{
    std::vector<short> array;
    auto value = parameters_.GetParam(key);
    AAFwk::IArray* ao = AAFwk::IArray::Query(value);
    if (ao != nullptr && AAFwk::Array::IsShortArray(ao)) {
        auto func = [&](AAFwk::IInterface* object) {
            if (object != nullptr) {
                AAFwk::IShort* value = AAFwk::IShort::Query(object);
                if (value != nullptr) {
                    array.push_back(AAFwk::Short::Unbox(value));
                }
            }
        };
        AAFwk::Array::ForEach(ao, func);
    }
    return array;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, short value)
{
    parameters_.SetParam(key, AAFwk::Short::Box(value));
    return *this;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, const std::vector<short>& value)
{
    std::size_t size = value.size();
    sptr<AAFwk::IArray> ao(new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IShort));
    if (ao == nullptr) {
        return *this;
    }
    for (std::size_t i = 0; i < size; i++) {
        ao->Set(i, AAFwk::Short::Box(value[i]));
    }
    parameters_.SetParam(key, ao);
    return *this;
}

std::string DistributedWant::GetStringParam(const std::string& key) const
{
    auto value = parameters_.GetParam(key);
    AAFwk::IString* ao = AAFwk::IString::Query(value);
    if (ao != nullptr) {
        return AAFwk::String::Unbox(ao);
    }
    return std::string();
}

std::vector<std::string> DistributedWant::GetStringArrayParam(const std::string& key) const
{
    std::vector<std::string> array;
    auto value = parameters_.GetParam(key);
    AAFwk::IArray* ao = AAFwk::IArray::Query(value);
    if (ao != nullptr && AAFwk::Array::IsStringArray(ao)) {
        auto func = [&](AAFwk::IInterface* object) {
            if (object != nullptr) {
                AAFwk::IString* value = AAFwk::IString::Query(object);
                if (value != nullptr) {
                    array.push_back(AAFwk::String::Unbox(value));
                }
            }
        };
        AAFwk::Array::ForEach(ao, func);
    }
    return array;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, const std::string& value)
{
    parameters_.SetParam(key, AAFwk::String::Box(value));
    return *this;
}

DistributedWant& DistributedWant::SetParam(const std::string& key, const std::vector<std::string>& value)
{
    std::size_t size = value.size();
    sptr<AAFwk::IArray> ao(new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IString));
    if (ao == nullptr) {
        return *this;
    }
    for (std::size_t i = 0; i < size; i++) {
        ao->Set(i, AAFwk::String::Box(value[i]));
    }
    parameters_.SetParam(key, ao);
    return *this;
}

DistributedOperation DistributedWant::GetOperation() const
{
    return operation_;
}

void DistributedWant::SetOperation(const DistributedOperation& operation)
{
    operation_ = operation;
}

bool DistributedWant::OperationEquals(const DistributedWant& want)
{
    return (operation_ == want.operation_);
}

std::string DistributedWant::GetUriString() const
{
    return operation_.GetUri().ToString();
}

OHOS::Uri DistributedWant::GetUri() const
{
    return operation_.GetUri();
}

DistributedWant& DistributedWant::SetUri(const std::string& uri)
{
    operation_.SetUri(OHOS::Uri(uri));
    return *this;
}

DistributedWant& DistributedWant::SetUri(const OHOS::Uri& uri)
{
    operation_.SetUri(uri);
    return *this;
}

DistributedWant& DistributedWant::SetUriAndType(const OHOS::Uri& uri, const std::string& type)
{
    operation_.SetUri(uri);
    return SetType(type);
}

DistributedWant& DistributedWant::FormatUri(const std::string& uri)
{
    return FormatUri(OHOS::Uri(uri));
}

DistributedWant& DistributedWant::FormatUri(const OHOS::Uri& uri)
{
    operation_.SetUri(GetLowerCaseScheme(uri));
    return *this;
}

bool DistributedWant::HasParameter(const std::string& key) const
{
    return parameters_.HasParam(key);
}

DistributedWant* DistributedWant::ReplaceParams(DistributedWantParams& wantParams)
{
    parameters_ = wantParams;
    return this;
}

DistributedWant* DistributedWant::ReplaceParams(DistributedWant& want)
{
    parameters_ = want.parameters_;
    return this;
}

void DistributedWant::RemoveParam(const std::string& key)
{
    parameters_.Remove(key);
}

void DistributedWant::ClearWant(DistributedWant* want)
{
    if (want == nullptr) {
        return;
    }
    want->SetType("");
    want->SetAction("");
    want->SetFlags(0);
    OHOS::AppExecFwk::ElementName elementName;
    want->SetElement(elementName);
    DistributedOperation operation;
    want->SetOperation(operation);
    DistributedWantParams parameters;
    want->SetParams(parameters);
}

bool DistributedWant::MarshallingWriteUri(Parcel& parcel) const
{
    if (GetUriString().empty()) {
        if (!parcel.WriteInt32(VALUE_NULL)) {
            return false;
        }
        return true;
    }
    
    if (!parcel.WriteInt32(VALUE_OBJECT)) {
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(GetUriString()))) {
        return false;
    }
    
    return true;
}

bool DistributedWant::MarshallingWriteEntities(Parcel& parcel) const
{
    std::vector<std::u16string> entityU16;
    std::vector<std::string> entities = GetEntities();
    for (std::vector<std::string>::size_type i = 0; i < entities.size(); i++) {
        entityU16.push_back(Str8ToStr16(entities[i]));
    }
    if (entityU16.size() == 0) {
        if (!parcel.WriteInt32(VALUE_NULL)) {
            return false;
        }
    } else {
        if (!parcel.WriteInt32(VALUE_OBJECT)) {
            return false;
        }
        if (!parcel.WriteString16Vector(entityU16)) {
            return false;
        }
    }
    return true;
}

bool DistributedWant::MarshallingWriteElement(Parcel& parcel) const
{
    ElementName empty;
    ElementName element = GetElement();
    if (element == empty) {
        if (!parcel.WriteInt32(VALUE_NULL)) {
            return false;
        }
    } else {
        if (!parcel.WriteInt32(VALUE_OBJECT)) {
            return false;
        }
        if (!parcel.WriteParcelable(&element)) {
            return false;
        }
    }
    return true;
}

bool DistributedWant::MarshallingWriteParameters(Parcel& parcel) const
{
    if (parameters_.Size() == 0) {
        if (!parcel.WriteInt32(VALUE_NULL)) {
            return false;
        }
        return true;
    }

    if (!parcel.WriteInt32(VALUE_OBJECT)) {
        return false;
    }
    
    if (!parcel.WriteParcelable(&parameters_)) {
        return false;
    }
    return true;
}

bool DistributedWant::Marshalling(Parcel& parcel) const
{
    // write action
    if (!parcel.WriteString16(Str8ToStr16(GetAction()))) {
        return false;
    }
    // write uri
    if (!MarshallingWriteUri(parcel)) {
        return false;
    }
    // write entities
    if (!MarshallingWriteEntities(parcel)) {
        return false;
    }
    // write flags
    if (!parcel.WriteUint32(GetFlags())) {
        return false;
    }
    // write element
    if (!MarshallingWriteElement(parcel)) {
        return false;
    }
    // write parameters
    if (!MarshallingWriteParameters(parcel)) {
        return false;
    }
    // write package
    if (!parcel.WriteString16(Str8ToStr16(GetBundle()))) {
        return false;
    }
    return true;
}

DistributedWant* DistributedWant::Unmarshalling(Parcel& parcel)
{
    DistributedWant* want = new (std::nothrow) DistributedWant();
    if (want != nullptr && !want->ReadFromParcel(parcel)) {
        delete want;
        want = nullptr;
    }
    return want;
}

bool DistributedWant::ReadUriFromParcel(Parcel& parcel)
{
    int value = VALUE_NULL;
    if (!parcel.ReadInt32(value)) {
        return false;
    }
    if (value == VALUE_OBJECT) {
        SetUri(Str16ToStr8(parcel.ReadString16()));
    }
    return true;
}

bool DistributedWant::ReadEntitiesFromParcel(Parcel& parcel)
{
    std::vector<std::string> entities;
    std::vector<std::u16string> entityU16;
    int value = VALUE_NULL;
    if (!parcel.ReadInt32(value)) {
        return false;
    }
    if (value == VALUE_OBJECT) {
        if (!parcel.ReadString16Vector(&entityU16)) {
            return false;
        }
    }
    for (std::vector<std::u16string>::size_type i = 0; i < entityU16.size(); i++) {
        entities.push_back(Str16ToStr8(entityU16[i]));
    }
    operation_.SetEntities(entities);
    return true;
}

bool DistributedWant::ReadElementFromParcel(Parcel& parcel)
{
    int value = VALUE_NULL;
    if (!parcel.ReadInt32(value)) {
        return false;
    }
    if (value == VALUE_OBJECT) {
        auto element = parcel.ReadParcelable<ElementName>();
        if (element != nullptr) {
            SetElement(*element);
            delete element;
            element = nullptr;
        } else {
            return false;
        }
    }
    return true;
}

bool DistributedWant::ReadParametersFromParcel(Parcel& parcel)
{
    int empty = VALUE_NULL;
    if (!parcel.ReadInt32(empty)) {
        return false;
    }
    if (empty == VALUE_OBJECT) {
        auto params = parcel.ReadParcelable<DistributedWantParams>();
        if (params != nullptr) {
            parameters_ = *params;
            delete params;
            params = nullptr;
        } else {
            return false;
        }
    }
    return true;
}

bool DistributedWant::ReadFromParcel(Parcel& parcel)
{
    // read action
    operation_.SetAction(Str16ToStr8(parcel.ReadString16()));
    // read uri
    if (!ReadUriFromParcel(parcel)) {
        return false;
    }
    // read entities
    if (!ReadEntitiesFromParcel(parcel)) {
        return false;
    }
    // read flags
    unsigned int flags;
    if (!parcel.ReadUint32(flags)) {
        return false;
    }
    operation_.SetFlags(flags);
    // read element
    if (!ReadElementFromParcel(parcel)) {
        return false;
    }
    // read parameters
    if (!ReadParametersFromParcel(parcel)) {
        return false;
    }
    // read package
    operation_.SetBundleName(Str16ToStr8(parcel.ReadString16()));
    return true;
}

nlohmann::json DistributedWant::ToJson() const
{
    DistributedWantParamWrapper wrapper(parameters_);
    std::string parametersString = wrapper.ToString();

    nlohmann::json dEntitiesJson;
    std::vector<std::string> entities = GetEntities();
    for (auto entity : entities) {
        dEntitiesJson.emplace_back(entity);
    }

    nlohmann::json wantJson = nlohmann::json {
        {"deviceId", operation_.GetDeviceId()},
        {"bundleName", operation_.GetBundleName()},
        {"abilityName", operation_.GetAbilityName()},
        {"uri", GetUriString()},
        {"type", GetType()},
        {"flags", GetFlags()},
        {"action", GetAction()},
        {"parameters", parametersString},
        {"entities", dEntitiesJson},
    };
    return wantJson;
}

bool DistributedWant::CanReadFromJson(nlohmann::json& wantJson)
{
    const auto& jsonObjectEnd = wantJson.end();
    if ((wantJson.find("deviceId") == jsonObjectEnd)
        || (wantJson.find("bundleName") == jsonObjectEnd)
        || (wantJson.find("abilityName") == jsonObjectEnd)
        || (wantJson.find("uri") == jsonObjectEnd)
        || (wantJson.find("type") == jsonObjectEnd)
        || (wantJson.find("flags") == jsonObjectEnd)
        || (wantJson.find("action") == jsonObjectEnd)
        || (wantJson.find("parameters") == jsonObjectEnd)
        || (wantJson.find("entities") == jsonObjectEnd)) {
        return false;
    }
    if (!wantJson["deviceId"].is_string()) {
        HILOGE("device id is not string");
        return false;
    }
    if (!wantJson["bundleName"].is_string()) {
        HILOGE("bundle name is not string");
        return false;
    }
    if (!wantJson["abilityName"].is_string()) {
        HILOGE("ability name is not string");
        return false;
    }
    if (!wantJson["uri"].is_string()) {
        HILOGE("uri is not string");
        return false;
    }
    if (!wantJson["type"].is_string()) {
        HILOGE("type is not string");
        return false;
    }
    if (!wantJson["flags"].is_number_unsigned()) {
        HILOGE("flags is not a number");
        return false;
    }
    if (!wantJson["action"].is_string()) {
        HILOGE("action is not string");
        return false;
    }
    if (!wantJson["parameters"].is_string()) {
        HILOGE("parameters is not string");
        return false;
    }
    return true;
}

bool DistributedWant::ReadFromJson(nlohmann::json& wantJson)
{
    if (!CanReadFromJson(wantJson)) {
        HILOGE("can not read from json");
        return false;
    }
    if (!wantJson.contains("deviceId") || !wantJson.contains("bundleName") || !wantJson.contains("abilityName") ||
        !wantJson.contains("uri") || !wantJson.contains("type") || !wantJson.contains("flags") ||
        !wantJson.contains("action") || !wantJson.contains("parameters") || !wantJson.contains("entities")) {
        HILOGE("data is empty");
        return false;
    }
    
    std::string deviceId = wantJson.at("deviceId").get<std::string>();
    std::string bundleName = wantJson.at("bundleName").get<std::string>();
    std::string abilityName = wantJson.at("abilityName").get<std::string>();
    SetElementName(deviceId, bundleName, abilityName);

    std::string uri = wantJson.at("uri").get<std::string>();
    SetUri(uri);

    std::string type = wantJson.at("type").get<std::string>();
    SetType(type);

    if (!wantJson.at("flags").is_number()) {
        return false;
    }
    unsigned int flags = wantJson.at("flags").get<unsigned int>();
    SetFlags(flags);

    std::string action = wantJson.at("action").get<std::string>();
    SetAction(action);
    
    if (!wantJson.at("parameters").is_string()) {
        return false;
    }
    std::string parametersString = wantJson.at("parameters").get<std::string>();
    DistributedWantParams parameters = DistributedWantParamWrapper::ParseWantParams(parametersString);
    SetParams(parameters);
    if (!wantJson.at("entities").is_null()) {
        std::vector<std::string> entities;
        wantJson.at("entities").get_to<std::vector<std::string>>(entities);
        for (size_t i = 0; i < entities.size(); i++) {
            AddEntity(entities[i]);
        }
    }
    return true;
}

std::string DistributedWant::ToString() const
{
    return ToJson().dump();
}

DistributedWant* DistributedWant::FromString(std::string& string)
{
    if (string.empty()) {
        return nullptr;
    }

    nlohmann::json wantJson = nlohmann::json::parse(string, nullptr, false);
    if (wantJson.is_discarded()) {
        return nullptr;
    }

    DistributedWant* want = new (std::nothrow) DistributedWant();
    if (want != nullptr && !want->ReadFromJson(wantJson)) {
        delete want;
        want = nullptr;
    }
    return want;
}

DistributedWant& DistributedWant::SetDeviceId(const std::string& deviceId)
{
    operation_.SetDeviceId(deviceId);
    return *this;
}
} // namespace DistributedSchedule
} // namespace OHOS

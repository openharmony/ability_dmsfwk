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

#include "distributed_want_params.h"

#include "array_wrapper.h"
#include "base_interfaces.h"
#include "base_object.h"
#include "bool_wrapper.h"
#include "byte_wrapper.h"
#include "distributed_want_params_wrapper.h"
#include "double_wrapper.h"
#include "float_wrapper.h"
#include "int_wrapper.h"
#include "long_wrapper.h"
#include "parcel.h"
#include "securec.h"
#include "short_wrapper.h"
#include "string_ex.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"
#include "zchar_wrapper.h"
#include "remote_object_wrapper.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const char* FD = "FD";
const char* REMOTE_OBJECT = "RemoteObject";
const char* TYPE_PROPERTY = "type";
const char* VALUE_PROPERTY = "value";
}
DistributedUnsupportedData::~DistributedUnsupportedData()
{
    if (buffer != nullptr) {
        delete[] buffer;
        buffer = nullptr;
    }
}

DistributedUnsupportedData::DistributedUnsupportedData() = default;

DistributedUnsupportedData::DistributedUnsupportedData(const DistributedUnsupportedData& other)
    : key(other.key), type(other.type), size(other.size)
{
    buffer = new uint8_t[size];
    if (memcpy_s(buffer, size, other.buffer, size) != EOK) {
        key.clear();
        type = 0;
        size = 0;
        delete[] buffer;
        buffer = nullptr;
    }
}

DistributedUnsupportedData::DistributedUnsupportedData(DistributedUnsupportedData&& other)
    : key(std::move(other.key)), type(other.type), size(other.size), buffer(other.buffer)
{
    other.type = 0;
    other.size = 0;
    other.buffer = nullptr;
}

DistributedUnsupportedData& DistributedUnsupportedData::operator=(const DistributedUnsupportedData& other)
{
    if (this == &other) {
        return *this;
    }
    key = other.key;
    type = other.type;
    size = other.size;
    buffer = new uint8_t[size];
    if (memcpy_s(buffer, size, other.buffer, size) != EOK) {
        key.clear();
        type = 0;
        size = 0;
        delete[] buffer;
        buffer = nullptr;
    }
    return *this;
}

DistributedUnsupportedData& DistributedUnsupportedData::operator=(DistributedUnsupportedData&& other)
{
    key = std::move(other.key);
    type = other.type;
    size = other.size;
    std::swap(buffer, other.buffer);

    other.type = 0;
    other.size = 0;
    if (other.buffer) {
        delete[] other.buffer;
        other.buffer = nullptr;
    }
    return *this;
}

std::string DistributedWantParams::GetStringByType(const sptr<AAFwk::IInterface> iIt, int typeId)
{
    if (typeId == VALUE_TYPE_BOOLEAN) {
        return static_cast<AAFwk::Boolean*>(AAFwk::IBoolean::Query(iIt))->ToString();
    } else if (typeId == VALUE_TYPE_BYTE) {
        return static_cast<AAFwk::Byte*>(AAFwk::IByte::Query(iIt))->ToString();
    } else if (typeId == VALUE_TYPE_CHAR) {
        return static_cast<AAFwk::Char*>(AAFwk::IChar::Query(iIt))->ToString();
    } else if (typeId == VALUE_TYPE_SHORT) {
        return static_cast<AAFwk::Short*>(AAFwk::IShort::Query(iIt))->ToString();
    } else if (typeId == VALUE_TYPE_INT) {
        return static_cast<AAFwk::Integer*>(AAFwk::IInteger::Query(iIt))->ToString();
    } else if (typeId == VALUE_TYPE_LONG) {
        return static_cast<AAFwk::Long*>(AAFwk::ILong::Query(iIt))->ToString();
    } else if (typeId == VALUE_TYPE_FLOAT) {
        return static_cast<AAFwk::Float*>(AAFwk::IFloat::Query(iIt))->ToString();
    } else if (typeId == VALUE_TYPE_DOUBLE) {
        return static_cast<AAFwk::Double*>(AAFwk::IDouble::Query(iIt))->ToString();
    } else if (typeId == VALUE_TYPE_STRING) {
        return static_cast<AAFwk::String*>(AAFwk::IString::Query(iIt))->ToString();
    } else if (typeId == VALUE_TYPE_ARRAY) {
        return static_cast<AAFwk::Array*>(AAFwk::IArray::Query(iIt))->ToString();
    } else if (typeId == VALUE_TYPE_WANTPARAMS) {
        return static_cast<DistributedWantParamWrapper*>(IDistributedWantParams::Query(iIt))->ToString();
    } else {
        return "";
    }
    return "";
}
template<typename T1, typename T2, typename T3>
static void SetNewArray(const AAFwk::InterfaceID& id, AAFwk::IArray* orgIArray, sptr<AAFwk::IArray>& ao);

DistributedWantParams::DistributedWantParams(const DistributedWantParams& wantParams)
{
    params_.clear();
    NewParams(wantParams, *this);
}
// inner use function
bool DistributedWantParams::NewParams(const DistributedWantParams& source, DistributedWantParams& dest)
{
    // Deep copy
    for (auto it = source.params_.begin(); it != source.params_.end(); it++) {
        sptr<IInterface> o = it->second;
        if (AAFwk::IString::Query(o) != nullptr) {
            dest.params_[it->first] = AAFwk::String::Box(AAFwk::String::Unbox(AAFwk::IString::Query(o)));
        } else if (AAFwk::IBoolean::Query(o) != nullptr) {
            dest.params_[it->first] = AAFwk::Boolean::Box(AAFwk::Boolean::Unbox(AAFwk::IBoolean::Query(o)));
        } else if (AAFwk::IByte::Query(o) != nullptr) {
            dest.params_[it->first] = AAFwk::Byte::Box(AAFwk::Byte::Unbox(AAFwk::IByte::Query(o)));
        } else if (AAFwk::IChar::Query(o) != nullptr) {
            dest.params_[it->first] = AAFwk::Char::Box(AAFwk::Char::Unbox(AAFwk::IChar::Query(o)));
        } else if (AAFwk::IShort::Query(o) != nullptr) {
            dest.params_[it->first] = AAFwk::Short::Box(AAFwk::Short::Unbox(AAFwk::IShort::Query(o)));
        } else if (AAFwk::IInteger::Query(o) != nullptr) {
            dest.params_[it->first] = AAFwk::Integer::Box(AAFwk::Integer::Unbox(AAFwk::IInteger::Query(o)));
        } else if (AAFwk::ILong::Query(o) != nullptr) {
            dest.params_[it->first] = AAFwk::Long::Box(AAFwk::Long::Unbox(AAFwk::ILong::Query(o)));
        } else if (AAFwk::IFloat::Query(o) != nullptr) {
            dest.params_[it->first] = AAFwk::Float::Box(AAFwk::Float::Unbox(AAFwk::IFloat::Query(o)));
        } else if (AAFwk::IDouble::Query(o) != nullptr) {
            dest.params_[it->first] = AAFwk::Double::Box(AAFwk::Double::Unbox(AAFwk::IDouble::Query(o)));
        } else if (AAFwk::IRemoteObjectWrap::Query(o) != nullptr) {
            dest.params_[it->first] =
                AAFwk::RemoteObjectWrap::Box(AAFwk::RemoteObjectWrap::UnBox(AAFwk::IRemoteObjectWrap::Query(o)));
        } else if (IDistributedWantParams::Query(o) != nullptr) {
            DistributedWantParams newDest(DistributedWantParamWrapper::Unbox(IDistributedWantParams::Query(o)));
            dest.params_[it->first] = DistributedWantParamWrapper::Box(newDest);
        } else if (AAFwk::IArray::Query(o) != nullptr) {
            sptr<AAFwk::IArray> destAO = nullptr;
            if (!NewArrayData(AAFwk::IArray::Query(o), destAO)) {
                continue;
            }
            dest.params_[it->first] = destAO;
        }
    }
    return true;
}

bool DistributedWantParams::NewArrayData(AAFwk::IArray* source, sptr<AAFwk::IArray>& dest)
{
    if (AAFwk::Array::IsBooleanArray(source)) {
        SetNewArray<bool, AAFwk::Boolean, AAFwk::IBoolean>(AAFwk::g_IID_IBoolean, source, dest);
    } else if (AAFwk::Array::IsCharArray(source)) {
        SetNewArray<char, AAFwk::Char, AAFwk::IChar>(AAFwk::g_IID_IChar, source, dest);
    } else if (AAFwk::Array::IsByteArray(source)) {
        SetNewArray<AAFwk::byte, AAFwk::Byte, AAFwk::IByte>(AAFwk::g_IID_IByte, source, dest);
    } else if (AAFwk::Array::IsShortArray(source)) {
        SetNewArray<short, AAFwk::Short, AAFwk::IShort>(AAFwk::g_IID_IShort, source, dest);
    } else if (AAFwk::Array::IsIntegerArray(source)) {
        SetNewArray<int, AAFwk::Integer, AAFwk::IInteger>(AAFwk::g_IID_IInteger, source, dest);
    } else if (AAFwk::Array::IsLongArray(source)) {
        SetNewArray<long, AAFwk::Long, AAFwk::ILong>(AAFwk::g_IID_ILong, source, dest);
    } else if (AAFwk::Array::IsFloatArray(source)) {
        SetNewArray<float, AAFwk::Float, AAFwk::IFloat>(AAFwk::g_IID_IFloat, source, dest);
    } else if (AAFwk::Array::IsDoubleArray(source)) {
        SetNewArray<double, AAFwk::Double, AAFwk::IDouble>(AAFwk::g_IID_IDouble, source, dest);
    } else if (AAFwk::Array::IsStringArray(source)) {
        SetNewArray<std::string, AAFwk::String, AAFwk::IString>(AAFwk::g_IID_IString, source, dest);
    } else {
        return false;
    }

    if (dest == nullptr) {
        return false;
    }

    return true;
}

DistributedWantParams& DistributedWantParams::operator=(const DistributedWantParams& other)
{
    if (this != &other) {
        params_.clear();
        NewParams(other, *this);
    }
    return *this;
}

bool DistributedWantParams::operator==(const DistributedWantParams& other)
{
    if (this->params_.size() != other.params_.size()) {
        return false;
    }
    for (auto itthis : this->params_) {
        auto itother = other.params_.find(itthis.first);
        if (itother == other.params_.end()) {
            return false;
        }
        if (!CompareInterface(itother->second, itthis.second, DistributedWantParams::GetDataType(itother->second))) {
            return false;
        }
    }
    return true;
}

int DistributedWantParams::GetDataType(const sptr<IInterface> iIt)
{
    if (iIt != nullptr && AAFwk::IBoolean::Query(iIt) != nullptr) {
        return VALUE_TYPE_BOOLEAN;
    } else if (iIt != nullptr && AAFwk::IByte::Query(iIt) != nullptr) {
        return VALUE_TYPE_BYTE;
    } else if (iIt != nullptr && AAFwk::IChar::Query(iIt) != nullptr) {
        return VALUE_TYPE_CHAR;
    } else if (iIt != nullptr && AAFwk::IShort::Query(iIt) != nullptr) {
        return VALUE_TYPE_SHORT;
    } else if (iIt != nullptr && AAFwk::IInteger::Query(iIt) != nullptr) {
        return VALUE_TYPE_INT;
    } else if (iIt != nullptr && AAFwk::ILong::Query(iIt) != nullptr) {
        return VALUE_TYPE_LONG;
    } else if (iIt != nullptr && AAFwk::IFloat::Query(iIt) != nullptr) {
        return VALUE_TYPE_FLOAT;
    } else if (iIt != nullptr && AAFwk::IDouble::Query(iIt) != nullptr) {
        return VALUE_TYPE_DOUBLE;
    } else if (iIt != nullptr && AAFwk::IString::Query(iIt) != nullptr) {
        return VALUE_TYPE_STRING;
    } else if (iIt != nullptr && AAFwk::IArray::Query(iIt) != nullptr) {
        return VALUE_TYPE_ARRAY;
    } else if (iIt != nullptr && IDistributedWantParams::Query(iIt) != nullptr) {
        return VALUE_TYPE_WANTPARAMS;
    }

    return VALUE_TYPE_NULL;
}

sptr<IInterface> DistributedWantParams::GetInterfaceByType(int typeId, const std::string& value)
{
    if (typeId == VALUE_TYPE_BOOLEAN) {
        return AAFwk::Boolean::Parse(value);
    } else if (typeId == VALUE_TYPE_BYTE) {
        return AAFwk::Byte::Parse(value);
    } else if (typeId == VALUE_TYPE_CHAR) {
        return AAFwk::Char::Parse(value);
    } else if (typeId == VALUE_TYPE_SHORT) {
        return AAFwk::Short::Parse(value);
    } else if (typeId == VALUE_TYPE_INT) {
        return AAFwk::Integer::Parse(value);
    } else if (typeId == VALUE_TYPE_LONG) {
        return AAFwk::Long::Parse(value);
    } else if (typeId == VALUE_TYPE_FLOAT) {
        return AAFwk::Float::Parse(value);
    } else if (typeId == VALUE_TYPE_DOUBLE) {
        return AAFwk::Double::Parse(value);
    } else if (typeId == VALUE_TYPE_STRING) {
        return AAFwk::String::Parse(value);
    } else if (typeId == VALUE_TYPE_ARRAY) {
        return AAFwk::Array::Parse(value);
    }

    return nullptr;
}

bool DistributedWantParams::CompareInterface(const sptr<IInterface> iIt1, const sptr<IInterface> iIt2, int typeId)
{
    bool flag = false;
    switch (typeId) {
        case VALUE_TYPE_BOOLEAN:
            flag = static_cast<AAFwk::Boolean*>(AAFwk::IBoolean::Query(iIt1))
                ->Equals(*(static_cast<AAFwk::Boolean*>(AAFwk::IBoolean::Query(iIt1))));
            break;
        case VALUE_TYPE_BYTE:
            flag = static_cast<AAFwk::Byte*>(AAFwk::IByte::Query(iIt1))
                ->Equals(*(static_cast<AAFwk::Byte*>(AAFwk::IByte::Query(iIt1))));
            break;
        case VALUE_TYPE_CHAR:
            flag = static_cast<AAFwk::Char*>(AAFwk::IChar::Query(iIt1))
                ->Equals(*(static_cast<AAFwk::Char*>(AAFwk::IChar::Query(iIt1))));
            break;
        case VALUE_TYPE_SHORT:
            flag = static_cast<AAFwk::Short*>(AAFwk::IShort::Query(iIt1))
                ->Equals(*(static_cast<AAFwk::Short*>(AAFwk::IShort::Query(iIt1))));
            break;
        case VALUE_TYPE_INT:
            flag = static_cast<AAFwk::Integer*>(AAFwk::IInteger::Query(iIt1))
                ->Equals(*(static_cast<AAFwk::Integer*>(AAFwk::IInteger::Query(iIt1))));
            break;
        case VALUE_TYPE_LONG:
            flag = static_cast<AAFwk::Long*>(AAFwk::ILong::Query(iIt1))
                ->Equals(*(static_cast<AAFwk::Long*>(AAFwk::ILong::Query(iIt1))));
            break;
        case VALUE_TYPE_FLOAT:
            flag = static_cast<AAFwk::Float*>(AAFwk::IFloat::Query(iIt1))
                ->Equals(*(static_cast<AAFwk::Float*>(AAFwk::IFloat::Query(iIt1))));
            break;
        case VALUE_TYPE_DOUBLE:
            flag = static_cast<AAFwk::Double*>(AAFwk::IDouble::Query(iIt1))
                ->Equals(*(static_cast<AAFwk::Double*>(AAFwk::IDouble::Query(iIt1))));
            break;
        case VALUE_TYPE_STRING:
            flag = static_cast<AAFwk::String*>(AAFwk::IString::Query(iIt1))
                ->Equals(*(static_cast<AAFwk::String*>(AAFwk::IString::Query(iIt1))));
            break;
        case VALUE_TYPE_ARRAY:
            flag = static_cast<AAFwk::Array*>(AAFwk::IArray::Query(iIt1))
                ->Equals(*(static_cast<AAFwk::Array*>(AAFwk::IArray::Query(iIt1))));
            break;
        case VALUE_TYPE_WANTPARAMS:
            flag = static_cast<DistributedWantParamWrapper*>(IDistributedWantParams::Query(iIt1))
                ->Equals(*(static_cast<DistributedWantParamWrapper*>(IDistributedWantParams::Query(iIt1))));
            break;
        default:
            break;
    }
    return flag;
}

void DistributedWantParams::SetParam(const std::string& key, IInterface* value)
{
    params_[key] = value;
}

sptr<IInterface> DistributedWantParams::GetParam(const std::string& key) const
{
    auto it = params_.find(key);
    if (it == params_.cend()) {
        return nullptr;
    }
    return it->second;
}

const std::map<std::string, sptr<IInterface>>& DistributedWantParams::GetParams() const
{
    return params_;
}

const std::set<std::string> DistributedWantParams::KeySet() const
{
    std::set<std::string> keySet;
    keySet.clear();

    for (auto it : params_) {
        keySet.emplace(it.first);
    }

    return keySet;
}

void DistributedWantParams::Remove(const std::string& key)
{
    params_.erase(key);
}

bool DistributedWantParams::HasParam(const std::string& key) const
{
    return (params_.count(key) > 0);
}

int DistributedWantParams::Size() const
{
    return params_.size();
}

bool DistributedWantParams::IsEmpty() const
{
    return (params_.size() == 0);
}

bool DistributedWantParams::WriteToParcelString(Parcel& parcel, sptr<IInterface>& o) const
{
    std::string value = AAFwk::String::Unbox(AAFwk::IString::Query(o));
    if (!parcel.WriteInt32(VALUE_TYPE_STRING)) {
        return false;
    }
    return parcel.WriteString16(Str8ToStr16(value));
}

bool DistributedWantParams::WriteToParcelBool(Parcel& parcel, sptr<IInterface>& o) const
{
    bool value = AAFwk::Boolean::Unbox(AAFwk::IBoolean::Query(o));
    if (!parcel.WriteInt32(VALUE_TYPE_BOOLEAN)) {
        return false;
    }
    return parcel.WriteInt8(value);
}

bool DistributedWantParams::WriteToParcelWantParams(Parcel& parcel, sptr<IInterface>& o) const
{
    DistributedWantParams value = DistributedWantParamWrapper::Unbox(IDistributedWantParams::Query(o));

    auto type = value.GetParam(TYPE_PROPERTY);
    AAFwk::IString *typeP = AAFwk::IString::Query(type);
    if (typeP != nullptr) {
        std::string typeValue = AAFwk::String::Unbox(typeP);
        if (typeValue == FD) {
            return WriteToParcelFD(parcel, value);
        }
        if (typeValue == REMOTE_OBJECT) {
            return WriteToParcelRemoteObject(parcel, value);
        }
    }

    if (!parcel.WriteInt32(VALUE_TYPE_WANTPARAMS)) {
        return false;
    }
    return parcel.WriteString16(Str8ToStr16(
        static_cast<DistributedWantParamWrapper*>(IDistributedWantParams::Query(o))->ToString()));
}

bool DistributedWantParams::WriteToParcelFD(Parcel& parcel, const DistributedWantParams& value) const
{
    if (!parcel.WriteInt32(VALUE_TYPE_FD)) {
        return false;
    }

    auto fdWrap = value.GetParam(VALUE_PROPERTY);
    AAFwk::IInteger *fdIWrap = AAFwk::IInteger::Query(fdWrap);
    if (fdIWrap != nullptr) {
        int fd = AAFwk::Integer::Unbox(fdIWrap);
        auto messageParcel = static_cast<MessageParcel*>(&parcel);
        if (messageParcel == nullptr) {
            return false;
        }
        bool ret = messageParcel->WriteFileDescriptor(fd);
        return ret;
    }

    return false;
}

bool DistributedWantParams::WriteToParcelRemoteObject(Parcel& parcel, const DistributedWantParams& value) const
{
    if (!parcel.WriteInt32(VALUE_TYPE_REMOTE_OBJECT)) {
        return false;
    }

    auto remoteObjectWrap = value.GetParam(VALUE_PROPERTY);
    AAFwk::IRemoteObjectWrap *remoteObjectIWrap = AAFwk::IRemoteObjectWrap::Query(remoteObjectWrap);
    if (remoteObjectIWrap != nullptr) {
        auto remoteObject = AAFwk::RemoteObjectWrap::UnBox(remoteObjectIWrap);
        auto messageParcel = static_cast<MessageParcel*>(&parcel);
        if (messageParcel == nullptr) {
            return false;
        }
        bool ret = messageParcel->WriteRemoteObject(remoteObject);
        return ret;
    }
    return false;
}

bool DistributedWantParams::WriteToParcelByte(Parcel& parcel, sptr<IInterface>& o) const
{
    AAFwk::byte value = AAFwk::Byte::Unbox(AAFwk::IByte::Query(o));
    if (!parcel.WriteInt32(VALUE_TYPE_BYTE)) {
        return false;
    }
    return parcel.WriteInt8(value);
}

bool DistributedWantParams::WriteToParcelChar(Parcel& parcel, sptr<IInterface>& o) const
{
    AAFwk::zchar value = AAFwk::Char::Unbox(AAFwk::IChar::Query(o));
    if (!parcel.WriteInt32(VALUE_TYPE_CHAR)) {
        return false;
    }
    return parcel.WriteInt32(value);
}

bool DistributedWantParams::WriteToParcelShort(Parcel& parcel, sptr<IInterface>& o) const
{
    short value = AAFwk::Short::Unbox(AAFwk::IShort::Query(o));
    if (!parcel.WriteInt32(VALUE_TYPE_SHORT)) {
        return false;
    }
    return parcel.WriteInt16(value);
}

bool DistributedWantParams::WriteToParcelInt(Parcel& parcel, sptr<IInterface>& o) const
{
    int value = AAFwk::Integer::Unbox(AAFwk::IInteger::Query(o));
    if (!parcel.WriteInt32(VALUE_TYPE_INT)) {
        return false;
    }
    return parcel.WriteInt32(value);
}

bool DistributedWantParams::WriteToParcelLong(Parcel& parcel, sptr<IInterface>& o) const
{
    long value = AAFwk::Long::Unbox(AAFwk::ILong::Query(o));
    if (!parcel.WriteInt32(VALUE_TYPE_LONG)) {
        return false;
    }
    return parcel.WriteInt64(value);
}

bool DistributedWantParams::WriteToParcelFloat(Parcel& parcel, sptr<IInterface>& o) const
{
    float value = AAFwk::Float::Unbox(AAFwk::IFloat::Query(o));
    if (!parcel.WriteInt32(VALUE_TYPE_FLOAT)) {
        return false;
    }
    return parcel.WriteFloat(value);
}

bool DistributedWantParams::WriteToParcelDouble(Parcel& parcel, sptr<IInterface>& o) const
{
    double value = AAFwk::Double::Unbox(AAFwk::IDouble::Query(o));
    if (!parcel.WriteInt32(VALUE_TYPE_DOUBLE)) {
        return false;
    }
    return parcel.WriteDouble(value);
}

bool DistributedWantParams::WriteMarshalling(Parcel& parcel, sptr<IInterface>& o) const
{
    if (AAFwk::IString::Query(o) != nullptr) {
        return WriteToParcelString(parcel, o);
    } else if (AAFwk::IBoolean::Query(o) != nullptr) {
        return WriteToParcelBool(parcel, o);
    } else if (AAFwk::IByte::Query(o) != nullptr) {
        return WriteToParcelByte(parcel, o);
    } else if (AAFwk::IChar::Query(o) != nullptr) {
        return WriteToParcelChar(parcel, o);
    } else if (AAFwk::IShort::Query(o) != nullptr) {
        return WriteToParcelShort(parcel, o);
    } else if (AAFwk::IInteger::Query(o) != nullptr) {
        return WriteToParcelInt(parcel, o);
    } else if (AAFwk::ILong::Query(o) != nullptr) {
        return WriteToParcelLong(parcel, o);
    } else if (AAFwk::IFloat::Query(o) != nullptr) {
        return WriteToParcelFloat(parcel, o);
    } else if (AAFwk::IDouble::Query(o) != nullptr) {
        return WriteToParcelDouble(parcel, o);
    } else if (IDistributedWantParams::Query(o) != nullptr) {
        return WriteToParcelWantParams(parcel, o);
    } else {
        AAFwk::IArray* ao = AAFwk::IArray::Query(o);
        if (ao != nullptr) {
            sptr<AAFwk::IArray> array(ao);
            return WriteArrayToParcel(parcel, array);
        } else {
            return true;
        }
    }
}

bool DistributedWantParams::DoMarshalling(Parcel& parcel) const
{
    size_t size = params_.size();
    if (!cachedUnsupportedData_.empty()) {
        size += cachedUnsupportedData_.size();
    }

    if (!parcel.WriteInt32(size)) {
        return false;
    }

    auto iter = params_.cbegin();
    while (iter != params_.cend()) {
        std::string key = iter->first;
        sptr<AAFwk::IInterface> o = iter->second;
        if (!parcel.WriteString16(Str8ToStr16(key))) {
            return false;
        }

        if (!WriteMarshalling(parcel, o)) {
            return false;
        }
        iter++;
    }

    if (!cachedUnsupportedData_.empty()) {
        for (const DistributedUnsupportedData& data : cachedUnsupportedData_) {
            if (!parcel.WriteString16(data.key)) {
                return false;
            }
            if (!parcel.WriteInt32(data.type)) {
                return false;
            }
            if (!parcel.WriteInt32(data.size)) {
                return false;
            }
            // Corresponding to Parcel#writeByteArray() in Java.
            if (!parcel.WriteInt32(data.size)) {
                return false;
            }
            if (!parcel.WriteBuffer(data.buffer, data.size)) {
                return false;
            }
        }
    }
    return true;
}

bool DistributedWantParams::Marshalling(Parcel& parcel) const
{
    return DoMarshalling(parcel);
}

template<typename dataType, typename className>
static bool SetArray(const AAFwk::InterfaceID& id, const std::vector<dataType>& value, sptr<AAFwk::IArray>& ao)
{
    typename std::vector<dataType>::size_type size = value.size();
    ao = new (std::nothrow) AAFwk::Array(size, id);
    if (ao != nullptr) {
        for (typename std::vector<dataType>::size_type i = 0; i < size; i++) {
            ao->Set(i, className::Box(value[i]));
        }
        return true;
    }
    return false;
}

template<typename T1, typename T2, typename T3>
static void FillArray(AAFwk::IArray* ao, std::vector<T1>&array)
{
    auto func = [&](AAFwk::IInterface* object) {
        if (object != nullptr) {
            T3* value = T3::Query(object);
            if (value != nullptr) {
                array.push_back(T2::Unbox(value));
            }
        }
    };
    AAFwk::Array::ForEach(ao, func);
}
// inner use template function
template<typename T1, typename T2, typename T3>
static void SetNewArray(const AAFwk::InterfaceID& id, AAFwk::IArray* orgIArray, sptr<AAFwk::IArray>& ao)
{
    if (orgIArray == nullptr) {
        return;
    }
    std::vector<T1> array;
    auto func = [&array](AAFwk::IInterface* object) {
        if (object != nullptr) {
            T3* value = T3::Query(object);
            if (value != nullptr) {
                array.push_back(T2::Unbox(value));
            }
        }
    };
    AAFwk::Array::ForEach(orgIArray, func);

    typename std::vector<T1>::size_type size = array.size();
    if (size > 0) {
        ao = new (std::nothrow) AAFwk::Array(size, id);
        if (ao != nullptr) {
            for (typename std::vector<T1>::size_type i = 0; i < size; i++) {
                ao->Set(i, T2::Box(array[i]));
            }
        }
    }
}

bool DistributedWantParams::WriteArrayToParcelString(Parcel& parcel, AAFwk::IArray* ao) const
{
    if (ao == nullptr) {
        return false;
    }

    std::vector<std::u16string> array;
    auto func = [&](IInterface* object) {
        std::string s = AAFwk::String::Unbox(AAFwk::IString::Query(object));
        array.push_back(Str8ToStr16(s));
    };

    AAFwk::Array::ForEach(ao, func);

    if (!parcel.WriteInt32(VALUE_TYPE_STRINGARRAY)) {
        return false;
    }
    return parcel.WriteString16Vector(array);
}

bool DistributedWantParams::WriteArrayToParcelBool(Parcel& parcel, AAFwk::IArray* ao) const
{
    if (ao == nullptr) {
        return false;
    }

    std::vector<int8_t> array;
    std::vector<int32_t> intArray;
    FillArray<int8_t, AAFwk::Boolean, AAFwk::IBoolean>(ao, array);
    if (!parcel.WriteInt32(VALUE_TYPE_BOOLEANARRAY)) {
        return false;
    }

    for (std::vector<int8_t>::size_type i = 0; i < array.size(); i++) {
        intArray.push_back(array[i]);
    }
    return parcel.WriteInt32Vector(intArray);
}

bool DistributedWantParams::WriteArrayToParcelByte(Parcel& parcel, AAFwk::IArray* ao) const
{
    if (ao == nullptr) {
        return false;
    }

    std::vector<int8_t> array;
    FillArray<int8_t, AAFwk::Byte, AAFwk::IByte>(ao, array);
    if (!parcel.WriteInt32(VALUE_TYPE_BYTEARRAY)) {
        return false;
    }
    return parcel.WriteInt8Vector(array);
}

bool DistributedWantParams::WriteArrayToParcelChar(Parcel& parcel, AAFwk::IArray* ao) const
{
    if (ao == nullptr) {
        return false;
    }

    std::vector<int32_t> array;
    FillArray<int32_t, AAFwk::Char, AAFwk::IChar>(ao, array);
    if (!parcel.WriteInt32(VALUE_TYPE_CHARARRAY)) {
        return false;
    }
    return parcel.WriteInt32Vector(array);
}

bool DistributedWantParams::WriteArrayToParcelShort(Parcel& parcel, AAFwk::IArray* ao) const
{
    if (ao == nullptr) {
        return false;
    }

    std::vector<short> array;
    FillArray<short, AAFwk::Short, AAFwk::IShort>(ao, array);
    if (!parcel.WriteInt32(VALUE_TYPE_SHORTARRAY)) {
        return false;
    }
    return parcel.WriteInt16Vector(array);
}

bool DistributedWantParams::WriteArrayToParcelInt(Parcel& parcel, AAFwk::IArray* ao) const
{
    if (ao == nullptr) {
        return false;
    }

    std::vector<int> array;
    FillArray<int, AAFwk::Integer, AAFwk::IInteger>(ao, array);
    if (!parcel.WriteInt32(VALUE_TYPE_INTARRAY)) {
        return false;
    }
    return parcel.WriteInt32Vector(array);
}

bool DistributedWantParams::WriteArrayToParcelLong(Parcel& parcel, AAFwk::IArray* ao) const
{
    if (ao == nullptr) {
        return false;
    }

    std::vector<int64_t> array;
    FillArray<int64_t, AAFwk::Long, AAFwk::ILong>(ao, array);
    if (!parcel.WriteInt32(VALUE_TYPE_LONGARRAY)) {
        return false;
    }
    return parcel.WriteInt64Vector(array);
}

bool DistributedWantParams::WriteArrayToParcelFloat(Parcel& parcel, AAFwk::IArray* ao) const
{
    if (ao == nullptr) {
        return false;
    }

    std::vector<float> array;
    FillArray<float, AAFwk::Float, AAFwk::IFloat>(ao, array);
    if (!parcel.WriteInt32(VALUE_TYPE_FLOATARRAY)) {
        return false;
    }
    return parcel.WriteFloatVector(array);
}

bool DistributedWantParams::WriteArrayToParcelDouble(Parcel& parcel, AAFwk::IArray* ao) const
{
    if (ao == nullptr) {
        return false;
    }

    std::vector<double> array;
    FillArray<double, AAFwk::Double, AAFwk::IDouble>(ao, array);
    if (!parcel.WriteInt32(VALUE_TYPE_DOUBLEARRAY)) {
        return false;
    }
    return parcel.WriteDoubleVector(array);
}

bool DistributedWantParams::WriteArrayToParcel(Parcel& parcel, AAFwk::IArray* ao) const
{
    if (AAFwk::Array::IsStringArray(ao)) {
        return WriteArrayToParcelString(parcel, ao);
    } else if (AAFwk::Array::IsBooleanArray(ao)) {
        return WriteArrayToParcelBool(parcel, ao);
    } else if (AAFwk::Array::IsByteArray(ao)) {
        return WriteArrayToParcelByte(parcel, ao);
    } else if (AAFwk::Array::IsCharArray(ao)) {
        return WriteArrayToParcelChar(parcel, ao);
    } else if (AAFwk::Array::IsShortArray(ao)) {
        return WriteArrayToParcelShort(parcel, ao);
    } else if (AAFwk::Array::IsIntegerArray(ao)) {
        return WriteArrayToParcelInt(parcel, ao);
    } else if (AAFwk::Array::IsLongArray(ao)) {
        return WriteArrayToParcelLong(parcel, ao);
    } else if (AAFwk::Array::IsFloatArray(ao)) {
        return WriteArrayToParcelFloat(parcel, ao);
    } else if (AAFwk::Array::IsDoubleArray(ao)) {
        return WriteArrayToParcelDouble(parcel, ao);
    } else {
        return true;
    }
}

bool DistributedWantParams::ReadFromParcelArrayString(Parcel& parcel, sptr<AAFwk::IArray>& ao)
{
    std::vector<std::u16string> value;
    if (!parcel.ReadString16Vector(&value)) {
        return false;
    }

    std::vector<std::u16string>::size_type size = value.size();
    ao = new (std::nothrow) AAFwk::Array(size, AAFwk::g_IID_IString);
    if (ao != nullptr) {
        for (std::vector<std::u16string>::size_type i = 0; i < size; i++) {
            ao->Set(i, AAFwk::String::Box(Str16ToStr8(value[i])));
        }
        return true;
    }
    return false;
}

bool DistributedWantParams::ReadFromParcelArrayBool(Parcel& parcel, sptr<AAFwk::IArray>& ao)
{
    std::vector<int32_t> value;
    std::vector<int8_t> boolValue;
    if (!parcel.ReadInt32Vector(&value)) {
        return false;
    }

    std::vector<int32_t>::size_type size = value.size();
    for (std::vector<int32_t>::size_type i = 0; i < size; i++) {
        boolValue.push_back(value[i]);
    }
    return SetArray<int8_t, AAFwk::Boolean>(AAFwk::g_IID_IBoolean, boolValue, ao);
}

bool DistributedWantParams::ReadFromParcelArrayByte(Parcel& parcel, sptr<AAFwk::IArray>& ao)
{
    std::vector<int8_t> value;
    if (!parcel.ReadInt8Vector(&value)) {
        return false;
    }
    return SetArray<int8_t, AAFwk::Byte>(AAFwk::g_IID_IByte, value, ao);
}

bool DistributedWantParams::ReadFromParcelArrayChar(Parcel& parcel, sptr<AAFwk::IArray>& ao)
{
    std::vector<int32_t> value;
    if (!parcel.ReadInt32Vector(&value)) {
        return false;
    }
    return SetArray<int32_t, AAFwk::Char>(AAFwk::g_IID_IChar, value, ao);
}

bool DistributedWantParams::ReadFromParcelArrayShort(Parcel& parcel, sptr<AAFwk::IArray>& ao)
{
    std::vector<short> value;
    if (!parcel.ReadInt16Vector(&value)) {
        return false;
    }
    return SetArray<short, AAFwk::Short>(AAFwk::g_IID_IShort, value, ao);
}

bool DistributedWantParams::ReadFromParcelArrayInt(Parcel& parcel, sptr<AAFwk::IArray>& ao)
{
    std::vector<int> value;
    if (!parcel.ReadInt32Vector(&value)) {
        return false;
    }
    return SetArray<int, AAFwk::Integer>(AAFwk::g_IID_IInteger, value, ao);
}

bool DistributedWantParams::ReadFromParcelArrayLong(Parcel& parcel, sptr<AAFwk::IArray>& ao)
{
    std::vector<int64_t> value;
    if (!parcel.ReadInt64Vector(&value)) {
        return false;
    }

#ifdef WANT_PARAM_USE_LONG
    return SetArray<int64_t, Long>(g_IID_ILong, value, ao);
#else
    std::vector<std::string> strList;
    for (size_t i = 0; i < value.size(); i++) {
        strList.push_back(std::to_string(value[i]));
    }
    return SetArray<std::string, AAFwk::String>(AAFwk::g_IID_IString, strList, ao);
#endif
}

bool DistributedWantParams::ReadFromParcelArrayFloat(Parcel& parcel, sptr<AAFwk::IArray>& ao)
{
    std::vector<float> value;
    if (!parcel.ReadFloatVector(&value)) {
        return false;
    }
    return SetArray<float, AAFwk::Float>(AAFwk::g_IID_IFloat, value, ao);
}

bool DistributedWantParams::ReadFromParcelArrayDouble(Parcel& parcel, sptr<AAFwk::IArray>& ao)
{
    std::vector<double> value;
    if (!parcel.ReadDoubleVector(&value)) {
        return false;
    }
    return SetArray<double, AAFwk::Double>(AAFwk::g_IID_IDouble, value, ao);
}

bool DistributedWantParams::ReadArrayToParcel(Parcel& parcel, int type, sptr<AAFwk::IArray>& ao)
{
    switch (type) {
        case VALUE_TYPE_STRINGARRAY:
        case VALUE_TYPE_CHARSEQUENCEARRAY:
            return ReadFromParcelArrayString(parcel, ao);
        case VALUE_TYPE_BOOLEANARRAY:
            return ReadFromParcelArrayBool(parcel, ao);
        case VALUE_TYPE_BYTEARRAY:
            return ReadFromParcelArrayByte(parcel, ao);
        case VALUE_TYPE_CHARARRAY:
            return ReadFromParcelArrayChar(parcel, ao);
        case VALUE_TYPE_SHORTARRAY:
            return ReadFromParcelArrayShort(parcel, ao);
        case VALUE_TYPE_INTARRAY:
            return ReadFromParcelArrayInt(parcel, ao);
        case VALUE_TYPE_LONGARRAY:
            return ReadFromParcelArrayLong(parcel, ao);
        case VALUE_TYPE_FLOATARRAY:
            return ReadFromParcelArrayFloat(parcel, ao);
        case VALUE_TYPE_DOUBLEARRAY:
            return ReadFromParcelArrayDouble(parcel, ao);
        default:
            break;
    }

    return true;
}

bool DistributedWantParams::ReadFromParcelString(Parcel& parcel, const std::string& key)
{
    std::u16string value = parcel.ReadString16();
    std::string strValue(Str16ToStr8(value));
    sptr<IInterface> intf = AAFwk::String::Box(Str16ToStr8(value));
    if (intf) {
        SetParam(key, intf);
    }
    return true;
}

bool DistributedWantParams::ReadFromParcelBool(Parcel& parcel, const std::string& key)
{
    int8_t value;
    if (parcel.ReadInt8(value)) {
        sptr<IInterface> intf = AAFwk::Boolean::Box(value);
        if (intf) {
            SetParam(key, intf);
        }
        return true;
    } else {
        return false;
    }
}

bool DistributedWantParams::ReadFromParcelInt8(Parcel& parcel, const std::string& key)
{
    int8_t value;
    if (parcel.ReadInt8(value)) {
        sptr<IInterface> intf = AAFwk::Byte::Box(value);
        if (intf) {
            SetParam(key, intf);
        }
        return true;
    } else {
        return false;
    }
}

bool DistributedWantParams::ReadFromParcelChar(Parcel& parcel, const std::string& key)
{
    int32_t value;
    if (parcel.ReadInt32(value)) {
        sptr<IInterface> intf = AAFwk::Char::Box(value);
        if (intf) {
            SetParam(key, intf);
        }
        return true;
    } else {
        return false;
    }
}

bool DistributedWantParams::ReadFromParcelShort(Parcel& parcel, const std::string& key)
{
    short value;
    if (parcel.ReadInt16(value)) {
        sptr<IInterface> intf = AAFwk::Short::Box(value);
        if (intf) {
            SetParam(key, intf);
        }
        return true;
    } else {
        return false;
    }
}

bool DistributedWantParams::ReadFromParcelInt(Parcel& parcel, const std::string& key)
{
    int value;
    if (parcel.ReadInt32(value)) {
        sptr<IInterface> intf = AAFwk::Integer::Box(value);
        if (intf) {
            SetParam(key, intf);
        }
        return true;
    } else {
        return false;
    }
}

bool DistributedWantParams::ReadFromParcelWantParamWrapper(Parcel& parcel, const std::string& key, int type)
{
    if (type == VALUE_TYPE_FD) {
        return ReadFromParcelFD(parcel, key);
    }

    if (type == VALUE_TYPE_REMOTE_OBJECT) {
        return ReadFromParcelRemoteObject(parcel, key);
    }

    std::u16string value = parcel.ReadString16();
    sptr<IInterface> intf = DistributedWantParamWrapper::Parse(Str16ToStr8(value));
    if (intf) {
        SetParam(key, intf);
    }
    return true;
}

bool DistributedWantParams::ReadFromParcelFD(Parcel& parcel, const std::string& key)
{
    auto messageParcel = static_cast<MessageParcel*>(&parcel);
    auto fd = messageParcel->ReadFileDescriptor();
    DistributedWantParams wp;
    wp.SetParam(TYPE_PROPERTY, AAFwk::String::Box(FD));
    wp.SetParam(VALUE_PROPERTY, AAFwk::Integer::Box(fd));
    sptr<IDistributedWantParams> pWantParams = DistributedWantParamWrapper::Box(wp);
    SetParam(key, pWantParams);
    return true;
}

bool DistributedWantParams::ReadFromParcelRemoteObject(Parcel& parcel, const std::string& key)
{
    auto messageParcel = static_cast<MessageParcel*>(&parcel);
    auto remoteObject = messageParcel->ReadRemoteObject();
    DistributedWantParams wp;
    wp.SetParam(TYPE_PROPERTY, AAFwk::String::Box(REMOTE_OBJECT));
    wp.SetParam(VALUE_PROPERTY, AAFwk::RemoteObjectWrap::Box(remoteObject));
    sptr<IDistributedWantParams> pWantParams = DistributedWantParamWrapper::Box(wp);
    SetParam(key, pWantParams);
    return true;
}

bool DistributedWantParams::ReadFromParcelLong(Parcel& parcel, const std::string& key)
{
    int64_t value;
    if (parcel.ReadInt64(value)) {
        std::string strValue(std::to_string(value));
#ifdef WANT_PARAM_USE_LONG
        sptr<IInterface> intf = Long::Box(value);
#else
        sptr<IInterface> intf = AAFwk::String::Box(std::to_string(value));
#endif
        if (intf) {
            SetParam(key, intf);
        }
        return true;
    } else {
        return false;
    }
}

bool DistributedWantParams::ReadFromParcelFloat(Parcel& parcel, const std::string& key)
{
    float value;
    if (parcel.ReadFloat(value)) {
        sptr<IInterface> intf = AAFwk::Float::Box(value);
        if (intf) {
            SetParam(key, intf);
        }
        return true;
    } else {
        return false;
    }
}

bool DistributedWantParams::ReadFromParcelDouble(Parcel& parcel, const std::string& key)
{
    double value;
    if (parcel.ReadDouble(value)) {
        sptr<IInterface> intf = AAFwk::Double::Box(value);
        if (intf) {
            SetParam(key, intf);
        }
        return true;
    } else {
        return false;
    }
}

bool DistributedWantParams::ReadUnsupportedData(Parcel& parcel, const std::string& key, int type)
{
    int bufferSize = 0;
    if (!parcel.ReadInt32(bufferSize)) {
        return false;
    }
    static constexpr int32_t maxAllowedSize = 100 * 1024 * 1024;
    if (bufferSize < 0 || bufferSize > maxAllowedSize) {
        return false;
    }

    int32_t length = 0;
    if (!parcel.ReadInt32(length)) {
        return false;
    }
    const uint8_t* bufferP = parcel.ReadUnpadBuffer(bufferSize);
    if (bufferP == nullptr) {
        return false;
    }

    DistributedUnsupportedData data;
    data.key = Str8ToStr16(key);
    data.type = type;
    data.size = bufferSize;
    data.buffer = new (std::nothrow) uint8_t[bufferSize];
    if (data.buffer == nullptr) {
        return false;
    }

    if (memcpy_s(data.buffer, bufferSize, bufferP, bufferSize) != EOK) {
        return false;
    }
    cachedUnsupportedData_.emplace_back(std::move(data));
    return true;
}

bool DistributedWantParams::ReadFromParcelParam(Parcel& parcel, const std::string& key, int type)
{
    switch (type) {
        case VALUE_TYPE_CHARSEQUENCE:
        case VALUE_TYPE_STRING:
            return ReadFromParcelString(parcel, key);
        case VALUE_TYPE_BOOLEAN:
            return ReadFromParcelBool(parcel, key);
        case VALUE_TYPE_BYTE:
            return ReadFromParcelInt8(parcel, key);
        case VALUE_TYPE_CHAR:
            return ReadFromParcelChar(parcel, key);
        case VALUE_TYPE_SHORT:
            return ReadFromParcelShort(parcel, key);
        case VALUE_TYPE_INT:
            return ReadFromParcelInt(parcel, key);
        case VALUE_TYPE_LONG:
            return ReadFromParcelLong(parcel, key);
        case VALUE_TYPE_FLOAT:
            return ReadFromParcelFloat(parcel, key);
        case VALUE_TYPE_DOUBLE:
            return ReadFromParcelDouble(parcel, key);
        case VALUE_TYPE_WANTPARAMS:
        case VALUE_TYPE_FD:
        case VALUE_TYPE_REMOTE_OBJECT:
            return ReadFromParcelWantParamWrapper(parcel, key, type);
        case VALUE_TYPE_NULL:
            break;
        case VALUE_TYPE_PARCELABLE:
        case VALUE_TYPE_PARCELABLEARRAY:
        case VALUE_TYPE_SERIALIZABLE:
        case VALUE_TYPE_LIST:
            if (!ReadUnsupportedData(parcel, key, type)) {
                return false;
            }
            break;
        default: {
            sptr<AAFwk::IArray> ao = nullptr;
            if (!ReadArrayToParcel(parcel, type, ao)) {
                return false;
            }
            sptr<IInterface> intf = ao;
            if (intf) {
                SetParam(key, intf);
            }
            break;
        }
    }
    return true;
}

bool DistributedWantParams::ReadFromParcel(Parcel& parcel)
{
    int32_t size;
    if (!parcel.ReadInt32(size)) {
        return false;
    }
    for (int32_t i = 0; i < size; i++) {
        std::u16string key = parcel.ReadString16();
        int type;
        if (!parcel.ReadInt32(type)) {
            return false;
        }
        if (!ReadFromParcelParam(parcel, Str16ToStr8(key), type)) {
            return false;
        }
    }
    return true;
}

DistributedWantParams* DistributedWantParams::Unmarshalling(Parcel& parcel)
{
    DistributedWantParams* wantParams = new (std::nothrow) DistributedWantParams();
    if (wantParams != nullptr && !wantParams->ReadFromParcel(parcel)) {
        delete wantParams;
        wantParams = nullptr;
    }
    return wantParams;
}

AAFwk::WantParams DistributedWantParams::ToWantParams()
{
    AAFwk::WantParams wantParams;
    std::map<std::string, sptr<IInterface>> data = GetParams();
    for (auto it = data.begin(); it != data.end(); it++) {
        wantParams.SetParam(it->first, it->second);
    }
    return wantParams;
}
} // namespace DistributedSchedule
} // namespace OHOS
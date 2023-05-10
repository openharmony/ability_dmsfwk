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
#ifndef OHOS_AAFWK_DISTRIBUTED_WANT_PARAMS_H
#define OHOS_AAFWK_DISTRIBUTED_WANT_PARAMS_H

#include <iostream>
#include <map>
#include <set>
#include <vector>
#include "base_interfaces.h"
#include "parcel.h"
#include "refbase.h"

namespace OHOS {
namespace AAFwk {
class DistributedUnsupportedData {
public:
    std::u16string key;
    int type = 0;
    int size = 0;
    uint8_t *buffer = nullptr;

    ~DistributedUnsupportedData();

    DistributedUnsupportedData();
    DistributedUnsupportedData(const DistributedUnsupportedData& other);
    DistributedUnsupportedData(DistributedUnsupportedData&& other);

    DistributedUnsupportedData& operator=(const DistributedUnsupportedData& other);
    DistributedUnsupportedData& operator=(DistributedUnsupportedData&& other);
};

class DistributedWantParams final : public Parcelable {
public:
    DistributedWantParams() = default;
    DistributedWantParams(const DistributedWantParams& wantParams);
    inline ~DistributedWantParams()
    {}
    DistributedWantParams& operator=(const DistributedWantParams& other);

    bool operator==(const DistributedWantParams& other);

    static sptr<IInterface> GetInterfaceByType(int typeId, const std::string& value);

    static bool CompareInterface(const sptr<IInterface> iIt1, const sptr<IInterface> iIt2, int typeId);

    static int GetDataType(const sptr<IInterface> iIt);

    static std::string GetStringByType(const sptr<IInterface> iIt, int typeId);

    void SetParam(const std::string& key, IInterface* value);

    sptr<IInterface> GetParam(const std::string& key) const;

    const std::map<std::string, sptr<IInterface>>& GetParams() const;

    const std::set<std::string> KeySet() const;

    void Remove(const std::string& key);

    bool HasParam(const std::string& key) const;

    int Size() const;

    bool IsEmpty() const;

    virtual bool Marshalling(Parcel& parcel) const;

    static DistributedWantParams* Unmarshalling(Parcel& parcel);

    void DumpInfo(int level) const;

private:
    enum {
        VALUE_TYPE_NULL = -1,
        VALUE_TYPE_BOOLEAN = 1,
        VALUE_TYPE_BYTE = 2,
        VALUE_TYPE_CHAR = 3,
        VALUE_TYPE_SHORT = 4,
        VALUE_TYPE_INT = 5,
        VALUE_TYPE_LONG = 6,
        VALUE_TYPE_FLOAT = 7,
        VALUE_TYPE_DOUBLE = 8,
        VALUE_TYPE_STRING = 9,
        VALUE_TYPE_CHARSEQUENCE = 10,
        VALUE_TYPE_BOOLEANARRAY = 11,
        VALUE_TYPE_BYTEARRAY = 12,
        VALUE_TYPE_CHARARRAY = 13,
        VALUE_TYPE_SHORTARRAY = 14,
        VALUE_TYPE_INTARRAY = 15,
        VALUE_TYPE_LONGARRAY = 16,
        VALUE_TYPE_FLOATARRAY = 17,
        VALUE_TYPE_DOUBLEARRAY = 18,
        VALUE_TYPE_STRINGARRAY = 19,
        VALUE_TYPE_CHARSEQUENCEARRAY = 20,

        VALUE_TYPE_PARCELABLE = 21,
        VALUE_TYPE_PARCELABLEARRAY = 22,
        VALUE_TYPE_SERIALIZABLE = 23,
        VALUE_TYPE_LIST = 50,

        VALUE_TYPE_WANTPARAMS = 101,
        VALUE_TYPE_ARRAY = 102,
    };

    bool WriteArrayToParcel(Parcel& parcel, IArray* ao) const;
    bool ReadArrayToParcel(Parcel& parcel, int type, sptr<IArray>& ao);
    bool ReadFromParcel(Parcel& parcel);
    bool ReadFromParcelParam(Parcel& parcel, const std::string& key, int type);
    bool ReadFromParcelString(Parcel& parcel, const std::string& key);
    bool ReadFromParcelBool(Parcel& parcel, const std::string& key);
    bool ReadFromParcelInt8(Parcel& parcel, const std::string& key);
    bool ReadFromParcelChar(Parcel& parcel, const std::string& key);
    bool ReadFromParcelShort(Parcel& parcel, const std::string& key);
    bool ReadFromParcelInt(Parcel& parcel, const std::string& key);
    bool ReadFromParcelLong(Parcel& parcel, const std::string& key);
    bool ReadFromParcelFloat(Parcel& parcel, const std::string& key);
    bool ReadFromParcelDouble(Parcel& parcel, const std::string& key);

    bool ReadFromParcelArrayString(Parcel& parcel, sptr<IArray>& ao);
    bool ReadFromParcelArrayBool(Parcel& parcel, sptr<IArray>& ao);
    bool ReadFromParcelArrayByte(Parcel& parcel, sptr<IArray>& ao);
    bool ReadFromParcelArrayChar(Parcel& parcel, sptr<IArray>& ao);
    bool ReadFromParcelArrayShort(Parcel& parcel, sptr<IArray>& ao);

    bool ReadFromParcelArrayInt(Parcel& parcel, sptr<IArray>& ao);
    bool ReadFromParcelArrayLong(Parcel& parcel, sptr<IArray>& ao);
    bool ReadFromParcelArrayFloat(Parcel& parcel, sptr<IArray>& ao);
    bool ReadFromParcelArrayDouble(Parcel& parcel, sptr<IArray>& ao);
    bool ReadFromParcelWantParamWrapper(Parcel& parcel, const std::string& key);

    bool WriteArrayToParcelString(Parcel& parcel, IArray* ao) const;
    bool WriteArrayToParcelBool(Parcel& parcel, IArray* ao) const;
    bool WriteArrayToParcelByte(Parcel& parcel, IArray* ao) const;
    bool WriteArrayToParcelChar(Parcel& parcel, IArray* ao) const;
    bool WriteArrayToParcelShort(Parcel& parcel, IArray* ao) const;
    bool WriteArrayToParcelInt(Parcel& parcel, IArray* ao) const;
    bool WriteArrayToParcelLong(Parcel& parcel, IArray* ao) const;
    bool WriteArrayToParcelFloat(Parcel& parcel, IArray* ao) const;
    bool WriteArrayToParcelDouble(Parcel& parcel, IArray* ao) const;

    bool WriteMarshalling(Parcel& parcel, sptr<IInterface>& o) const;
    bool WriteToParcelString(Parcel& parcel, sptr<IInterface>& o) const;
    bool WriteToParcelBool(Parcel& parcel, sptr<IInterface>& o) const;
    bool WriteToParcelByte(Parcel& parcel, sptr<IInterface>& o) const;
    bool WriteToParcelChar(Parcel& parcel, sptr<IInterface>& o) const;
    bool WriteToParcelShort(Parcel& parcel, sptr<IInterface>& o) const;
    bool WriteToParcelInt(Parcel& parcel, sptr<IInterface>& o) const;
    bool WriteToParcelLong(Parcel& parcel, sptr<IInterface>& o) const;
    bool WriteToParcelFloat(Parcel& parcel, sptr<IInterface>& o) const;
    bool WriteToParcelDouble(Parcel& parcel, sptr<IInterface>& o) const;
    bool WriteToParcelWantParams(Parcel& parcel, sptr<IInterface>& o) const;

    bool DoMarshalling(Parcel& parcel) const;
    bool ReadUnsupportedData(Parcel& parcel, const std::string& key, int type);

    friend class DistributedWantParamWrapper;
    friend class DistributedWant;
    // inner use function
    bool NewArrayData(IArray* source, sptr<IArray>& dest);
    bool NewParams(const DistributedWantParams& source, DistributedWantParams& dest);
    std::map<std::string, sptr<IInterface>> params_;
    std::vector<DistributedUnsupportedData> cachedUnsupportedData_;
};
}  // namespace AAFwk
}  // namespace OHOS

#endif  // OHOS_AAFWK_DISTRIBUTED_WANT_PARAMS_H
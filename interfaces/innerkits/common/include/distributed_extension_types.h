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

#ifndef OHOS_DISTRIBUTED_EXTENSION_TYPES_H
#define OHOS_DISTRIBUTED_EXTENSION_TYPES_H

#include <string>

#include "iremote_object.h"
#include "parcel.h"

namespace OHOS {
namespace DistributedSchedule {
struct DExtSourceInfo : public Parcelable {
    std::string deviceId;
    std::string networkId;
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;

    DExtSourceInfo() = default;
    DExtSourceInfo(std::string deviceId, std::string networkId, std::string bundleName, std::string moduleName,
        std::string abilityName)
        : deviceId(deviceId), networkId(networkId), bundleName(bundleName), moduleName(moduleName),
          abilityName(abilityName) {}
    
    bool ReadFromParcel(Parcel &parcel)
    {
        deviceId = parcel.ReadString();
        networkId = parcel.ReadString();
        bundleName = parcel.ReadString();
        moduleName = parcel.ReadString();
        abilityName = parcel.ReadString();
        return true;
    }

    virtual bool Marshalling(Parcel &parcel) const override
    {
        if (!parcel.WriteString(deviceId)) {
            return false;
        }
        if (!parcel.WriteString(networkId)) {
            return false;
        }
        if (!parcel.WriteString(bundleName)) {
            return false;
        }
        if (!parcel.WriteString(moduleName)) {
            return false;
        }
        if (!parcel.WriteString(abilityName)) {
            return false;
        }
        return true;
    }

    static DExtSourceInfo *Unmarshalling(Parcel &parcel)
    {
        DExtSourceInfo *info = new (std::nothrow) DExtSourceInfo();
        if (info == nullptr) {
            return nullptr;
        }

        if (!info->ReadFromParcel(parcel)) {
            delete info;
            info = nullptr;
        }
        return info;
    }
};

struct DExtSinkInfo : public Parcelable {
    int32_t userId = -1;
    int32_t pid = -1;
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string serviceName;

    DExtSinkInfo() = default;
    DExtSinkInfo(int32_t userId, int32_t pid, std::string bundleName, std::string moduleName,
        std::string abilityName, std::string serviceName)
        : userId(userId), pid(pid), bundleName(bundleName), moduleName(moduleName),
          abilityName(abilityName), serviceName(serviceName) {}
    
    bool IsEmpty() const
    {
        return bundleName.empty() && moduleName.empty() && abilityName.empty() && serviceName.empty();
    }
    bool ReadFromParcel(Parcel &parcel)
    {
        pid = parcel.ReadInt32();
        userId = parcel.ReadInt32();
        bundleName = parcel.ReadString();
        moduleName = parcel.ReadString();
        abilityName = parcel.ReadString();
        serviceName = parcel.ReadString();
        return true;
    }

    virtual bool Marshalling(Parcel &parcel) const override
    {
        if (!parcel.WriteInt32(pid)) {
            return false;
        }
        if (!parcel.WriteInt32(userId)) {
            return false;
        }
        if (!parcel.WriteString(bundleName)) {
            return false;
        }
        if (!parcel.WriteString(moduleName)) {
            return false;
        }
        if (!parcel.WriteString(abilityName)) {
            return false;
        }
        if (!parcel.WriteString(serviceName)) {
            return false;
        }
        return true;
    }

    static DExtSinkInfo *Unmarshalling(Parcel &parcel)
    {
        DExtSinkInfo *info = new (std::nothrow) DExtSinkInfo();
        if (info == nullptr) {
            return nullptr;
        }

        if (!info->ReadFromParcel(parcel)) {
            delete info;
            info = nullptr;
        }
        return info;
    }
};

enum class DExtConnectResult : int32_t {
    SUCCESS = 0,
    FAILED = 1,
    PERMISSION_DENIED = 2,
    TIMEOUT = 3,
};

struct DExtConnectInfo : public Parcelable {
    DExtSourceInfo sourceInfo;
    DExtSinkInfo sinkInfo;
    std::string tokenId;
    std::string delegatee;

    DExtConnectInfo() = default;
    DExtConnectInfo(DExtSourceInfo sourceInfo, DExtSinkInfo sinkInfo, std::string tokenId, std::string delegatee)
        : sourceInfo(sourceInfo), sinkInfo(sinkInfo), tokenId(tokenId), delegatee(delegatee) {}

    bool ReadFromParcel(Parcel &parcel)
    {
        if (!sourceInfo.ReadFromParcel(parcel)) {
            return false;
        }
        if (!sinkInfo.ReadFromParcel(parcel)) {
            return false;
        }
        tokenId = parcel.ReadString();
        delegatee = parcel.ReadString();
        return true;
    }

    virtual bool Marshalling(Parcel &parcel) const override
    {
        if (!sourceInfo.Marshalling(parcel)) {
            return false;
        }
        if (!sinkInfo.Marshalling(parcel)) {
            return false;
        }
        if (!parcel.WriteString(tokenId)) {
            return false;
        }
        if (!parcel.WriteString(delegatee)) {
            return false;
        }
        return true;
    }

    static DExtConnectInfo *Unmarshalling(Parcel &parcel)
    {
        DExtConnectInfo *info = new (std::nothrow) DExtConnectInfo();
        if (info == nullptr) {
            return nullptr;
        }

        if (!info->ReadFromParcel(parcel)) {
            delete info;
            info = nullptr;
        }
        return info;
    }
};

struct DExtConnectResultInfo : public Parcelable {
    DExtConnectInfo connectInfo;
    DExtConnectResult result { OHOS::DistributedSchedule::DExtConnectResult::FAILED };
    int32_t errCode { 0 };

    DExtConnectResultInfo() = default;
    DExtConnectResultInfo(DExtConnectInfo connectInfo, DExtConnectResult result, int32_t errCode)
        : connectInfo(connectInfo), result(result), errCode(errCode) {}

    bool ReadFromParcel(Parcel &parcel)
    {
        if (!connectInfo.ReadFromParcel(parcel)) {
            return false;
        }
        result = static_cast<DExtConnectResult>(parcel.ReadInt32());
        errCode = parcel.ReadInt32();
        return true;
    }

    virtual bool Marshalling(Parcel &parcel) const override
    {
        if (!connectInfo.Marshalling(parcel)) {
            return false;
        }
        if (!parcel.WriteInt32(static_cast<int32_t>(result))) {
            return false;
        }
        if (!parcel.WriteInt32(errCode)) {
            return false;
        }
        return true;
    }

    static DExtConnectResultInfo *Unmarshalling(Parcel &parcel)
    {
        DExtConnectResultInfo *info = new (std::nothrow) DExtConnectResultInfo();
        if (info == nullptr) {
            return nullptr;
        }

        if (!info->ReadFromParcel(parcel)) {
            delete info;
            info = nullptr;
        }
        return info;
    }
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_EXTENSION_TYPES_H
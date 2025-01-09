/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ability_connection_info.h"

#include "dtbschedmgr_log.h"
#include "parcel_helper.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
const std::string TAG = "collabSessionInfo";
}

bool PeerInfo::ReadFromParcel(Parcel &parcel)
{
    deviceId = Str16ToStr8(parcel.ReadString16());
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    abilityName = Str16ToStr8(parcel.ReadString16());
    serverId = Str16ToStr8(parcel.ReadString16());
    return true;
}

bool PeerInfo::Marshalling(Parcel &parcel) const
{
    parcel.WriteString16(Str8ToStr16(deviceId));
    parcel.WriteString16(Str8ToStr16(bundleName));
    parcel.WriteString16(Str8ToStr16(moduleName));
    parcel.WriteString16(Str8ToStr16(abilityName));
    parcel.WriteString16(Str8ToStr16(serverId));
    return true;
}

PeerInfo *PeerInfo::Unmarshalling(Parcel &parcel)
{
    PeerInfo *info = new (std::nothrow) PeerInfo();
    if (info != nullptr && !info->ReadFromParcel(parcel)) {
        HILOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool ConnectOption::ReadFromParcel(Parcel &parcel)
{
    needSendData = parcel.ReadBool();
    needSendStream = parcel.ReadBool();
    needReceiveStream = parcel.ReadBool();
    auto optionsPtr = parcel.ReadParcelable<AAFwk::WantParams>();
    if (optionsPtr) {
        options = *optionsPtr;
    }
    auto parametersPtr = parcel.ReadParcelable<AAFwk::WantParams>();
    if (parametersPtr) {
        parameters = *parametersPtr;
    }
    return true;
}

bool ConnectOption::Marshalling(Parcel &parcel) const
{
    parcel.WriteBool(needSendData);
    parcel.WriteBool(needSendStream);
    parcel.WriteBool(needReceiveStream);
    parcel.WriteParcelable(&options);
    parcel.WriteParcelable(&parameters);
    return true;
}

ConnectOption *ConnectOption::Unmarshalling(Parcel &parcel)
{
    ConnectOption *opt = new (std::nothrow) ConnectOption();
    if (opt != nullptr && !opt->ReadFromParcel(parcel)) {
        HILOGE("read from parcel failed");
        delete opt;
        opt = nullptr;
    }
    return opt;
}
}  // namespace DistributedCollab
}  // namespace OHOS
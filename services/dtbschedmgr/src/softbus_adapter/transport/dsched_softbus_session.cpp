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

#include "dsched_softbus_session.h"

#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
DSchedSoftbusSession::DSchedSoftbusSession()
{
    sessionId_ = 0;
    refCount_ = 0;
    isServer_ = false;
    maxSendBytesSize_ = 0;
    maxQos_ = 0;
}

DSchedSoftbusSession::~DSchedSoftbusSession()
{
}

int32_t DSchedSoftbusSession::HandleBytesReceived(int32_t sessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    return ERR_OK;
}

int32_t DSchedSoftbusSession::SendData(std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    return ERR_OK;
}

void DSchedSoftbusSession::PackRecvData(std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
}

void DSchedSoftbusSession::AssembleNoFrag(std::shared_ptr<DSchedDataBuffer> buffer, SessionDataHeader& headerPara)
{
}

void DSchedSoftbusSession::AssembleFrag(std::shared_ptr<DSchedDataBuffer> buffer, SessionDataHeader& headerPara)
{
}

int32_t DSchedSoftbusSession::UnPackSendData(std::shared_ptr<DSchedDataBuffer> buffer)
{
    return ERR_OK;
}
}  // namespace DistributedSchedule
}  // namespace OHOS
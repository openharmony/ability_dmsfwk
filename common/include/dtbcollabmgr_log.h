/*
* Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef SERVICES_DTBCOLLABMGR_INCLUDE_DTBCOLLABMGR_LOG_H_
#define SERVICES_DTBCOLLABMGR_INCLUDE_DTBCOLLABMGR_LOG_H_

#include "errors.h"
#include "hilog/log.h"
#include "inttypes.h"

namespace OHOS {
namespace DistributedCollab {
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD004170

#undef LOG_TAG
#define LOG_TAG "DSched_Service"

#ifdef HILOGD
#undef HILOGD
#endif

#ifdef HILOGF
#undef HILOGF
#endif

#ifdef HILOGE
#undef HILOGE
#endif

#ifdef HILOGW
#undef HILOGW
#endif

#ifdef HILOGI
#undef HILOGI
#endif

#define HILOGF(fmt, ...) HILOG_FATAL(LOG_CORE, "%{public}s::%{public}s " fmt, TAG.c_str(), __FUNCTION__, ##__VA_ARGS__)
#define HILOGE(fmt, ...) HILOG_ERROR(LOG_CORE, "%{public}s::%{public}s " fmt, TAG.c_str(), __FUNCTION__, ##__VA_ARGS__)
#define HILOGW(fmt, ...) HILOG_WARN(LOG_CORE, "%{public}s::%{public}s " fmt, TAG.c_str(), __FUNCTION__, ##__VA_ARGS__)
#define HILOGI(fmt, ...) HILOG_INFO(LOG_CORE, "%{public}s::%{public}s " fmt, TAG.c_str(), __FUNCTION__, ##__VA_ARGS__)
#define HILOGD(fmt, ...) HILOG_DEBUG(LOG_CORE, "%{public}s::%{public}s " fmt, TAG.c_str(), __FUNCTION__, ##__VA_ARGS__)

enum {
    /**
     * Module type: Distributed schedule Service side
     */
    DMS_COLLAB_MODULE_TYPE_SERVICE = 1,
};

// offset of dms error, only be used in this file.
constexpr ErrCode DMS_SERVICE_ERR_OFFSET = ErrCodeOffset(SUBSYS_DISTRIBUTEDSCHEDULE, DMS_COLLAB_MODULE_TYPE_SERVICE);

enum DmsInterfaceSdkErr {
    /**
     * Result(16300501) for the distributed sched work abnormally.
     */
    ERR_DMS_WORK_ABNORMALLY = 16300501,
    /**
     * Result(16300503) throw to js for the application is not installed on the remote end and installation-free is
     * not supported.
     */
    ERR_REMOTE_UNINSTALLED_AND_UNFREEINSTALL = 16300503,
    /**
     * Result(16300504) throw to js for the application is not installed on the remote end but installation-free is
     * supported, try again with freeInstall flag.
     */
    ERR_CONTINUE_WITHOUT_FREEINSTALL_FLAG = 16300504,
    /**
     * Result(16300506) throw to js for the local continuation task is already in progress.
     */
    ERR_CONTINUE_ALREADY_IN_PROGRESS = 16300506,
    /**
     * Result(16300507) throw to js for Failed to get the missionInfo of the specified bundle name.
     */
    ERR_GET_MISSION_INFO_OF_BUNDLE_NAME = 16300507,
    /**
     * Result(16300508) throw to js for bind error due to the remote device hotspot enable, try again after disable
     * the remote device hotspot.
     */
    ERR_BIND_REMOTE_HOTSPOT_ENABLE_STATE = 16300508,
    /**
     * Result(16300509) throw to js for the remote device has been linked with other devices, try again when
     * the remote device is idle.
     */
    ERR_BIND_REMOTE_IN_BUSY_LINK = 16300509,
};

/**
 * @brief error code for distribute collab
 *
 */
enum {
    /**
     * @brief Result 29425664 for distribute collab error start
     *
     */
    INVALID_PARAMETERS_ERR = DMS_SERVICE_ERR_OFFSET,

    NULL_POINTER_ERROR,

    CREATE_SOCKET_FAILED,

    LISTEN_SOCKET_FAILED,

    BIND_SOCKET_FAILED,

    NULL_EVENT_HANDLER,

    POST_TASK_FAILED,

    NO_SUCH_LOCK,

    NO_SUCH_DATA_TYPE,

    NO_SUCH_CHANNEL,

    CHANNEL_NUM_EXCEED_LIMIT,

    CREATE_SERVER_CHANNEL_FAILED,

    CREATE_CLIENT_CHANNEL_FAILED,

    INVALID_CHANNEL_ID,

    INVALID_CHANNEL_TYPE,

    INVALID_CHANNEL_NAME,

    INVALID_LISTENER,

    INVALID_SOCKET_ID,

    INVALID_SOCKET_NAME,

    NO_CONNECTED_SOCKET_ID,

    CONNECT_CHANNEL_FAILED,

    RECV_DATA_EMPTY,

    COPY_DATA_TO_BUFFER_FAILED,

    WRITE_TLV_ITEM_TO_BUFFER_FAILED,

    READ_TLV_ITEM_FROM_BUFFER_FAILED,

    GET_SESSION_OPTION_FAILED,

    WRITE_SESSION_HEADER_FAILED,

    WRITE_SEND_DATA_BUFFER_FAILED,

    SEND_DATA_BY_SOFTBUS_FAILED,

    DATA_SIZE_EXCEED_LIMIT,

    INVALID_SESSION_HEADER,

    INVALID_SESSION_HEADER_FLAG_TYPE,

    INVALID_SESSION_HEADER_TOTAL_LEN,

    INVALID_SESSION_HEADER_SEQ_NUM,

    INVALID_SESSION_HEADER_SUB_SEQ,

    WRITE_PAYLOAD_TO_BUFFER_FAILED,

    FLAG_TYPE_NOT_MATCH_BUFFER_STATE,

    PARSE_AV_TRANS_STREAM_EXT_FAILED,

    GET_SERIALIZED_DATA_FAILED,

    READ_SURFACE_BUFFER_FAILED,

    CREATE_SURFACE_FAILED,

    DMS_PERMISSION_DENIED,

    ERR_IS_NOT_SYSTEM_APP,

    ERR_INVALID_PARAMETERS,

    ONLY_SUPPORT_ONE_STREAM,

    RECEIVE_STREAM_NOT_START,

    ERR_EXECUTE_FUNCTION,

    STREAM_CHANNEL_NOT_EXITS,

    CONNECT_MESSAGE_CHANNEL_FAILED,

    CONNECT_DATA_CHANNEL_FAILED,

    CONNECT_STREAM_BYTES_CHANNEL_FAILED,

    ERR_JSON_GENERATION_FAILED,

    REGISTER_FILE_SCHEMA_FAILED,

    INVALID_FILE_NAME,

    CREATE_DIR_FAILED,

    FAILED_TO_CREATE_MESSAGE_CHANNEL,

    FAILED_TO_CREATE_DATA_CHANNEL,

    FAILED_TO_CREATE_STREAM_CHANNEL,

    FAILED_TO_CREATE_SEND_FILE_CHANNEL,

    FAILED_TO_CREATE_RECEIVE_FILE_CHANNEL,

    CONNECT_STREAM_CHANNEL_FAILED,

    CONNECT_SEND_FILE_CHANNEL_FAILED,

    SAME_SESSION_IS_CONNECTING,

    INVALID_SESSION_ID,
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif

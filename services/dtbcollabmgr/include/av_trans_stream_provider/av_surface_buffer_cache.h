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
#ifndef OHOS_AV_TRANS_STREAM_AV_SURFACE_BUFFER_CACHE_H
#define OHOS_AV_TRANS_STREAM_AV_SURFACE_BUFFER_CACHE_H

#include "av_trans_data_buffer.h"
#include "ibuffer_consumer_listener.h"
#include "iconsumer_surface.h"
#include "surface_type.h"
#include "surface_utils.h"
#include <atomic>
#include <mutex>
#include <queue>
#include <thread>

namespace OHOS {
namespace DistributedCollab {
class AVSurfaceBufferCache : public std::enable_shared_from_this<AVSurfaceBufferCache> {
public:
    AVSurfaceBufferCache(const sptr<Surface>& surface)
        : outputSurface_(surface) {};
    ~AVSurfaceBufferCache();
    void Init();
    void Start();
    void Stop();
    int32_t GetSurface(sptr<Surface>& surface);

private:
    struct Cache {
        std::unique_ptr<AVTransDataBuffer> data_ = nullptr;
        BufferRequestConfig config_;
        uint32_t index_ = 0;
    };

    class SurfaceListener : public IBufferConsumerListener {
    public:
        SurfaceListener(const sptr<Surface>& surface,
            const std::shared_ptr<AVSurfaceBufferCache>& cache)
            : surface_(surface)
            , cache_(cache) {};
        void OnBufferAvailable() override;

    private:
        wptr<Surface> surface_;
        std::weak_ptr<AVSurfaceBufferCache> cache_ ;
    };

private:
    void AddCache(std::unique_ptr<AVTransDataBuffer>& data, BufferRequestConfig& config);
    int32_t AddSurfaceBuffer(const sptr<SurfaceBuffer>& buffer);
    void Process();
    void WriteDataToSurface(const std::unique_ptr<Cache>& cacheData);

private:
    struct CacheCompare {
        bool operator()(const std::unique_ptr<Cache>& lhs, const std::unique_ptr<Cache>& rhs) const
        {
            return lhs->index_ > rhs->index_;
        }
    };

    std::mutex queueMutex_;
    std::priority_queue<std::unique_ptr<Cache>,
        std::vector<std::unique_ptr<Cache>>, CacheCompare>
        cacheQueue_;

    std::condition_variable cv_;
    std::atomic<bool> isRunning_ = false;
    std::thread processingThread_;
    uint32_t lastIndex_ = 0;

    sptr<Surface> outputSurface_ { nullptr };
    sptr<Surface> innerSurface_ = { nullptr };
};
} // namespace DistributedCollab
} // namespace OHOS
#endif
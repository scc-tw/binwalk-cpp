#include "task_pool.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <mutex>
#include <thread>
#include <vector>

namespace binwalk {
namespace detail {

struct task_pool::shared_state {
    std::mutex mutex;
    std::condition_variable batch_posted;
    std::condition_variable batch_drained;

    const std::function<void(std::size_t)>* body = nullptr;
    std::size_t count = 0;
    std::atomic<std::size_t> next_index{0};

    std::uint64_t batch_number = 0;
    std::size_t workers_still_running = 0;
    bool shutting_down = false;

    std::exception_ptr first_failure;
    std::vector<std::thread> workers;

    void run_until_no_indices_remain() {
        const auto& work = *body;
        for(;;) {
            const auto index = next_index.fetch_add(1, std::memory_order_relaxed);
            if(index >= count) {
                return;
            }
            work(index);
        }
    }

    void remember_current_failure() {
        std::lock_guard<std::mutex> guard(mutex);
        if(!first_failure) {
            first_failure = std::current_exception();
        }
    }
};

task_pool::task_pool(std::size_t width) : state_(std::make_shared<shared_state>()) {
    const auto helpers = width > 1 ? width - 1 : 0;
    state_->workers.reserve(helpers);

    for(std::size_t worker = 0; worker < helpers; ++worker) {
        auto state = state_;
        state_->workers.emplace_back([state] {
            std::uint64_t last_batch_joined = 0;
            for(;;) {
                std::unique_lock<std::mutex> guard(state->mutex);
                state->batch_posted.wait(guard, [&] {
                    return state->shutting_down || state->batch_number != last_batch_joined;
                });
                if(state->shutting_down) {
                    return;
                }
                last_batch_joined = state->batch_number;
                guard.unlock();

                try {
                    state->run_until_no_indices_remain();
                } catch(...) {
                    state->remember_current_failure();
                }

                guard.lock();
                if(--state->workers_still_running == 0) {
                    state->batch_drained.notify_one();
                }
            }
        });
    }
}

task_pool::~task_pool() {
    {
        std::lock_guard<std::mutex> guard(state_->mutex);
        state_->shutting_down = true;
    }
    state_->batch_posted.notify_all();
    for(auto& worker : state_->workers) {
        if(worker.joinable()) {
            worker.join();
        }
    }
}

std::size_t task_pool::width() const noexcept {
    return state_->workers.size() + 1;
}

void task_pool::run(std::size_t count, const std::function<void(std::size_t)>& body) {
    if(count == 0) {
        return;
    }
    if(state_->workers.empty()) {
        for(std::size_t index = 0; index < count; ++index) {
            body(index);
        }
        return;
    }

    {
        std::lock_guard<std::mutex> guard(state_->mutex);
        state_->body = &body;
        state_->count = count;
        state_->next_index.store(0, std::memory_order_relaxed);
        state_->workers_still_running = state_->workers.size();
        state_->first_failure = nullptr;
        ++state_->batch_number;
    }
    state_->batch_posted.notify_all();

    std::exception_ptr caller_failure;
    try {
        state_->run_until_no_indices_remain();
    } catch(...) {
        caller_failure = std::current_exception();
    }

    std::unique_lock<std::mutex> guard(state_->mutex);
    state_->batch_drained.wait(guard, [&] { return state_->workers_still_running == 0; });

    auto worker_failure = state_->first_failure;
    state_->first_failure = nullptr;
    state_->body = nullptr;
    guard.unlock();

    if(caller_failure) {
        std::rethrow_exception(caller_failure);
    }
    if(worker_failure) {
        std::rethrow_exception(worker_failure);
    }
}

}
}

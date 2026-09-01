#pragma once

#include <cstddef>
#include <functional>
#include <memory>

namespace binwalk {
namespace detail {

class task_pool {
public:
    explicit task_pool(std::size_t width);
    ~task_pool();

    task_pool(const task_pool&) = delete;
    task_pool& operator=(const task_pool&) = delete;

    [[nodiscard]] std::size_t width() const noexcept;

    void run(std::size_t count, const std::function<void(std::size_t)>& body);

private:
    struct shared_state;
    std::shared_ptr<shared_state> state_;
};

}
}

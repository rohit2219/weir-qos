// Copyright 2024 Bloomberg Finance L.P.
// Distributed under the terms of the Apache 2.0 license.

#ifndef INCLUDED_MSG_PROCESSOR
#define INCLUDED_MSG_PROCESSOR

#include <condition_variable>
#include <memory>
#include <mutex>
#include <readerwriterqueue.h>
#include <spdlog/spdlog.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <yaml-cpp/yaml.h>

#include "common.h"
#include "redis_utils.h"
#include "time_wrapper.h"

namespace syslogsrv {

namespace test {
FORWARD_DECLARE_TEST(msg_processor, connects_to_redis_on_flush_if_enough_time_has_passed_since_last_connect);
FORWARD_DECLARE_TEST(msg_processor, doesnt_connect_to_redis_on_flush_if_there_was_a_recent_connect_attempt);
FORWARD_DECLARE_TEST(redis_cmd_key, different_users_produce_different_hashes);
FORWARD_DECLARE_TEST(redis_cmd_key, different_timestamps_produce_different_hashes);
FORWARD_DECLARE_TEST(redis_cmd_key, different_categories_produce_different_hashes);
FORWARD_DECLARE_TEST(redis_cmd_key, keys_are_equivalent_when_timestamps_differ_slightly_within_a_second);
FORWARD_DECLARE_TEST(redis_cmd_key, keys_are_not_equivalent_when_timestamps_differ_slightly_across_seconds);
FORWARD_DECLARE_TEST(StsMsgProcessorTest, processStsTokenVerb_valid_input);
FORWARD_DECLARE_TEST(StsMsgProcessorTest, processStsTokenVerb_malformed_input);
FORWARD_DECLARE_TEST(StsMsgProcessorTest, processStsTokenVerb_invalid_token);
FORWARD_DECLARE_TEST(StsMsgProcessorTest, processStsTokenDataXfer_valid_input);
FORWARD_DECLARE_TEST(StsMsgProcessorTest, processStsTokenDataXfer_malformed_input);
FORWARD_DECLARE_TEST(StsMsgProcessorTest, processStsTokenDataXfer_empty_token);
FORWARD_DECLARE_TEST(StsMsgProcessorTest, processStsTokenRoleMapping_valid_input);
FORWARD_DECLARE_TEST(StsMsgProcessorTest, processStsTokenRoleMapping_missing_arn);
FORWARD_DECLARE_TEST(StsMsgProcessorTest, processStsTokenRoleMapping_missing_session_token);
class StsMsgProcessorTest;
} // namespace test

constexpr inline std::string_view DELIMITER = "~|~";
constexpr inline std::chrono::seconds STATS_LOG_INTERVAL(30);
constexpr inline int DEFAULT_STS_TOKEN_ROLE_TTL = 12 * 3600; // 12 hours, in seconds current max ttl for STS tokens

struct RawEvents {
    static constexpr const char* reqStart() { return "req~|~"; }
    static constexpr const char* reqEnd() { return "req_end~|~"; }
    static constexpr const char* dataXfer() { return "data_xfer~|~"; }
    static constexpr const char* activeReqs() { return "active_reqs~|~"; }
    static constexpr const char* stsTokenRoleMapping() { return "role_ststoken~|~"; }
    static constexpr const char* stsTokenVerb() { return "req_ststoken~|~"; }
    static constexpr const char* stsTokenReqEnd() { return "req_end_ststoken~|~"; }
    static constexpr const char* stsTokenDataXfer() { return "data_xfer_ststoken~|~"; }
    static constexpr const char* stsTokenActiveReqs() { return "active_reqs_ststoken~|~"; }
};

// Orchestrates processing of messages from HAProxy.
// A thread pulls messages off the in-memory queue, parses them and determines what
// updates to redis are necessary to action each message. These redis updates are
// aggregated and sent of to the server periodically.
class Processor {
  public:
    using FIFOList = moodycamel::BlockingReaderWriterQueue<std::string>;

    Processor(FIFOList& msg_q, const YAML::Node& config, int worker_id, const TimeWrapper& time,
              std::unique_ptr<NetInterface> net);
    ~Processor();

    Processor(const Processor&) = delete;
    Processor& operator=(const Processor&) = delete;

    // Start the internal processing threads, which process messages from the message queued given at construction.
    void start();

  private:
    FRIEND_TEST(test::msg_processor, connects_to_redis_on_flush_if_enough_time_has_passed_since_last_connect);
    FRIEND_TEST(test::msg_processor, doesnt_connect_to_redis_on_flush_if_there_was_a_recent_connect_attempt);
    FRIEND_TEST(test::redis_cmd_key, different_users_produce_different_hashes);
    FRIEND_TEST(test::redis_cmd_key, different_timestamps_produce_different_hashes);
    FRIEND_TEST(test::redis_cmd_key, different_categories_produce_different_hashes);
    FRIEND_TEST(test::redis_cmd_key, keys_are_equivalent_when_timestamps_differ_slightly_within_a_second);
    FRIEND_TEST(test::redis_cmd_key, keys_are_not_equivalent_when_timestamps_differ_slightly_across_seconds);
    FRIEND_TEST(test::StsMsgProcessorTest, processStsTokenVerb_valid_input);
    FRIEND_TEST(test::StsMsgProcessorTest, processStsTokenVerb_malformed_input);
    FRIEND_TEST(test::StsMsgProcessorTest, processStsTokenVerb_invalid_token);
    FRIEND_TEST(test::StsMsgProcessorTest, processStsTokenDataXfer_valid_input);
    FRIEND_TEST(test::StsMsgProcessorTest, processStsTokenDataXfer_malformed_input);
    FRIEND_TEST(test::StsMsgProcessorTest, processStsTokenDataXfer_empty_token);
    FRIEND_TEST(test::StsMsgProcessorTest, processStsTokenRoleMapping_valid_input);
    FRIEND_TEST(test::StsMsgProcessorTest, processStsTokenRoleMapping_missing_arn);
    FRIEND_TEST(test::StsMsgProcessorTest, processStsTokenRoleMapping_missing_session_token);
    friend class test::StsMsgProcessorTest;

    struct RedisCmdKey {
        std::string m_user;
        std::chrono::system_clock::time_point m_timestamp;
        std::string m_cat;

        bool operator==(const RedisCmdKey& other) const;
    };
    struct RedisCmdKeyHash {
        std::size_t operator()(const RedisCmdKey& k) const;
    };

    std::string m_endpoint;
    FIFOList& m_haprxy_mesg_q;
    std::shared_ptr<spdlog::logger> m_logger;
    int m_worker_id;
    const TimeWrapper m_time;

    // Example:  {"user_AKIAIOSFODNN7EXAMPLE", 1599322430, "PUT"} -> 1
    using QosRedisCommandMap = std::unordered_map<RedisCmdKey, int, RedisCmdKeyHash>;
    QosRedisCommandMap m_qos_redis_commands;

    // Example: "conn_v2_user_up_instance1234_AKIAIOSFODNN7EXAMPLE$dev.dc" -> 7
    std::unordered_map<std::string, int64_t> m_qos_redis_active_reqs;

    std::mutex m_redis_cv_mutex;
    std::condition_variable m_redis_cv;

    // RedisServerConnection is our wrapper around redis async context.
    // "Note: A redisContext is not thread-safe." in
    // https://github.com/redis/hiredis That is, only 1 thread must interact
    // with RedisServerConnection objects.
    std::unique_ptr<RedisServerConnection> m_qos_redis_conn;

    // redis data configs
    int m_redis_qos_ttl;
    int m_redis_qos_conn_ttl;

    // redis connection and commands handling
    std::chrono::seconds m_check_conn_interval;
    std::chrono::system_clock::time_point m_last_redis_connect_time;
    std::chrono::system_clock::time_point m_last_redis_flush_time;
    int m_qos_not_send_count;

    std::jthread m_msg_consumer_thread;
    std::jthread m_redis_reconnect_thread;

    // metrics batching settings - how frequently to flush data to async event loop
    int m_processor_batch_count;
    std::chrono::milliseconds m_processor_batch_flush_period;
    void setMetricsBatchingParams(const YAML::Node& config);

    // this function sends data to Qos Redis
    // verb_user_AKIAIOSFODNN7EXAMPLE_1599322752 -> { PUT = 1, GET = 2 }
    void sendToRedisQos();

    // these functions processes the req data from haproxy.
    void processReq(std::string_view raw_input);
    void processDataXfer(std::string_view raw_input);
    void processActiveRequests(std::string_view raw_input);
    void processReqEnd(std::string_view raw_input);
    void processStsTokenRoleMapping(std::string_view raw_input);
    void processStsTokenVerb(std::string_view raw_input);
    void processStsTokenDataXfer(std::string_view raw_input);
    void processStsTokenActiveReqs(std::string_view raw_input);
    void enqueueStsRoleMetric(const std::string& sts_key, int amount);

    // Consumes the HAProxy messages added into the `message_queue` by the main
    // thread (see syslog_server.cpp::msgProducerThread), turns them into commands
    // that can be forwarded to redis, and periodically sends all buffered commands
    // to redis for processing.
    void messageConsumerThread(std::stop_token stop);

    // thread to check the redis server connection periodically
    // to verify the server name still resolves into the same IP
    void checkRedisServerConnThread(std::stop_token stop);
};

} // namespace syslogsrv

#endif

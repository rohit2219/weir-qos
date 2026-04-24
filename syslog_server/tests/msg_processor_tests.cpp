// Copyright 2024 Bloomberg Finance L.P.
// Distributed under the terms of the Apache 2.0 license.

#include <memory>
#include <spdlog/sinks/stdout_sinks.h>

#include "msg_processor.h"
#include "test_common.h"
#include "time_wrapper.h"

namespace syslogsrv {
namespace test {

class MockNetInterface : public NetInterface {
  public:
    MOCK_METHOD(int, getaddrinfo, (const char*, const char*, const struct addrinfo*, struct addrinfo**), (override));
    MOCK_METHOD(void, freeaddrinfo, (addrinfo*), (override));
    MOCK_METHOD(std::string, getIpAddressBySockAddr, (const sockaddr* const saddr), (override));
    MOCK_METHOD(redisAsyncContext*, redisAsyncConnect, (const char*, int), (override));
    MOCK_METHOD(int, redisLibevAttach, (EV_P_ redisAsyncContext*), (override));
    MOCK_METHOD(void, redisAsyncDisconnect, (redisAsyncContext*), (override));
    MOCK_METHOD(int, redisAsyncCommand, (redisAsyncContext*, redisCallbackFn*, void*, const char*), (override));
    MOCK_METHOD(void, redisAsyncFree, (redisAsyncContext*), (override));
};

struct TestLogger {
    TestLogger() { spdlog::stdout_logger_mt(SERVER_NAME); }
    ~TestLogger() { spdlog::drop(SERVER_NAME); }
};

TEST(msg_processor, connects_to_redis_on_flush_if_enough_time_has_passed_since_last_connect) {
    TestLogger testlog;
    auto net = std::make_unique<testing::StrictMock<MockNetInterface>>();
    EXPECT_CALL(*net, redisAsyncFree).WillRepeatedly(testing::Return());
    EXPECT_CALL(*net, redisAsyncConnect).Times(testing::Exactly(1));

    const int check_conn_interval_sec = 30;
    const std::string config_yaml = std::string("{ redis_check_conn_interval_sec: ") +
                                    std::to_string(check_conn_interval_sec) +
                                    ", endpoint: localdev.dockerdc, redis_server: localhost:9004, redis_qos_ttl: 2, "
                                    "redis_qos_conn_ttl: 60, reqs_queue_drop_percentage_when_full: 20 }";
    Processor::FIFOList mq(1);

    std::chrono::seconds now_seconds(100);
    TimeWrapper time([&now_seconds]() { return std::chrono::system_clock::time_point(now_seconds); });

    const YAML::Node& config = YAML::Load(config_yaml);
    Processor proc(mq, config, 0, time, std::move(net));
    proc.m_redis_qos_ttl = 2;

    proc.m_qos_redis_commands[{"user_AKIAIOSFODNN7EXAMPL1", time.now(), "GET"}] = 10;
    proc.m_last_redis_connect_time = time.now();

    now_seconds += std::chrono::seconds(check_conn_interval_sec + 10);
    proc.sendToRedisQos();

    EXPECT_EQ(proc.m_qos_redis_commands.size(), 0);
}

TEST(msg_processor, doesnt_connect_to_redis_on_flush_if_there_was_a_recent_connect_attempt) {
    TestLogger testlog;
    auto net = std::make_unique<testing::StrictMock<MockNetInterface>>();
    EXPECT_CALL(*net, redisAsyncFree).WillRepeatedly(testing::Return());
    EXPECT_CALL(*net, redisAsyncConnect).Times(testing::Exactly(0));

    const int check_conn_interval_sec = 30;
    const std::string config_yaml = std::string("{ redis_check_conn_interval_sec: ") +
                                    std::to_string(check_conn_interval_sec) +
                                    ", endpoint: localdev.dockerdc, redis_server: localhost:9004, redis_qos_ttl: 2, "
                                    "redis_qos_conn_ttl: 60, reqs_queue_drop_percentage_when_full: 20 }";
    Processor::FIFOList mq(1);

    std::chrono::seconds now_seconds(100);
    TimeWrapper time([&now_seconds]() { return std::chrono::system_clock::time_point(now_seconds); });

    const YAML::Node& config = YAML::Load(config_yaml);
    Processor proc(mq, config, 0, time, std::move(net));
    proc.m_last_redis_connect_time = time.now();

    now_seconds += std::chrono::seconds(check_conn_interval_sec - 10);
    proc.sendToRedisQos();
}

TEST(redis_cmd_key, different_users_produce_different_hashes) {
    auto time_now = TimeWrapper().now();
    Processor::RedisCmdKey key1 = {"user_AKIAIOSFODNN7EXAMPL1", time_now, "GET"};
    Processor::RedisCmdKey key2 = {"user_AKIAIOSFODNN7EXAMPL2", time_now, "GET"};

    Processor::RedisCmdKeyHash hash;
    EXPECT_NE(key1, key2);
    EXPECT_NE(hash(key1), hash(key2));
}

TEST(redis_cmd_key, different_timestamps_produce_different_hashes) {
    auto time_now = TimeWrapper().now();
    Processor::RedisCmdKey key1 = {"user_AKIAIOSFODNN7EXAMPL1", time_now, "GET"};
    Processor::RedisCmdKey key2 = {"user_AKIAIOSFODNN7EXAMPL1", time_now + std::chrono::seconds(3), "GET"};

    Processor::RedisCmdKeyHash hash;
    EXPECT_NE(key1, key2);
    EXPECT_NE(hash(key1), hash(key2));
}

TEST(redis_cmd_key, different_categories_produce_different_hashes) {
    auto time_now = TimeWrapper().now();
    Processor::RedisCmdKey key1 = {"user_AKIAIOSFODNN7EXAMPL1", time_now, "GET"};
    Processor::RedisCmdKey key2 = {"user_AKIAIOSFODNN7EXAMPL1", time_now, "PUT"};

    Processor::RedisCmdKeyHash hash;
    EXPECT_NE(key1, key2);
    EXPECT_NE(hash(key1), hash(key2));
}

TEST(redis_cmd_key, keys_are_equivalent_when_timestamps_differ_slightly_within_a_second) {
    // As of C++20, system_clock is defined to count time since the unix epoch (midnight on 01/01/1970)
    // so it's guaranteed to count from the start of a second, meaning that 997ms is the same second as 987ms.
    std::chrono::system_clock::time_point time1(std::chrono::milliseconds(987));
    std::chrono::system_clock::time_point time2(std::chrono::milliseconds(997));
    Processor::RedisCmdKey key1 = {"user_AKIAIOSFODNN7EXAMPL1", time1, "GET"};
    Processor::RedisCmdKey key2 = {"user_AKIAIOSFODNN7EXAMPL1", time2, "GET"};

    Processor::RedisCmdKeyHash hash;
    EXPECT_EQ(key1, key2);
    EXPECT_EQ(hash(key1), hash(key2));
}

TEST(redis_cmd_key, keys_are_not_equivalent_when_timestamps_differ_slightly_across_seconds) {
    std::chrono::system_clock::time_point time1(std::chrono::milliseconds(997));
    std::chrono::system_clock::time_point time2(std::chrono::milliseconds(1007));
    Processor::RedisCmdKey key1 = {"user_AKIAIOSFODNN7EXAMPL1", time1, "GET"};
    Processor::RedisCmdKey key2 = {"user_AKIAIOSFODNN7EXAMPL1", time2, "GET"};

    Processor::RedisCmdKeyHash hash;
    EXPECT_NE(key1, key2);
    EXPECT_NE(hash(key1), hash(key2));
}
// Helper to create a Processor instance for STS tests
class StsMsgProcessorTest : public ::testing::Test {
  protected:
    void SetUp() override {
        logger_ = spdlog::stdout_logger_mt(std::string(SERVER_NAME) + "_sts_" + std::to_string(test_counter_++));
    }
    void TearDown() override { spdlog::drop(logger_->name()); }

    std::unique_ptr<Processor> makeProcessor() {
        auto net = std::make_unique<testing::StrictMock<MockNetInterface>>();
        EXPECT_CALL(*net, redisAsyncFree).WillRepeatedly(testing::Return());
        const std::string config_yaml = "{ redis_check_conn_interval_sec: 30, endpoint: localdev.dockerdc, "
                                        "redis_server: localhost:9004, redis_qos_ttl: 2, "
                                        "redis_qos_conn_ttl: 60, reqs_queue_drop_percentage_when_full: 20 }";
        const YAML::Node config = YAML::Load(config_yaml);
        auto proc = std::make_unique<Processor>(mq_, config, 0, time_, std::move(net));
        // Override the logger so the processor uses the test-specific one
        proc->m_logger = logger_;
        return proc;
    }

    Processor::FIFOList mq_{1};
    std::chrono::seconds now_seconds_{100};
    TimeWrapper time_{[this]() { return std::chrono::system_clock::time_point(now_seconds_); }};
    std::shared_ptr<spdlog::logger> logger_;
    static int test_counter_;
};

int StsMsgProcessorTest::test_counter_ = 0;

// --- processStsTokenVerb tests ---

TEST_F(StsMsgProcessorTest, processStsTokenVerb_valid_input) {
    auto proc = makeProcessor();
    // req_ststoken~|~1.2.3.4:58840~|~STSTOKENABCDE12345678~|~PUT~|~up~|~instance1234~|~7~|~LISTBUCKETS
    const std::string input =
        "req_ststoken~|~1.2.3.4:58840~|~STSTOKENABCDE12345678~|~PUT~|~up~|~instance1234~|~7~|~LISTBUCKETS";
    // Should not crash; currently redis commands are commented out so no observable redis state
    proc->processStsTokenVerb(input);
}

TEST_F(StsMsgProcessorTest, processStsTokenVerb_malformed_input) {
    auto proc = makeProcessor();
    // Too few tokens
    const std::string input = "req_ststoken~|~1.2.3.4:58840~|~STSTOKEN";
    proc->processStsTokenVerb(input);
    // Should log error and return without crashing
}

TEST_F(StsMsgProcessorTest, processStsTokenVerb_invalid_token) {
    auto proc = makeProcessor();
    // Token with non-printable characters
    const std::string input = "req_ststoken~|~1.2.3.4:58840~|~BAD\x01TOKEN~|~PUT~|~up~|~instance1234~|~7~|~LISTBUCKETS";
    proc->processStsTokenVerb(input);
    // Should log error about invalid token and return without crashing
}

// --- processStsTokenDataXfer tests ---

TEST_F(StsMsgProcessorTest, processStsTokenDataXfer_valid_input) {
    auto proc = makeProcessor();
    const std::string input = "data_xfer_ststoken~|~1.2.3.4:55094~|~TOKENABCDE1234567890~|~dwn~|~4096";
    proc->processStsTokenDataXfer(input);
}

TEST_F(StsMsgProcessorTest, processStsTokenDataXfer_malformed_input) {
    auto proc = makeProcessor();
    // Missing length field
    const std::string input = "data_xfer_ststoken~|~1.2.3.4:55094~|~TOKENABCDE";
    proc->processStsTokenDataXfer(input);
}

TEST_F(StsMsgProcessorTest, processStsTokenDataXfer_empty_token) {
    auto proc = makeProcessor();
    const std::string input = "data_xfer_ststoken~|~1.2.3.4:55094~|~~|~dwn~|~4096";
    proc->processStsTokenDataXfer(input);
    // Empty token should cause early return
}

// --- processStsTokenRoleMapping tests ---

TEST_F(StsMsgProcessorTest, processStsTokenRoleMapping_valid_input) {
    auto proc = makeProcessor();
    const std::string xml_body = "<AssumeRoleResponse><Credentials>"
                                 "<SessionToken>FwoGZXIvYXdzEBYaDHqa</SessionToken>"
                                 "</Credentials><AssumedRoleUser>"
                                 "<Arn>arn:aws:sts::123456:assumed-role/S3Access/session1</Arn>"
                                 "</AssumedRoleUser></AssumeRoleResponse>";
    const std::string input =
        std::string("role_ststoken~|~") + xml_body + "~|~arn:aws:sts::123456:assumed-role/S3Access/session1";
    proc->processStsTokenRoleMapping(input);
}

TEST_F(StsMsgProcessorTest, processStsTokenRoleMapping_missing_arn) {
    auto proc = makeProcessor();
    // XML without <Arn> tag
    const std::string xml_body = "<AssumeRoleResponse><Credentials>"
                                 "<SessionToken>FwoGZXIvYXdzEBYaDHqa</SessionToken>"
                                 "</Credentials></AssumeRoleResponse>";
    const std::string input = std::string("role_ststoken~|~") + xml_body + "~|~some-role-arn";
    proc->processStsTokenRoleMapping(input);
    // Should log error about missing Arn and return
}

TEST_F(StsMsgProcessorTest, processStsTokenRoleMapping_missing_session_token) {
    auto proc = makeProcessor();
    // XML with Arn but no SessionToken
    const std::string xml_body = "<AssumeRoleResponse><AssumedRoleUser>"
                                 "<Arn>arn:aws:sts::123456:assumed-role/S3Access/session1</Arn>"
                                 "</AssumedRoleUser></AssumeRoleResponse>";
    const std::string input =
        std::string("role_ststoken~|~") + xml_body + "~|~arn:aws:sts::123456:assumed-role/S3Access/session1";
    proc->processStsTokenRoleMapping(input);
    // Should log error about missing SessionToken and return
}

} // namespace test
} // namespace syslogsrv

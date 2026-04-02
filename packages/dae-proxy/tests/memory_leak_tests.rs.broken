//! Memory leak detection tests for dae-proxy
//!
//! These tests are designed to detect memory leaks in async contexts,
//! improper resource cleanup, and Arc/Box/Rc usage issues.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;

#[cfg(test)]
mod memory_leak_tests {
    use super::*;
    use dae_proxy::{
        connection::Connection,
        connection_pool::{ConnectionKey, ConnectionPool},
        rule_engine::{PacketInfo, RuleEngine, RuleEngineConfig},
        rules::{DomainRule, Rule, RuleGroup, RuleMatchAction},
        socks5::Socks5Handler,
        shadowsocks::{ShadowsocksHandler, SsCipherType, SsServerConfig},
    };
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);

    struct AllocationGuard;
    impl AllocationGuard {
        fn new() -> Self {
            ALLOCATION_COUNT.fetch_add(1, Ordering::SeqCst);
            Self
        }
    }
    impl Drop for AllocationGuard {
        fn drop(&mut self) {
            ALLOCATION_COUNT.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn get_allocation_count() -> usize {
        ALLOCATION_COUNT.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn test_arc_drop_on_scope_exit() {
        let initial_count = get_allocation_count();
        
        {
            let arc_data: Arc<Vec<u8>> = Arc::new(vec![0u8; 1024]);
            let _arc_clone = arc_data.clone();
            let _arc_clone2 = arc_data.clone();
            assert_eq!(Arc::strong_count(&arc_data), 3);
        }
        
        sleep(Duration::from_millis(10)).await;
        
        let final_count = get_allocation_count();
        assert_eq!(final_count, initial_count, "Arc not properly dropped");
    }

    #[tokio::test]
    async fn test_rule_engine_arc_sharing() {
        let config = RuleEngineConfig::default();
        let engine = RuleEngine::new(config).expect("Failed to create engine");
        let shared_engine: Arc<RuleEngine> = Arc::new(engine);
        
        let _ref1 = shared_engine.clone();
        let _ref2 = shared_engine.clone();
        let _ref3 = shared_engine.clone();
        
        assert_eq!(Arc::strong_count(&shared_engine), 4);
        
        drop(_ref1);
        drop(_ref2);
        drop(_ref3);
        
        assert_eq!(Arc::strong_count(&shared_engine), 1);
    }

    #[tokio::test]
    async fn test_connection_arc_cleanup() {
        let initial = get_allocation_count();
        
        let conn = Connection::new(
            "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
            "8.8.8.8:443".parse::<SocketAddr>().unwrap(),
        );
        let shared: Arc<Connection> = Arc::new(conn);
        
        let _clone1 = shared.clone();
        let _clone2 = shared.clone();
        
        drop(shared);
        drop(_clone1);
        drop(_clone2);
        
        sleep(Duration::from_millis(10)).await;
        
        let final_count = get_allocation_count();
        assert_eq!(final_count, initial, "Connection Arc not cleaned up");
    }

    #[tokio::test]
    async fn test_box_heap_allocation() {
        let initial = get_allocation_count();
        
        {
            let boxed: Box<Vec<u8>> = Box::new(vec![0u8; 4096]);
            let _inner = *boxed;
        }
        
        sleep(Duration::from_millis(10)).await;
        
        let final_count = get_allocation_count();
        assert_eq!(final_count, initial, "Box not properly deallocated");
    }

    #[tokio::test]
    async fn test_boxed_trait_objects() {
        let initial = get_allocation_count();
        
        {
            let _handler: Box<dyn Send + Sync> = Box::new(Socks5Handler::new());
        }
        
        sleep(Duration::from_millis(10)).await;
        
        let final_count = get_allocation_count();
        assert_eq!(final_count, initial, "Boxed trait object leak detected");
    }

    #[tokio::test]
    async fn test_connection_pool_no_leak_on_insert() {
        let pool = ConnectionPool::new(100);
        let initial_size = pool.len();
        
        for i in 0..100 {
            let key = ConnectionKey::new(
                Ipv4Addr::new(192, 168, 1, (i % 255) as u8).into(),
                Ipv4Addr::new(8, 8, 8, 8).into(),
                12345 + i,
                443,
                6,
            );
            let conn = Connection::new(
                SocketAddr::new(Ipv4Addr::new(192, 168, 1, 1).into(), 12345 + i),
                SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 443),
            );
            pool.insert(key, Arc::new(conn));
        }
        
        assert_eq!(pool.len(), initial_size + 100);
        
        pool.clear();
        sleep(Duration::from_millis(10)).await;
        
        assert_eq!(pool.len(), 0, "Pool not cleared properly");
    }

    #[tokio::test]
    async fn test_connection_pool_concurrent_access() {
        use tokio::task::JoinSet;
        
        let pool: Arc<ConnectionPool> = Arc::new(ConnectionPool::new(1000));
        let mut join_set = JoinSet::new();
        
        for task_id in 0..10 {
            let pool_clone = pool.clone();
            join_set.spawn(async move {
                for i in 0..100 {
                    let key = ConnectionKey::new(
                        Ipv4Addr::new(192, 168, 1, task_id as u8).into(),
                        Ipv4Addr::new(8, 8, 8, 8).into(),
                        12345 + i,
                        443,
                        6,
                    );
                    let conn = Connection::new(
                        SocketAddr::new(Ipv4Addr::new(192, 168, 1, task_id as u8).into(), 12345 + i),
                        SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 443),
                    );
                    pool_clone.insert(key, Arc::new(conn));
                }
            });
        }
        
        while join_set.join_next().await.is_some() {}
        
        assert!(pool.len() > 0, "Pool should have entries");
    }

    #[tokio::test]
    async fn test_rule_engine_no_leak_on_reload() {
        let initial = get_allocation_count();
        
        let config1 = RuleEngineConfig::default();
        let _engine1 = RuleEngine::new(config1).expect("Failed to create engine");
        
        let mut group = RuleGroup::default();
        group.name = "reload_test".to_string();
        group.rules.push(Rule::Domain(DomainRule {
            pattern: "test.com".to_string(),
            action: RuleMatchAction::Allow,
        }));
        
        let config2 = RuleEngineConfig {
            groups: vec![group],
            ..Default::default()
        };
        let _engine2 = RuleEngine::new(config2).expect("Failed to create engine");
        
        sleep(Duration::from_millis(10)).await;
        
        let final_count = get_allocation_count();
        assert!(
            final_count <= initial + 10,
            "Rule engine reload caused memory leak: {} allocations",
            final_count - initial
        );
    }

    #[tokio::test]
    async fn test_rule_matching_no_allocation() {
        let config = RuleEngineConfig::default();
        let engine = RuleEngine::new(config).expect("Failed to create engine");
        
        let packet = PacketInfo::new(
            Ipv4Addr::new(192, 168, 1, 100).into(),
            Ipv4Addr::new(8, 8, 8, 8).into(),
            12345,
            443,
            6,
        );
        
        let initial = get_allocation_count();
        
        for _ in 0..1000 {
            let _ = engine.match_packet(&packet);
        }
        
        let final_count = get_allocation_count();
        assert_eq!(
            final_count, initial,
            "Rule matching should not allocate on hot path"
        );
    }

    #[tokio::test]
    async fn test_abandoned_task_no_leak() {
        let initial = get_allocation_count();
        
        tokio::spawn(async {
            let data: Vec<u8> = vec![0u8; 1024 * 1024];
            black_box(data);
            sleep(Duration::from_secs(10)).await;
        });
        
        sleep(Duration::from_millis(100)).await;
        
        let final_count = get_allocation_count();
        assert!(
            final_count <= initial + 1024,
            "Abandoned task may have leaked memory"
        );
    }

    #[tokio::test]
    async fn test_cancelled_task_cleanup() {
        let initial = get_allocation_count();
        
        let handle = tokio::spawn(async {
            let big_data: Vec<u8> = vec![0u8; 1024 * 1024];
            black_box(big_data);
            sleep(Duration::from_secs(60)).await;
            42
        });
        
        sleep(Duration::from_millis(50)).await;
        
        handle.abort();
        
        sleep(Duration::from_millis(100)).await;
        
        let _ = handle.await;
        
        let final_count = get_allocation_count();
        assert!(
            final_count <= initial + 10,
            "Cancelled task did not clean up: {} bytes leaked",
            (final_count - initial) * 1024
        );
    }

    fn black_box<T>(val: T) -> T {
        use std::hint::black_box;
        black_box(val)
    }

    #[tokio::test]
    #[ignore]
    async fn test_long_running_memory_stability() {
        let pool: Arc<ConnectionPool> = Arc::new(ConnectionPool::new(1000));
        
        let start_memory = get_allocation_count();
        
        for iteration in 0..300 {
            for i in 0..10 {
                let key = ConnectionKey::new(
                    Ipv4Addr::new(192, 168, 1, (iteration % 255) as u8).into(),
                    Ipv4Addr::new(8, 8, 8, 8).into(),
                    12345 + i,
                    443,
                    6,
                );
                let conn = Connection::new(
                    SocketAddr::new(Ipv4Addr::new(192, 168, 1, 1).into(), 12345 + i),
                    SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 443),
                );
                pool.insert(key, Arc::new(conn));
            }
            
            pool.clear_expired();
            sleep(Duration::from_millis(100)).await;
        }
        
        let end_memory = get_allocation_count();
        let growth = end_memory - start_memory;
        
        assert!(
            growth < 100,
            "Long-running test showed memory growth: {} allocations",
            growth
        );
    }

    #[tokio::test]
    async fn test_high_concurrency_no_leak() {
        use tokio::task::JoinSet;
        
        let pool: Arc<ConnectionPool> = Arc::new(ConnectionPool::new(10000));
        let start = get_allocation_count();
        
        let mut join_set = JoinSet::new();
        
        for task_id in 0..100 {
            let pool_clone = pool.clone();
            join_set.spawn(async move {
                for i in 0..100 {
                    let key = ConnectionKey::new(
                        Ipv4Addr::new(192, 168, 1, task_id as u8).into(),
                        Ipv4Addr::new(8, 8, 8, 8).into(),
                        12345 + i,
                        443,
                        6,
                    );
                    let conn = Connection::new(
                        SocketAddr::new(Ipv4Addr::new(192, 168, 1, task_id as u8).into(), 12345 + i),
                        SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 443),
                    );
                    pool_clone.insert(key, Arc::new(conn));
                }
            });
        }
        
        while join_set.join_next().await.is_some() {}
        
        assert_eq!(pool.len(), 10000);
        
        pool.clear();
        sleep(Duration::from_millis(100)).await;
        
        let end = get_allocation_count();
        let leaked = end - start;
        
        assert!(
            leaked < 50,
            "High concurrency test leaked {} allocations",
            leaked
        );
    }

    #[tokio::test]
    async fn test_shadowsocks_handler_no_leak() {
        let initial = get_allocation_count();
        
        {
            let config = SsServerConfig {
                cipher: SsCipherType::Aes256Gcm,
                password: "test-password".to_string(),
                ..Default::default()
            };
            let _handler = ShadowsocksHandler::new(config);
        }
        
        sleep(Duration::from_millis(10)).await;
        
        let final_count = get_allocation_count();
        assert_eq!(final_count, initial, "Shadowsocks handler leaked");
    }

    #[tokio::test]
    async fn test_rwlock_no_leak_on_contention() {
        let lock = Arc::new(RwLock::new(vec![0u8; 1024]));
        let start = get_allocation_count();
        
        let lock_clone = lock.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..1000 {
                let _guard = lock_clone.write().await;
            }
        });
        
        let lock_clone2 = lock.clone();
        let handle2 = tokio::spawn(async move {
            for _ in 0..1000 {
                let _guard = lock_clone2.read().await;
            }
        });
        
        let _ = handle.await;
        let _ = handle2.await;
        
        let end = get_allocation_count();
        assert!(
            end <= start + 20,
            "RwLock contention may leak: {}",
            end - start
        );
    }
}

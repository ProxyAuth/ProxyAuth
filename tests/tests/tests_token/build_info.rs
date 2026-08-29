#[cfg(test)]
mod tests {
    use proxyauth::build::build_info::{get, update_build_info, update, BuildInfo};

    fn save_build_info() -> BuildInfo {
        get()
    }

    fn restore_build_info(original: &BuildInfo) {
        update(original.clone());
    }

    #[test]
    fn get_returns_nonempty_build_info() {
        let info = get();
        assert!(!info.version.is_empty());
        assert!(!info.build_hk.is_empty());
        assert!(!info.shuffled_order.is_empty());
    }

    #[test]
    fn to_string_roundtrip() {
        let info = get();
        let s = info.to_string();
        let parts: Vec<&str> = s.split('|').collect();
        assert_eq!(parts.len(), 8);
        assert_eq!(parts[0], info.version);
        assert_eq!(parts[1], info.build_time.to_string());
        assert_eq!(parts[2], info.build_rand.to_string());
        assert_eq!(parts[3], info.build_seed.to_string());
        assert_eq!(parts[4], info.build_seed2.to_string());
        assert_eq!(parts[5], info.build_epoch.to_string());
        assert_eq!(parts[6], info.build_hk);
        assert_eq!(parts[7], info.shuffled_order);
    }

    #[test]
    fn shuffled_order_list_splits_comma_separated() {
        let info = get();
        let list = info.shuffled_order_list();
        assert!(!list.is_empty());
        // Each element should be a non-empty string
        for item in &list {
            assert!(!item.is_empty());
        }
        // The joined result should match the original
        let rejoined = list.join(",");
        assert_eq!(rejoined, info.shuffled_order);
    }

    #[test]
    fn shuffled_order_list_matches_build_info_shuffled_order() {
        let info = get();
        let list = info.shuffled_order_list();
        assert_eq!(list.len(), info.shuffled_order.split(',').count());
        for (a, b) in list.iter().zip(info.shuffled_order.split(',')) {
            assert_eq!(a.trim(), b.trim());
        }
    }

    #[test]
    fn update_build_info_valid_input() {
        let saved = save_build_info();
        let input = "test-version|1234|5678|9012|3456|7890|test-hk|a,b,c";
        let result = update_build_info(input);
        assert!(result.is_ok());

        let info = get();
        assert_eq!(info.version, "test-version");
        assert_eq!(info.build_time, 1234);
        assert_eq!(info.build_rand, 5678);
        assert_eq!(info.build_seed, 9012);
        assert_eq!(info.build_seed2, 3456);
        assert_eq!(info.build_epoch, 7890);
        assert_eq!(info.build_hk, "test-hk");
        assert_eq!(info.shuffled_order, "a,b,c");

        restore_build_info(&saved);
    }

    #[test]
    fn update_build_info_too_few_fields() {
        let result = update_build_info("a|b|c");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("8 fields"));
    }

    #[test]
    fn update_build_info_too_many_fields() {
        let result = update_build_info("a|b|c|d|e|f|g|h|i");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("8 fields"));
    }

    #[test]
    fn update_build_info_invalid_build_time() {
        let result = update_build_info("v|not_a_number|0|0|0|0|hk|order");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("build_time"));
    }

    #[test]
    fn update_build_info_invalid_build_rand() {
        let result = update_build_info("v|0|not_a_number|0|0|0|hk|order");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("build_rand"));
    }

    #[test]
    fn update_build_info_invalid_build_seed() {
        let result = update_build_info("v|0|0|not_a_number|0|0|hk|order");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("build_seed"));
    }

    #[test]
    fn update_build_info_invalid_build_seed2() {
        let result = update_build_info("v|0|0|0|not_a_number|0|hk|order");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("build_seed2"));
    }

    #[test]
    fn update_build_info_invalid_build_epoch() {
        let result = update_build_info("v|0|0|0|0|not_a_number|hk|order");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("build_epoch"));
    }

    #[test]
    fn update_build_info_preserves_through_to_string() {
        let saved = save_build_info();
        let input = "v2|100|200|300|400|500|hk-val|x,y,z";
        let _ = update_build_info(input);
        let info = get();
        let serialized = info.to_string();
        assert!(serialized.contains("v2"));
        assert!(serialized.contains("100"));
        assert!(serialized.contains("200"));
        assert!(serialized.contains("hk-val"));
        assert!(serialized.contains("x,y,z"));
        restore_build_info(&saved);
    }

    #[test]
    fn build_info_shuffled_order_list_empty_string() {
        let info = BuildInfo {
            version: "test".into(),
            build_time: 0,
            build_rand: 0,
            build_seed: 0,
            build_seed2: 0,
            build_epoch: 0,
            build_hk: "hk".into(),
            shuffled_order: String::new(),
        };
        let list = info.shuffled_order_list();
        // Empty string split by comma gives one empty element
        assert_eq!(list.len(), 1);
        assert!(list[0].is_empty());
    }

    #[test]
    fn build_info_shuffled_order_list_single_element() {
        let info = BuildInfo {
            version: "test".into(),
            build_time: 0,
            build_rand: 0,
            build_seed: 0,
            build_seed2: 0,
            build_epoch: 0,
            build_hk: "hk".into(),
            shuffled_order: "username".into(),
        };
        let list = info.shuffled_order_list();
        assert_eq!(list, vec!["username"]);
    }

    #[test]
    fn build_info_shuffled_order_list_with_spaces() {
        let info = BuildInfo {
            version: "test".into(),
            build_time: 0,
            build_rand: 0,
            build_seed: 0,
            build_seed2: 0,
            build_epoch: 0,
            build_hk: "hk".into(),
            shuffled_order: " a , b , c ".into(),
        };
        let list = info.shuffled_order_list();
        assert_eq!(list, vec!["a", "b", "c"]);
    }
}

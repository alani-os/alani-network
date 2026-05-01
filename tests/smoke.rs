#[test]
fn repository_identity_is_stable() {
    assert_eq!(alani_network::repository_name(), "alani-network");
    assert!(!alani_network::module_names().is_empty());
}

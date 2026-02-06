//! Integration tests for rootless system requirements check.

#[cfg(target_os = "linux")]
use container::rootless::system_check::check_system_requirements;

#[cfg(target_os = "linux")]
#[test]
fn test_check_system_requirements() {
    let result = check_system_requirements();
    println!("System check result: {:?}", result);

    if !result.passed {
        if let Some(msg) = result.error_message() {
            println!("{}", msg);
        }
    }
}

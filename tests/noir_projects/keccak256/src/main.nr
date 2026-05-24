use keccak256::keccak256;

fn main(x: [u8; 32], result: [u8; 32]) {
    let digest = keccak256(x, 32);
    assert(digest == result);
}

#[test]
fn test_main() {
    let input: [u8; 32] = 123.to_le_bytes();
    let result = [
        117, 161, 42, 122, 171, 96, 25, 82, 239, 113, 221, 109, 167, 23, 37, 234, 164, 235, 120, 131, 9, 96, 103, 84, 108, 138, 227, 249, 156, 201, 34, 46,
    ];
    main(input, result);
}

from ctypes import CDLL, POINTER, c_ubyte

rijndael = CDLL('./rijndael.so')


def test_add_round_key():
    block = [0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37,
             0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34]
    round_key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2,
                 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
    expected_result = [0x19, 0xf6, 0x24, 0xf8, 0x6b, 0xf1, 0x85,
                       0x9b, 0x5d, 0x6a, 0x0a, 0x04, 0xa1, 0x1f, 0x38, 0x08]

    rijndael.add_round_key(block, round_key)

    assert block == expected_result


def test_sub_bytes():
    block = [0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37,
             0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34]
    expected_result = [0x7c, 0x82, 0x6f, 0x8f, 0x1f, 0x9d, 0x6f,
                       0x4e, 0x22, 0x2a, 0x50, 0x2c, 0x38, 0x20, 0x56, 0x0e]

    rijndael.sub_bytes(block)

    assert block == expected_result


def test_shift_rows():
    block = [0x7c, 0x82, 0x6f, 0x8f, 0x1f, 0x9d, 0x6f, 0x4e,
             0x22, 0x2a, 0x50, 0x2c, 0x38, 0x20, 0x56, 0x0e]
    expected_result = [0x7c, 0x9d, 0x50, 0x2c, 0x1f, 0x2a, 0x56,
                       0x0e, 0x22, 0x82, 0x6f, 0x8f, 0x38, 0x20, 0x6f, 0x4e]

    rijndael.shift_rows(block)

    assert block == expected_result


def test_mix_columns():
    block = [0x7c, 0x9d, 0x50, 0x2c, 0x1f, 0x2a, 0x56, 0x0e,
             0x22, 0x82, 0x6f, 0x8f, 0x38, 0x20, 0x6f, 0x4e]
    expected_result = [0x47, 0x40, 0xa3, 0x4c, 0x37, 0xd4, 0x94,
                       0xed, 0x3e, 0x4c, 0x9c, 0x58, 0x4f, 0x7a, 0x23, 0x41]

    rijndael.mix_columns(block)

    assert block == expected_result


def test_expand_key():
    cipher_key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2,
                  0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
    expected_result = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
                       0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05,
                       0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f,
                       0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b,
                       0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00,
                       0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc,
                       0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd,
                       0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f,
                       0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f,
                       0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e,
                       0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6]

    result = rijndael.expand_key(cipher_key)

    assert result == expected_result


test_add_round_key()
test_sub_bytes()
test_shift_rows()
test_mix_columns()
test_expand_key()

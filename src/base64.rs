const BASE64_MAP: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '-',
];

fn first_six_bits (byte: u8) -> u8 {
    (byte & 0b1111_1100) >> 2
}

fn second_six_bits(first_byte: u8, second_byte: u8) -> u8 {
    (first_byte & 0b0000_0011) << 4 | ((second_byte & 0b1111_0000) >> 4)
}

fn third_six_bits(second_byte: u8, third_byte: u8) ->u8 {
    (second_byte & 0b0000_1111) << 2 | ((third_byte & 0b1100_0000) >> 6)
}


pub fn encode(content: &str) -> String {
    let characters: &[u8] = content.as_bytes();
    let mut base64_output = Vec::with_capacity((characters.len() / 3 + 1) * 4);

    let mut counter = 0;
    while counter + 3 <= characters.len() {
        let first_character = first_six_bits(characters[counter]);
        let second_character =
            second_six_bits(characters[counter], characters[counter + 1]);
        let third_character =
            third_six_bits(characters[counter + 1], characters[counter + 2]);
        let fourt_character = characters[counter + 2] & 0b00111111;

        base64_output.append(&mut vec![
            BASE64_MAP[first_character as usize],
            BASE64_MAP[second_character as usize],
            BASE64_MAP[third_character as usize],
            BASE64_MAP[fourt_character as usize],
        ]);

        counter += 3;
    }

    if counter + 1 == characters.len() {
        let first_character = first_six_bits(characters[counter]);
        let second_character = second_six_bits(characters[counter], 0);

        base64_output.append(&mut vec![
            BASE64_MAP[first_character as usize],
            BASE64_MAP[second_character as usize],
            '=',
            '=',
        ]);
    } else if counter + 2 == characters.len() {
        let first_character = first_six_bits(characters[counter]);
        let second_character =
            second_six_bits(characters[counter], characters[counter + 1]);
        let third_character = third_six_bits(characters[counter + 1], 0);

        base64_output.append(&mut vec![
            BASE64_MAP[first_character as usize],
            BASE64_MAP[second_character as usize],
            BASE64_MAP[third_character as usize],
            '=',
        ]);
    }

    base64_output.into_iter().collect::<String>()
}




pub fn decode(base64: &str) -> String {
    if base64.len() % 4 != 0 {
        panic!("A base64 string contains a multiple of 4 characters");
    }


    let mut base64_bits = Vec::<u8>::new();

    for char in base64.chars() {
        if char.is_ascii_uppercase() {
            base64_bits.push((char as u8)-65);
        } else if char.is_ascii_lowercase() {
            base64_bits.push((char as u8)-97+26);
        } else if char.is_numeric() {
            base64_bits.push((char as u8) -48 +52);
        } else if char == '=' {
            base64_bits.push(255);
        } else {
            panic!("The character does not conform to base 64 standards, {}", base64);
        }
    }


    let chunks: Vec<&[u8]> = base64_bits.chunks(4).collect();
    let mut output = String::new();

    for chunk in &chunks {
        let mut character_bits: u32 = 0;
        character_bits |= (chunk[0] as u32) << 18;
        character_bits |= (chunk[1] as u32) << 12;

        let character_bytes;
        if chunk[2] == 255 {
            character_bytes = character_bits.to_be_bytes()[1..2].to_vec();
        } else if chunk[3] == 255 {
            character_bits |= (chunk[2] as u32) << 6;

            character_bytes = character_bits.to_be_bytes()[1..3].to_vec();
        } else {
            character_bits |= (chunk[2] as u32) << 6;
            character_bits |= chunk[3] as u32;

            character_bytes = character_bits.to_be_bytes()[1..4].to_vec();
        }

        let characters = std::str::from_utf8(&character_bytes);
        match characters {
            Ok(characters) => output.push_str(characters),
            Err(_) => panic!("enter a valid utf8 string."),
        }
    }

    output
}

#[test]
fn decode_simple_string() {

    let test_value = "abc";
    let base64 = "YWJj";

    assert_eq!(test_value, decode(base64));

    let test_value = "abcd";
    let base64 = "YWJjZA==";

    assert_eq!(test_value, decode(base64));

    let test_value = "abcde";
    let base64 = "YWJjZGU=";

    assert_eq!(test_value, decode(base64));

    let test_value = "abcabc";
    let base64 = "YWJjYWJj";

    assert_eq!(test_value, decode(base64));

    let content = "abcabc";
    let base64_value = "YWJjYWJj";

    assert_eq!(base64_value, encode(content));
}

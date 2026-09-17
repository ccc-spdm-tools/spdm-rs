// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

pub(crate) fn commonly_mapped_to_nothing(character: char) -> bool {
    matches!(
        character as u32,
        0x00AD
            | 0x034F
            | 0x1806
            | 0x180B..=0x180D
            | 0x200B..=0x200D
            | 0x2060
            | 0xFE00..=0xFE0F
            | 0xFEFF
    )
}

pub(crate) fn is_nameprep_prohibited(character: char) -> bool {
    let code = character as u32;
    matches!(
        code,
        0x00A0
            | 0x1680
            | 0x2000..=0x200B
            | 0x202F
            | 0x205F
            | 0x3000
            | 0x0080..=0x009F
            | 0x06DD
            | 0x070F
            | 0x180E
            | 0x200C..=0x200D
            | 0x2028..=0x2029
            | 0x2060..=0x2063
            | 0x206A..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFD
            | 0x1D173..=0x1D17A
            | 0xE000..=0xF8FF
            | 0xF0000..=0xFFFFD
            | 0x100000..=0x10FFFD
            | 0xFDD0..=0xFDEF
            | 0x2FF0..=0x2FFB
            | 0x0340..=0x0341
            | 0x200E..=0x200F
            | 0x202A..=0x202E
            | 0xE0001
            | 0xE0020..=0xE007F
    ) || code & 0xFFFF >= 0xFFFE
}

pub(crate) fn is_bidi_r_or_al(character: char) -> bool {
    in_ranges(character, BIDI_R_AL)
}

pub(crate) fn is_bidi_l(character: char) -> bool {
    in_ranges(character, BIDI_L)
}

fn in_ranges(character: char, ranges: &[(u32, u32)]) -> bool {
    let code = character as u32;
    ranges
        .binary_search_by(|&(start, end)| {
            if start > code {
                Ordering::Greater
            } else if end < code {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        })
        .is_ok()
}

pub(crate) fn punycode_encode(input: &str) -> Option<String> {
    const BASE: usize = 36;
    const TMIN: usize = 1;
    const TMAX: usize = 26;
    const INITIAL_N: usize = 128;
    const INITIAL_BIAS: usize = 72;
    const MAX_OUTPUT: usize = 59;

    let mut code_points = Vec::new();
    code_points.try_reserve_exact(63).ok()?;
    for character in input.chars() {
        if code_points.len() == 63 {
            return None;
        }
        code_points.push(character as usize);
    }
    let mut output = String::new();
    output.try_reserve_exact(MAX_OUTPUT).ok()?;
    for &code in &code_points {
        if code < INITIAL_N {
            if output.len() == MAX_OUTPUT {
                return None;
            }
            output.push(char::from_u32(code as u32)?);
        }
    }

    let basic_count = output.len();
    let mut handled = basic_count;
    if basic_count != 0 {
        if output.len() == MAX_OUTPUT {
            return None;
        }
        output.push('-');
    }

    let mut n = INITIAL_N;
    let mut delta = 0usize;
    let mut bias = INITIAL_BIAS;
    while handled < code_points.len() {
        let next = code_points
            .iter()
            .copied()
            .filter(|&code| code >= n)
            .min()?;
        delta = delta.checked_add(next.checked_sub(n)?.checked_mul(handled.checked_add(1)?)?)?;
        n = next;

        for &code in &code_points {
            if code < n {
                delta = delta.checked_add(1)?;
            }
            if code != n {
                continue;
            }

            let mut value = delta;
            let mut k = BASE;
            loop {
                let threshold = if k <= bias {
                    TMIN
                } else if k >= bias.checked_add(TMAX)? {
                    TMAX
                } else {
                    k.checked_sub(bias)?
                };
                if value < threshold {
                    break;
                }
                let digit = threshold.checked_add(
                    value
                        .checked_sub(threshold)?
                        .checked_rem(BASE.checked_sub(threshold)?)?,
                )?;
                if output.len() == MAX_OUTPUT {
                    return None;
                }
                output.push(encode_digit(digit)?);
                value = value
                    .checked_sub(threshold)?
                    .checked_div(BASE.checked_sub(threshold)?)?;
                k = k.checked_add(BASE)?;
            }
            if output.len() == MAX_OUTPUT {
                return None;
            }
            output.push(encode_digit(value)?);
            bias = adapt_bias(delta, handled.checked_add(1)?, handled == basic_count)?;
            delta = 0;
            handled = handled.checked_add(1)?;
        }

        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(output)
}

pub(crate) fn punycode_decode(input: &str) -> Option<String> {
    const BASE: usize = 36;
    const TMIN: usize = 1;
    const TMAX: usize = 26;
    const INITIAL_N: usize = 128;
    const INITIAL_BIAS: usize = 72;

    if input.is_empty() || input.len() > 59 || !input.is_ascii() {
        return None;
    }

    let mut output = Vec::new();
    output.try_reserve_exact(63).ok()?;
    let encoded = if let Some(delimiter) = input.rfind('-') {
        for byte in input[..delimiter].bytes() {
            if !byte.is_ascii() || output.len() == 63 {
                return None;
            }
            output.push(char::from(byte));
        }
        &input[delimiter + 1..]
    } else {
        input
    };

    let mut n = INITIAL_N;
    let mut index = 0usize;
    let mut bias = INITIAL_BIAS;
    let mut encoded = encoded.bytes();
    while encoded.len() != 0 {
        let old_index = index;
        let mut weight = 1usize;
        let mut k = BASE;
        loop {
            let digit = decode_digit(encoded.next()?)?;
            index = index.checked_add(digit.checked_mul(weight)?)?;
            let threshold = if k <= bias {
                TMIN
            } else if k >= bias.checked_add(TMAX)? {
                TMAX
            } else {
                k.checked_sub(bias)?
            };
            if digit < threshold {
                break;
            }
            weight = weight.checked_mul(BASE.checked_sub(threshold)?)?;
            k = k.checked_add(BASE)?;
        }

        let points = output.len().checked_add(1)?;
        bias = adapt_bias(index.checked_sub(old_index)?, points, old_index == 0)?;
        n = n.checked_add(index.checked_div(points)?)?;
        index = index.checked_rem(points)?;
        let character = char::from_u32(u32::try_from(n).ok()?)?;
        if output.len() == 63 {
            return None;
        }
        output.insert(index, character);
        index = index.checked_add(1)?;
    }

    let mut decoded = String::new();
    decoded
        .try_reserve_exact(output.len().checked_mul(4)?)
        .ok()?;
    for character in output {
        decoded.push(character);
    }
    Some(decoded)
}

fn encode_digit(digit: usize) -> Option<char> {
    match digit {
        0..=25 => char::from_u32(u32::try_from(digit).ok()?.checked_add(u32::from(b'a'))?),
        26..=35 => char::from_u32(
            u32::try_from(digit)
                .ok()?
                .checked_sub(26)?
                .checked_add(u32::from(b'0'))?,
        ),
        _ => None,
    }
}

fn decode_digit(digit: u8) -> Option<usize> {
    match digit {
        b'a'..=b'z' => Some(usize::from(digit - b'a')),
        b'A'..=b'Z' => Some(usize::from(digit - b'A')),
        b'0'..=b'9' => Some(usize::from(digit - b'0') + 26),
        _ => None,
    }
}

fn adapt_bias(mut delta: usize, points: usize, first: bool) -> Option<usize> {
    const BASE: usize = 36;
    const TMIN: usize = 1;
    const TMAX: usize = 26;
    const SKEW: usize = 38;
    const DAMP: usize = 700;

    delta /= if first { DAMP } else { 2 };
    delta = delta.checked_add(delta.checked_div(points)?)?;
    let limit = (BASE - TMIN).checked_mul(TMAX)?.checked_div(2)?;
    let mut k = 0usize;
    while delta > limit {
        delta /= BASE - TMIN;
        k = k.checked_add(BASE)?;
    }
    k.checked_add(
        (BASE - TMIN + 1)
            .checked_mul(delta)?
            .checked_div(delta.checked_add(SKEW)?)?,
    )
}

const BIDI_R_AL: &[(u32, u32)] = &[
    (0x5BE, 0x5BE),
    (0x5C0, 0x5C0),
    (0x5C3, 0x5C3),
    (0x5D0, 0x5EA),
    (0x5F0, 0x5F4),
    (0x61B, 0x61B),
    (0x61F, 0x61F),
    (0x621, 0x63A),
    (0x640, 0x64A),
    (0x66D, 0x66F),
    (0x671, 0x6D5),
    (0x6DD, 0x6DD),
    (0x6E5, 0x6E6),
    (0x6FA, 0x6FE),
    (0x700, 0x70D),
    (0x710, 0x710),
    (0x712, 0x72C),
    (0x780, 0x7A5),
    (0x7B1, 0x7B1),
    (0x200F, 0x200F),
    (0xFB1D, 0xFB1D),
    (0xFB1F, 0xFB28),
    (0xFB2A, 0xFB36),
    (0xFB38, 0xFB3C),
    (0xFB3E, 0xFB3E),
    (0xFB40, 0xFB41),
    (0xFB43, 0xFB44),
    (0xFB46, 0xFBB1),
    (0xFBD3, 0xFD3D),
    (0xFD50, 0xFD8F),
    (0xFD92, 0xFDC7),
    (0xFDF0, 0xFDFC),
    (0xFE70, 0xFE74),
    (0xFE76, 0xFEFC),
];

const BIDI_L: &[(u32, u32)] = &[
    (0x41, 0x5A),
    (0x61, 0x7A),
    (0xAA, 0xAA),
    (0xB5, 0xB5),
    (0xBA, 0xBA),
    (0xC0, 0xD6),
    (0xD8, 0xF6),
    (0xF8, 0x220),
    (0x222, 0x233),
    (0x250, 0x2AD),
    (0x2B0, 0x2B8),
    (0x2BB, 0x2C1),
    (0x2D0, 0x2D1),
    (0x2E0, 0x2E4),
    (0x2EE, 0x2EE),
    (0x37A, 0x37A),
    (0x386, 0x386),
    (0x388, 0x38A),
    (0x38C, 0x38C),
    (0x38E, 0x3A1),
    (0x3A3, 0x3CE),
    (0x3D0, 0x3F5),
    (0x400, 0x482),
    (0x48A, 0x4CE),
    (0x4D0, 0x4F5),
    (0x4F8, 0x4F9),
    (0x500, 0x50F),
    (0x531, 0x556),
    (0x559, 0x55F),
    (0x561, 0x587),
    (0x589, 0x589),
    (0x903, 0x903),
    (0x905, 0x939),
    (0x93D, 0x940),
    (0x949, 0x94C),
    (0x950, 0x950),
    (0x958, 0x961),
    (0x964, 0x970),
    (0x982, 0x983),
    (0x985, 0x98C),
    (0x98F, 0x990),
    (0x993, 0x9A8),
    (0x9AA, 0x9B0),
    (0x9B2, 0x9B2),
    (0x9B6, 0x9B9),
    (0x9BE, 0x9C0),
    (0x9C7, 0x9C8),
    (0x9CB, 0x9CC),
    (0x9D7, 0x9D7),
    (0x9DC, 0x9DD),
    (0x9DF, 0x9E1),
    (0x9E6, 0x9F1),
    (0x9F4, 0x9FA),
    (0xA05, 0xA0A),
    (0xA0F, 0xA10),
    (0xA13, 0xA28),
    (0xA2A, 0xA30),
    (0xA32, 0xA33),
    (0xA35, 0xA36),
    (0xA38, 0xA39),
    (0xA3E, 0xA40),
    (0xA59, 0xA5C),
    (0xA5E, 0xA5E),
    (0xA66, 0xA6F),
    (0xA72, 0xA74),
    (0xA83, 0xA83),
    (0xA85, 0xA8B),
    (0xA8D, 0xA8D),
    (0xA8F, 0xA91),
    (0xA93, 0xAA8),
    (0xAAA, 0xAB0),
    (0xAB2, 0xAB3),
    (0xAB5, 0xAB9),
    (0xABD, 0xAC0),
    (0xAC9, 0xAC9),
    (0xACB, 0xACC),
    (0xAD0, 0xAD0),
    (0xAE0, 0xAE0),
    (0xAE6, 0xAEF),
    (0xB02, 0xB03),
    (0xB05, 0xB0C),
    (0xB0F, 0xB10),
    (0xB13, 0xB28),
    (0xB2A, 0xB30),
    (0xB32, 0xB33),
    (0xB36, 0xB39),
    (0xB3D, 0xB3E),
    (0xB40, 0xB40),
    (0xB47, 0xB48),
    (0xB4B, 0xB4C),
    (0xB57, 0xB57),
    (0xB5C, 0xB5D),
    (0xB5F, 0xB61),
    (0xB66, 0xB70),
    (0xB83, 0xB83),
    (0xB85, 0xB8A),
    (0xB8E, 0xB90),
    (0xB92, 0xB95),
    (0xB99, 0xB9A),
    (0xB9C, 0xB9C),
    (0xB9E, 0xB9F),
    (0xBA3, 0xBA4),
    (0xBA8, 0xBAA),
    (0xBAE, 0xBB5),
    (0xBB7, 0xBB9),
    (0xBBE, 0xBBF),
    (0xBC1, 0xBC2),
    (0xBC6, 0xBC8),
    (0xBCA, 0xBCC),
    (0xBD7, 0xBD7),
    (0xBE7, 0xBF2),
    (0xC01, 0xC03),
    (0xC05, 0xC0C),
    (0xC0E, 0xC10),
    (0xC12, 0xC28),
    (0xC2A, 0xC33),
    (0xC35, 0xC39),
    (0xC41, 0xC44),
    (0xC60, 0xC61),
    (0xC66, 0xC6F),
    (0xC82, 0xC83),
    (0xC85, 0xC8C),
    (0xC8E, 0xC90),
    (0xC92, 0xCA8),
    (0xCAA, 0xCB3),
    (0xCB5, 0xCB9),
    (0xCBE, 0xCBE),
    (0xCC0, 0xCC4),
    (0xCC7, 0xCC8),
    (0xCCA, 0xCCB),
    (0xCD5, 0xCD6),
    (0xCDE, 0xCDE),
    (0xCE0, 0xCE1),
    (0xCE6, 0xCEF),
    (0xD02, 0xD03),
    (0xD05, 0xD0C),
    (0xD0E, 0xD10),
    (0xD12, 0xD28),
    (0xD2A, 0xD39),
    (0xD3E, 0xD40),
    (0xD46, 0xD48),
    (0xD4A, 0xD4C),
    (0xD57, 0xD57),
    (0xD60, 0xD61),
    (0xD66, 0xD6F),
    (0xD82, 0xD83),
    (0xD85, 0xD96),
    (0xD9A, 0xDB1),
    (0xDB3, 0xDBB),
    (0xDBD, 0xDBD),
    (0xDC0, 0xDC6),
    (0xDCF, 0xDD1),
    (0xDD8, 0xDDF),
    (0xDF2, 0xDF4),
    (0xE01, 0xE30),
    (0xE32, 0xE33),
    (0xE40, 0xE46),
    (0xE4F, 0xE5B),
    (0xE81, 0xE82),
    (0xE84, 0xE84),
    (0xE87, 0xE88),
    (0xE8A, 0xE8A),
    (0xE8D, 0xE8D),
    (0xE94, 0xE97),
    (0xE99, 0xE9F),
    (0xEA1, 0xEA3),
    (0xEA5, 0xEA5),
    (0xEA7, 0xEA7),
    (0xEAA, 0xEAB),
    (0xEAD, 0xEB0),
    (0xEB2, 0xEB3),
    (0xEBD, 0xEBD),
    (0xEC0, 0xEC4),
    (0xEC6, 0xEC6),
    (0xED0, 0xED9),
    (0xEDC, 0xEDD),
    (0xF00, 0xF17),
    (0xF1A, 0xF34),
    (0xF36, 0xF36),
    (0xF38, 0xF38),
    (0xF3E, 0xF47),
    (0xF49, 0xF6A),
    (0xF7F, 0xF7F),
    (0xF85, 0xF85),
    (0xF88, 0xF8B),
    (0xFBE, 0xFC5),
    (0xFC7, 0xFCC),
    (0xFCF, 0xFCF),
    (0x1000, 0x1021),
    (0x1023, 0x1027),
    (0x1029, 0x102A),
    (0x102C, 0x102C),
    (0x1031, 0x1031),
    (0x1038, 0x1038),
    (0x1040, 0x1057),
    (0x10A0, 0x10C5),
    (0x10D0, 0x10F8),
    (0x10FB, 0x10FB),
    (0x1100, 0x1159),
    (0x115F, 0x11A2),
    (0x11A8, 0x11F9),
    (0x1200, 0x1206),
    (0x1208, 0x1246),
    (0x1248, 0x1248),
    (0x124A, 0x124D),
    (0x1250, 0x1256),
    (0x1258, 0x1258),
    (0x125A, 0x125D),
    (0x1260, 0x1286),
    (0x1288, 0x1288),
    (0x128A, 0x128D),
    (0x1290, 0x12AE),
    (0x12B0, 0x12B0),
    (0x12B2, 0x12B5),
    (0x12B8, 0x12BE),
    (0x12C0, 0x12C0),
    (0x12C2, 0x12C5),
    (0x12C8, 0x12CE),
    (0x12D0, 0x12D6),
    (0x12D8, 0x12EE),
    (0x12F0, 0x130E),
    (0x1310, 0x1310),
    (0x1312, 0x1315),
    (0x1318, 0x131E),
    (0x1320, 0x1346),
    (0x1348, 0x135A),
    (0x1361, 0x137C),
    (0x13A0, 0x13F4),
    (0x1401, 0x1676),
    (0x1681, 0x169A),
    (0x16A0, 0x16F0),
    (0x1700, 0x170C),
    (0x170E, 0x1711),
    (0x1720, 0x1731),
    (0x1735, 0x1736),
    (0x1740, 0x1751),
    (0x1760, 0x176C),
    (0x176E, 0x1770),
    (0x1780, 0x17B6),
    (0x17BE, 0x17C5),
    (0x17C7, 0x17C8),
    (0x17D4, 0x17DA),
    (0x17DC, 0x17DC),
    (0x17E0, 0x17E9),
    (0x1810, 0x1819),
    (0x1820, 0x1877),
    (0x1880, 0x18A8),
    (0x1E00, 0x1E9B),
    (0x1EA0, 0x1EF9),
    (0x1F00, 0x1F15),
    (0x1F18, 0x1F1D),
    (0x1F20, 0x1F45),
    (0x1F48, 0x1F4D),
    (0x1F50, 0x1F57),
    (0x1F59, 0x1F59),
    (0x1F5B, 0x1F5B),
    (0x1F5D, 0x1F5D),
    (0x1F5F, 0x1F7D),
    (0x1F80, 0x1FB4),
    (0x1FB6, 0x1FBC),
    (0x1FBE, 0x1FBE),
    (0x1FC2, 0x1FC4),
    (0x1FC6, 0x1FCC),
    (0x1FD0, 0x1FD3),
    (0x1FD6, 0x1FDB),
    (0x1FE0, 0x1FEC),
    (0x1FF2, 0x1FF4),
    (0x1FF6, 0x1FFC),
    (0x200E, 0x200E),
    (0x2071, 0x2071),
    (0x207F, 0x207F),
    (0x2102, 0x2102),
    (0x2107, 0x2107),
    (0x210A, 0x2113),
    (0x2115, 0x2115),
    (0x2119, 0x211D),
    (0x2124, 0x2124),
    (0x2126, 0x2126),
    (0x2128, 0x2128),
    (0x212A, 0x212D),
    (0x212F, 0x2131),
    (0x2133, 0x2139),
    (0x213D, 0x213F),
    (0x2145, 0x2149),
    (0x2160, 0x2183),
    (0x2336, 0x237A),
    (0x2395, 0x2395),
    (0x249C, 0x24E9),
    (0x3005, 0x3007),
    (0x3021, 0x3029),
    (0x3031, 0x3035),
    (0x3038, 0x303C),
    (0x3041, 0x3096),
    (0x309D, 0x309F),
    (0x30A1, 0x30FA),
    (0x30FC, 0x30FF),
    (0x3105, 0x312C),
    (0x3131, 0x318E),
    (0x3190, 0x31B7),
    (0x31F0, 0x321C),
    (0x3220, 0x3243),
    (0x3260, 0x327B),
    (0x327F, 0x32B0),
    (0x32C0, 0x32CB),
    (0x32D0, 0x32FE),
    (0x3300, 0x3376),
    (0x337B, 0x33DD),
    (0x33E0, 0x33FE),
    (0x3400, 0x4DB5),
    (0x4E00, 0x9FA5),
    (0xA000, 0xA48C),
    (0xAC00, 0xD7A3),
    (0xD800, 0xFA2D),
    (0xFA30, 0xFA6A),
    (0xFB00, 0xFB06),
    (0xFB13, 0xFB17),
    (0xFF21, 0xFF3A),
    (0xFF41, 0xFF5A),
    (0xFF66, 0xFFBE),
    (0xFFC2, 0xFFC7),
    (0xFFCA, 0xFFCF),
    (0xFFD2, 0xFFD7),
    (0xFFDA, 0xFFDC),
    (0x10300, 0x1031E),
    (0x10320, 0x10323),
    (0x10330, 0x1034A),
    (0x10400, 0x10425),
    (0x10428, 0x1044D),
    (0x1D000, 0x1D0F5),
    (0x1D100, 0x1D126),
    (0x1D12A, 0x1D166),
    (0x1D16A, 0x1D172),
    (0x1D183, 0x1D184),
    (0x1D18C, 0x1D1A9),
    (0x1D1AE, 0x1D1DD),
    (0x1D400, 0x1D454),
    (0x1D456, 0x1D49C),
    (0x1D49E, 0x1D49F),
    (0x1D4A2, 0x1D4A2),
    (0x1D4A5, 0x1D4A6),
    (0x1D4A9, 0x1D4AC),
    (0x1D4AE, 0x1D4B9),
    (0x1D4BB, 0x1D4BB),
    (0x1D4BD, 0x1D4C0),
    (0x1D4C2, 0x1D4C3),
    (0x1D4C5, 0x1D505),
    (0x1D507, 0x1D50A),
    (0x1D50D, 0x1D514),
    (0x1D516, 0x1D51C),
    (0x1D51E, 0x1D539),
    (0x1D53B, 0x1D53E),
    (0x1D540, 0x1D544),
    (0x1D546, 0x1D546),
    (0x1D54A, 0x1D550),
    (0x1D552, 0x1D6A3),
    (0x1D6A8, 0x1D7C9),
    (0x20000, 0x2A6D6),
    (0x2F800, 0x2FA1D),
    (0xF0000, 0xFFFFD),
    (0x100000, 0x10FFFD),
];

#[cfg(test)]
mod tests {
    use super::{punycode_decode, punycode_encode};

    #[test]
    fn test_rfc3492_punycode_encoding() {
        assert_eq!(punycode_encode("bücher").as_deref(), Some("bcher-kva"));
        assert_eq!(punycode_encode("例え").as_deref(), Some("r8jz45g"));
        assert_eq!(punycode_encode("éxample").as_deref(), Some("xample-9ua"));
        assert_eq!(punycode_decode("bcher-kva").as_deref(), Some("bücher"));
        assert_eq!(punycode_decode("r8jz45g").as_deref(), Some("例え"));
        assert_eq!(punycode_decode("xample-9ua").as_deref(), Some("éxample"));
        for (unicode, encoded) in [
            ("ليهمابتكلموشعربي؟", "egbpdaj6bu4bxfgehfvwxn"),
            ("他们为什么不说中文", "ihqwcrb4cv8a8dqg056pqjye"),
            (
                "なぜみんな日本語を話してくれないのか",
                "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa",
            ),
        ] {
            assert_eq!(punycode_encode(unicode).as_deref(), Some(encoded));
            assert_eq!(punycode_decode(encoded).as_deref(), Some(unicode));
        }
    }

    #[test]
    fn test_punycode_rejects_invalid_or_excessive_input() {
        assert!(punycode_decode("").is_none());
        assert!(punycode_decode("not_valid").is_none());
        assert!(punycode_decode(&"a".repeat(60)).is_none());
        assert!(punycode_encode(&"é".repeat(64)).is_none());
    }
}

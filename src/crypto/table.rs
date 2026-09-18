use crate::utils::hash::md5;

const OFFSET_ROL: fn(u8, usize) -> u64 = |p: u8, o: usize| -> u64 { (p as u64) << (8 * o) };

/// Table cipher: substitution table generated from password
pub struct TableCipher {
    enc_table: [u8; 256],
    dec_table: [u8; 256],
}

impl TableCipher {
    pub fn new(password: &[u8]) -> Self {
        let digest = md5(password);

        let mut key: u64 = 0;
        for i in 0..8 {
            key = key.wrapping_add(OFFSET_ROL(digest[i], i));
        }

        let mut enc_table = [0u8; 256];
        for i in 0..256 {
            enc_table[i] = i as u8;
        }

        for i in 1..1024u64 {
            Self::merge_sort(&mut enc_table, 256, i as u32, key);
        }

        let mut dec_table = [0u8; 256];
        for i in 0..256 {
            dec_table[enc_table[i] as usize] = i as u8;
        }

        Self { enc_table, dec_table }
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        data.iter().map(|&b| self.enc_table[b as usize]).collect()
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        data.iter().map(|&b| self.dec_table[b as usize]).collect()
    }

    fn random_compare(x: u8, y: u8, salt: u32, key: u64) -> i32 {
        ((key % (x as u64 + salt as u64)) as i64 - (key % (y as u64 + salt as u64)) as i64) as i32
    }

    fn merge_sort(array: &mut [u8], length: usize, salt: u32, key: u64) {
        if length <= 1 {
            return;
        }
        let middle = length / 2;
        let llength = length - middle;

        Self::merge_sort(array, llength, salt, key);
        Self::merge_sort(&mut array[llength..], middle, salt, key);

        // Merge
        let left = array[..llength].to_vec();
        let right = array[llength..length].to_vec();

        let mut i = 0;
        let mut j = 0;
        let mut k = 0;

        while i < llength && j < middle {
            if Self::random_compare(left[i], right[j], salt, key) <= 0 {
                array[k] = left[i];
                i += 1;
            } else {
                array[k] = right[j];
                j += 1;
            }
            k += 1;
        }

        while i < llength {
            array[k] = left[i];
            i += 1;
            k += 1;
        }

        while j < middle {
            array[k] = right[j];
            j += 1;
            k += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_roundtrip() {
        let cipher = TableCipher::new(b"password");
        let data = b"hello world";
        let encrypted = cipher.encrypt(data);
        assert_ne!(encrypted, data);
        let decrypted = cipher.decrypt(&encrypted);
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_table_empty() {
        let cipher = TableCipher::new(b"key");
        let data = b"";
        let encrypted = cipher.encrypt(data);
        assert_eq!(encrypted, b"");
    }

    #[test]
    fn test_table_single_byte() {
        let cipher = TableCipher::new(b"password");
        for b in 0..=255u8 {
            let encrypted = cipher.encrypt(&[b]);
            let decrypted = cipher.decrypt(&encrypted);
            assert_eq!(decrypted, [b]);
        }
    }
}

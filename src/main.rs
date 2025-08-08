use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aead::generic_array::GenericArray;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand_core::{OsRng, RngCore};

fn encrypt_data(data: &[u8], password: &str) -> Vec<u8> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 100_000, &mut key);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let key = GenericArray::from_slice(&key);
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), data)
        .expect("encryption failed");
    [salt.to_vec(), nonce.to_vec(), ciphertext].concat()
}

fn decrypt_data(data: &[u8], password: &str) -> Vec<u8> {
    let salt = &data[0..16];
    let nonce = &data[16..28];
    let ciphertext = &data[28..];
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut key);
    let key = GenericArray::from_slice(&key);
    let cipher = Aes256Gcm::new(key);
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .expect("decryption failed")
}

fn main() {
    let encrypted = encrypt_data(b"Hello, world!", "mysecret");
    let decrypted = decrypt_data(&encrypted[..], "mysecret");
    println!("{:?}", &decrypted[..]);
}

use ed25519_dalek::ed25519::signature::SignerMut;
use serde::{Deserialize, Serialize}; //Для работы с JSON
use std::fs::{write, File, read_to_string};
use std::io::Read;
use ed25519_dalek::{Keypair, PublicKey, Signature, SecretKey, Verifier};
use rand::rngs::OsRng; //Генерация случайных данных
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Errors {
    #[error("Ошибка чтения файла: {0}")]
    FileReadError(String),
    #[error("Ошибка десериализации JSON: {0}")]
    JsonDeserializeError(String),
    #[error("Ошибка записи файла: {0}")]
    FileWriteError(String),
    #[error("Ошибка декодирования приватного ключа: {0}")]
    PrivateKeyDecodeError(String),
    #[error("Ошибка декодирования публичного ключа: {0}")]
    PublicKeyDecodeError(String),
    #[error("Ошибка создания секретного ключа: {0}")]
    SecretKeyCreationError(String),
    #[error("Ошибка создания публичного ключа: {0}")]
    PublicKeyCreationError(String),
    #[error("Приватный и публичный ключи совпадают, сохранение невозможно.")]
    IdenticalKeysError,
}

pub fn generate_keypair() -> Keypair {
    let mut csprng = OsRng; // Криптографически безопасный генератор случайных чисел
    Keypair::generate(&mut csprng)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InputData {
    message: String,
}

pub fn read_json_file(path: &str) -> Result<InputData, Errors> {
    let mut file = File::open(path).map_err(|e| Errors::FileReadError(e.to_string()))?;
    let mut contents: String = String::new();
    file.read_to_string(&mut contents).map_err(|e| Errors::FileReadError(e.to_string()))?;
    let data: InputData = serde_json::from_str(&contents).map_err(|e| Errors::JsonDeserializeError(e.to_string()))?;
    Ok(data)
}

pub fn save_keys(keypair: &Keypair) -> Result<(), Errors> {
    let private_key_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::encode(keypair.secret.to_bytes())
    );
    if keypair.public.as_bytes() == keypair.secret.as_bytes() {
        return Err(Errors::IdenticalKeysError);
    }
    write("private_key.pem", private_key_pem).map_err(|e| Errors::FileWriteError(e.to_string()))?;

    let public_key_base64 = base64::encode(keypair.public.to_bytes());
    write("public_key.pem", public_key_base64).map_err(|e| Errors::FileWriteError(e.to_string()))?;

    Ok(())
}

pub fn sign_message(message: &str, keypair: &mut Keypair) -> Signature {
    let message_bytes = message.as_bytes();
    keypair.sign(message_bytes)
}

pub fn verify_signature(message: &str, signature: &Signature, public_key: &PublicKey) -> bool {
    let message_bytes = message.as_bytes();
    public_key.verify(message_bytes, signature).is_ok()
}

pub fn load_keys(private_key_path: &str, public_key_path: &str) -> Result<Keypair, Errors> {
    let private_key_pem = read_to_string(private_key_path).map_err(|e| Errors::FileReadError(e.to_string()))?;
    let private_key_base64 = private_key_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let private_key_bytes = base64::decode(private_key_base64).map_err(|_| Errors::PrivateKeyDecodeError("Ошибка декодирования приватного ключа".to_string()))?;
    let secret_key = SecretKey::from_bytes(&private_key_bytes).map_err(|_| Errors::SecretKeyCreationError("Ошибка создания секретного ключа".to_string()))?;

    let public_key_base64 = read_to_string(public_key_path).map_err(|e| Errors::FileReadError(e.to_string()))?;
    let public_key_bytes = base64::decode(public_key_base64.trim()).map_err(|_| Errors::PublicKeyDecodeError("Ошибка декодирования публичного ключа".to_string()))?;
    let public_key = PublicKey::from_bytes(&public_key_bytes).map_err(|_| Errors::PublicKeyCreationError("Ошибка создания публичного ключа".to_string()))?;

    Ok(Keypair {
        public: public_key,
        secret: secret_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reading_json() {
        let path: &str = "input.json";

        let data: Option<InputData> = match read_json_file(path) {
            Ok(data) => {
                println!("Прочитано сообщение: {:?}", data);
                Some(data)
            }
            Err(e) => {
                eprintln!("Ошибка чтения файла .JSON: {}", e);
                None
            }
        };

        assert_eq!(&data.unwrap().message, "Привет, мир!")
    }

    #[test]
    #[ignore]
    fn test_reading_bad_json() {
        let path: &str = "bad_input.json";

        let data: Option<InputData> = match read_json_file(path) {
            Ok(data) => {
                println!("Прочитано сообщение: {:?}", data);
                Some(data)
            }
            Err(e) => {
                eprintln!("Ошибка чтения файла .JSON: {}", e);
                None
            }
        };
        assert!(data.is_none());
    }

    #[test]
    fn test_reading_json_bad_path() {
        let path: &str = "bad_input1.json";

        let data: Option<InputData> = match read_json_file(path) {
            Ok(data) => {
                println!("Прочитано сообщение: {:?}", data);
                Some(data)
            }
            Err(e) => {
                eprintln!("Ошибка чтения файла .JSON: {}", e);
                None
            }
        };
    }

    #[test]
    fn creating_keypair() {
        let mut keypair: Keypair = generate_keypair();
        println!("Секретный ключ: {:?}", keypair.secret);
        println!("Открытый ключ: {:?}", keypair.public);
    }

    #[test]
    fn save_keys_test() {
        let mut keypair: Keypair = generate_keypair();
        save_keys(&keypair).expect("Не удалось сохранить ключи")
    }

    #[test]
    fn test_save_keys_identical_keys() {
        let dummy_key_bytes = [42u8; 32];
        let secret_key = SecretKey::from_bytes(&dummy_key_bytes).unwrap();
        let public_key = PublicKey::from_bytes(&dummy_key_bytes).unwrap();

        let keypair = Keypair { secret: secret_key, public: public_key };

        let result = save_keys(&keypair);
        assert!(result.is_err());
    }

    #[test]
    fn checking_signature() {
        let mut keypair: Keypair = generate_keypair();

        let path: &str = "input.json";

        let data: Option<InputData> = match read_json_file(path) {
            Ok(data) => {
                println!("Прочитано сообщение: {:?}", data);
                Some(data)
            }
            Err(e) => {
                eprintln!("Ошибка чтения файла .JSON: {}", e);
                None
            }
        };
        let signature = sign_message(&data.unwrap().message, &mut keypair);
        let signature_bytes = signature.to_bytes();
        let signature_base64 = base64::encode(signature_bytes);
        println!("Подпись в формате Base64: {}", signature_base64);
    }

    #[test]
    fn verify_signature_test_valid() {
        let mut keypair: Keypair = generate_keypair();
        let message: &str = "Привет, мир!";
        let signature = keypair.sign(message.as_bytes());

        let public_key = keypair.public;

        let result = verify_signature(message, &signature, &public_key);
        assert!(result, "Подпись должна быть валидной!");
    }

    #[test]
    fn verify_signature_test_invalid() {
        let mut keypair: Keypair = generate_keypair();
        let message: &str = "Привет, мир!";
        let signature = keypair.sign(message.as_bytes());

        let public_key = keypair.public;

        let fake_signature = Signature::from_bytes(&[0u8; 64]).expect("Не удалось создать фейковую подпись");

        let result = verify_signature(message, &fake_signature, &public_key);
        assert!(!result, "Подпись не должна быть валидной с неверными данными!");
    }

    #[test]
    fn verify_signature_test_invalid_key() {
        let mut keypair: Keypair = generate_keypair();
        let message: &str = "Привет, мир!";
        let signature = keypair.sign(message.as_bytes());

        let another_keypair = generate_keypair();
        let another_public_key = another_keypair.public;
        let result = verify_signature(message, &signature, &another_public_key);
        assert!(!result, "Подпись не должна быть валидной с неверным публичным ключом!")
    }

    #[test]
    #[ignore]
    fn test_load_keys_valid() {
        let keypair = generate_keypair();

        let private_key_pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::encode(keypair.secret.to_bytes())
        );
        write("private_key.pem", private_key_pem).expect("Не удалось сохранить приватный ключ");

        let public_key_base64 = base64::encode(keypair.public.to_bytes());
        write("public_key.pem", public_key_base64).expect("Не удалось сохранить публичный ключ");

        let loaded_keys = load_keys("private_key.pem", "public_key.pem").expect("Не удалось загрузить ключи");

        assert_eq!(loaded_keys.secret.to_bytes(), keypair.secret.to_bytes());
        assert_eq!(loaded_keys.public.to_bytes(), keypair.public.to_bytes());
    }

    #[test]
    fn test_load_keys_file_not_found() {
        let result = load_keys("nonexistent_private_key.pem", "nonexistent_public_key.pem");
        assert!(result.is_err(), "Ожидалась ошибка при загрузке несуществующих файлов");
    }
}

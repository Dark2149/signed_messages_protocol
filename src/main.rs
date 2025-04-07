mod lib;
use ed25519_dalek::{Keypair, PublicKey, Signature, SecretKey, Verifier};
use ed25519_dalek::ed25519::signature::SignerMut;
use std::fs::{write, File, read_to_string}; 
use lib::*;
pub fn main() { 
    //Чтение файла .json 
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
 
    //Сохранение ключей 
    //save_keys(&keypair).expect("Не удалось сохранить ключи"); 
    //sign_message(&data.unwrap().message, &mut keypair); // Только если удалось успешно прочитать JSON, иначе будет вызвана паника  
}





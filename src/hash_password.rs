use bcrypt::{hash, DEFAULT_COST};

fn main() {
    let password = "your_password_here"; // Replace with the password you wish to hash
    match hash(password, DEFAULT_COST) {
        Ok(hashed) => println!("Hashed password: {}", hashed),
        Err(e) => println!("Error hashing password: {}", e),
    }
}

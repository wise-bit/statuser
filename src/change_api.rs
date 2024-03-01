use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
use actix_web::{middleware, web, App, HttpResponse, HttpServer, Responder};
use bcrypt::verify;
use dotenv::dotenv;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::env;
use std::fmt;
use std::sync::Mutex;

static APP_STATE: Lazy<Mutex<State>> = Lazy::new(|| Mutex::new(State::Inactive));

#[derive(Deserialize)]
struct LoginInfo {
    username: String,
    password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum State {
    Active,
    Inactive,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            State::Active => write!(f, "Active"),
            State::Inactive => write!(f, "Inactive"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateChange {
    state: State,
}

async fn get_state() -> impl Responder {
    let state = APP_STATE.lock().unwrap();
    HttpResponse::Ok().body(state.to_string())
}

async fn set_state(id: Identity, state_info: web::Json<StateChange>) -> impl Responder {
    if let Some(_) = id.identity() {
        let mut state = APP_STATE.lock().unwrap();
        *state = state_info.state.clone();

        HttpResponse::Ok().body(format!("State updated to {:?}", state_info.state))
    } else {
        HttpResponse::Unauthorized().body("Unauthorized")
    }
}

async fn login(id: Identity, info: web::Json<LoginInfo>) -> impl Responder {
    let login_info: LoginInfo = info.into_inner();
    let hashed_password: String = env::var("HASHED_PASSWORD").expect("HASHED_PASSWORD must be set");

    if login_info.username == "admin"
        && verify(login_info.password, &hashed_password).unwrap_or(false)
    {
        id.remember(login_info.username);
        HttpResponse::Ok().body("Logged in")
    } else {
        HttpResponse::Unauthorized().body(format!("Incorrect username or password"))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("auth-cookie")
                    .secure(false),
            ))
            .service(web::resource("/get_state").route(web::get().to(get_state)))
            .service(web::resource("/set_state").route(web::post().to(set_state)))
            .service(web::resource("/login").route(web::post().to(login)))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

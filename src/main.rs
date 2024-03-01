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

#[derive(Deserialize)]
struct StateChangeWithPassword {
    state: State,
    password: String,
}

async fn get_state() -> impl Responder {
    let state = APP_STATE.lock().unwrap();
    let (color, state_text) = match *state {
        State::Active => ("lightgreen", "Active"),
        State::Inactive => ("coral", "Inactive"),
    };

    let html = format!(
        "<html>
            <head>
                <title>Application State</title>
                <style>
                    body {{
                        font-family: 'Arial', sans-serif;
                        color: white;
                        background-color: {};
                        padding: 20px;
                        text-align: center;
                    }}
                    h1 {{
                        font-size: 2em;
                    }}
                </style>
            </head>
            <body>
                <h1>Current State: {}</h1>
            </body>
        </html>",
        color, state_text
    );
    HttpResponse::Ok().content_type("text/html").body(html)
}

async fn get_set_state_form() -> impl Responder {
    let html = "
        <html>
            <head><title>Set State</title></head>
            <body>
                <h1>Set State</h1>
                <form action='/set_state' method='post'>
                    <label for='state'>State:</label>
                    <select id='state' name='state'>
                        <option value='Active'>Active</option>
                        <option value='Inactive'>Inactive</option>
                    </select>
                    <label for='password'>Password:</label>
                    <input type='password' id='password' name='password' required>
                    <input type='submit' value='Set State'>
                </form>
            </body>
        </html>";
    HttpResponse::Ok().content_type("text/html").body(html)
}

async fn set_state(_id: Identity, form: web::Form<StateChangeWithPassword>) -> impl Responder {
    // Extract the form data
    let StateChangeWithPassword { state, password } = form.into_inner();

    let hashed_password: String = env::var("HASHED_PASSWORD").expect("HASHED_PASSWORD must be set");

    if verify(&password, &hashed_password).unwrap_or(false) {
        let mut app_state = APP_STATE.lock().unwrap();
        *app_state = state.clone();
        HttpResponse::Ok().content_type("text/html").body(format!(
            "<html><body><h1>State updated to {}</h1></body></html>",
            state
        ))
    } else {
        // Authentication failed
        HttpResponse::Unauthorized()
            .content_type("text/html")
            .body("<html><body><h1>Unauthorized</h1></body></html>")
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
            .service(web::resource("/").route(web::get().to(get_state)))
            .service(web::resource("/get_state").route(web::get().to(get_state)))
            .service(web::resource("/set_state_form").route(web::get().to(get_set_state_form)))
            .service(web::resource("/set_state").route(web::post().to(set_state)))
            .service(web::resource("/login").route(web::post().to(login)))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

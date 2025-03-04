use actix_web::{web, HttpResponse, Responder};

async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Welcome to the Barber Shop API!")
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/").route(web::get().to(hello)));
}

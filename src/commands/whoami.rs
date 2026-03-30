use crate::client::MlabClient;

pub fn run(client: &MlabClient) {
    match client.get("/") {
        Ok(resp) => crate::commands::print_response(resp),
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    }
}

use crate::client::MlabClient;

pub fn domain(client: &MlabClient, domain: &str) {
    match client.get(&format!("/scan/domain/status?domain={}", domain)) {
        Ok(resp) => crate::commands::print_response(resp),
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    }
}

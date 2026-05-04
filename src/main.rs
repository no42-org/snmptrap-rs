use std::process::ExitCode;

fn main() -> ExitCode {
    match snmptrap_rs::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            err.report_to_stderr();
            ExitCode::from(err.exit_code())
        }
    }
}

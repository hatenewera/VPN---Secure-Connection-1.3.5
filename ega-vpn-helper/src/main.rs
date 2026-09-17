#![cfg_attr(windows, windows_subsystem = "windows")]

use std::{env, fs::{self, OpenOptions}, io::Write, path::PathBuf, process::{Command, Stdio}};

fn write_result(path: &PathBuf, ok: bool, message: &str) {
    let _ = fs::write(path, format!("{}\n{}", if ok { "OK" } else { "ERROR" }, message));
}

fn start(config: PathBuf, xray: PathBuf, runtime: PathBuf) -> Result<(), String> {
    fs::create_dir_all(&runtime).map_err(|e| e.to_string())?;
    let result = runtime.join("helper-result.txt");
    let pid_file = runtime.join("xray.pid");
    let log_path = runtime.join("xray.log");
    let log = OpenOptions::new().create(true).append(true).open(&log_path).map_err(|e| e.to_string())?;
    let test = Command::new(&xray).args(["run", "-test", "-c"]).arg(&config).output().map_err(|e| format!("Xray test failed: {e}"))?;
    if !test.status.success() {
        let stderr = String::from_utf8_lossy(&test.stderr);
        write_result(&result, false, &format!("Xray config error: {stderr}"));
        return Err(format!("Xray config error: {stderr}"));
    }
    let child = Command::new(&xray)
        .args(["run", "-c"]).arg(&config)
        .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
        .stderr(Stdio::from(log))
        .current_dir(&runtime)
        .spawn().map_err(|e| format!("Cannot start Xray: {e}"))?;
    fs::write(&pid_file, child.id().to_string()).map_err(|e| e.to_string())?;
    write_result(&result, true, &format!("Xray started, PID {}", child.id()));
    Ok(())
}

fn stop(runtime: PathBuf) -> Result<(), String> {
    fs::create_dir_all(&runtime).map_err(|e| e.to_string())?;
    let result = runtime.join("helper-result.txt");
    let pid_file = runtime.join("xray.pid");
    if let Ok(pid) = fs::read_to_string(&pid_file) {
        let pid = pid.trim();
        if !pid.is_empty() {
            let status = Command::new("taskkill").args(["/PID", pid, "/T", "/F"]).status().map_err(|e| e.to_string())?;
            if !status.success() {
                write_result(&result, false, &format!("taskkill failed for PID {pid}"));
                return Err(format!("Cannot stop Xray PID {pid}"));
            }
        }
    }
    let _ = fs::remove_file(&pid_file);
    write_result(&result, true, "Xray stopped");
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 { return; }
    let command = args[1].as_str();
    let result = match command {
        "start" if args.len() >= 5 => start(PathBuf::from(&args[2]), PathBuf::from(&args[3]), PathBuf::from(&args[4])),
        "stop" if args.len() >= 3 => stop(PathBuf::from(&args[2])),
        _ => Err("Invalid helper command".into()),
    };
    if let Err(e) = result {
        if args.len() >= 5 && command == "start" { write_result(&PathBuf::from(&args[4]).join("helper-result.txt"), false, &e); }
        if args.len() >= 3 && command == "stop" { write_result(&PathBuf::from(&args[2]).join("helper-result.txt"), false, &e); }
    }
}

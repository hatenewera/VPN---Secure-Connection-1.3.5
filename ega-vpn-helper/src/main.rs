#![cfg_attr(windows, windows_subsystem = "windows")]

use std::{env, fs::{self, OpenOptions}, io::Write, path::PathBuf, process::{Command, Stdio}, time::Duration};

fn write_result(path: &PathBuf, ok: bool, message: &str) {
    let _ = fs::write(path, format!("{}\n{}", if ok { "OK" } else { "ERROR" }, message));
}

fn start(config: PathBuf, xray: PathBuf, runtime: PathBuf) -> Result<(), String> {
    fs::create_dir_all(&runtime).map_err(|e| e.to_string())?;
    let result = runtime.join("helper-result.txt");
    let pid_file = runtime.join("xray.pid");
    let log_path = runtime.join("xray.log");
    let _ = fs::remove_file(&result);
    let _ = fs::remove_file(&pid_file);
    let mut log = OpenOptions::new().create(true).append(true).open(&log_path).map_err(|e| e.to_string())?;
    writeln!(log, "\n--- EGA VPN helper start ---").ok();
    if !xray.exists() { let e=format!("Xray executable not found: {}", xray.display()); write_result(&result,false,&e); return Err(e); }
    if !config.exists() { let e=format!("Xray config not found: {}", config.display()); write_result(&result,false,&e); return Err(e); }
    let test = Command::new(&xray).args(["run", "-test", "-c"]).arg(&config).output().map_err(|e| format!("Cannot execute Xray config test: {e}"))?;
    if !test.status.success() {
        let stdout=String::from_utf8_lossy(&test.stdout);
        let stderr=String::from_utf8_lossy(&test.stderr);
        let detail=format!("Xray config test failed (exit {:?})\nSTDOUT: {}\nSTDERR: {}", test.status.code(), stdout.trim(), stderr.trim());
        writeln!(log, "{}", detail).ok();
        write_result(&result, false, &detail);
        return Err(detail);
    }
    let mut child = Command::new(&xray)
        .args(["run", "-c"]).arg(&config)
        .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
        .stderr(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
        .current_dir(&runtime)
        .spawn().map_err(|e| format!("Cannot start Xray process: {e}"))?;
    let pid=child.id();
    fs::write(&pid_file, pid.to_string()).map_err(|e| e.to_string())?;
    std::thread::sleep(Duration::from_secs(2));
    match child.try_wait() {
        Ok(Some(status)) => {
            let detail=format!("Xray exited immediately. Exit code: {:?}.\nXray log:\n{}", status.code(), tail(&log_path,40));
            write_result(&result,false,&detail);
            let _=fs::remove_file(&pid_file);
            return Err(detail);
        }
        Ok(None) => {
            writeln!(log, "Xray process is running, PID {}", pid).ok();
            write_result(&result,true,&format!("Xray started successfully, PID {}\nXray log:\n{}",pid,tail(&log_path,20)));
        }
        Err(e) => {
            let detail=format!("Cannot query Xray process: {e}\nXray log:\n{}",tail(&log_path,40));
            write_result(&result,false,&detail);
            return Err(detail);
        }
    }
    Ok(())
}

fn tail(path:&PathBuf, lines:usize)->String {
    fs::read_to_string(path).unwrap_or_default().lines().rev().take(lines).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n")
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

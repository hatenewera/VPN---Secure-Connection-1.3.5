use std::{fs::{self,OpenOptions},io::Write,process::{Command,Stdio},sync::Mutex};
use tauri::{Manager, window::{Color, Effect, EffectState, EffectsBuilder}};

struct State(Mutex<bool>);

fn runtime_dir(_app:&tauri::AppHandle)->Result<std::path::PathBuf,String>{
    let base=dirs::data_local_dir().ok_or("Cannot find LOCALAPPDATA")?.join("EGA VPN");
    fs::create_dir_all(&base).map_err(|e|e.to_string())?; Ok(base)
}

#[tauri::command]
fn fetch_subscription(url:String)->Result<String,String>{
    let u=url.trim();
    if !(u.starts_with("https://") || u.starts_with("http://")){return Err("Subscription URL must start with http:// or https://".into())}
    let client=reqwest::blocking::Client::builder()
        .user_agent("EGA-VPN/1.1")
        .timeout(std::time::Duration::from_secs(20))
        .build().map_err(|e|format!("HTTP client error: {e}"))?;
    let r=client.get(u).send().map_err(|e|format!("Subscription download failed: {e}"))?;
    if !r.status().is_success(){return Err(format!("Subscription returned HTTP {}",r.status()))}
    r.text().map_err(|e|format!("Cannot read subscription: {e}"))
}

#[tauri::command]
fn xray_start(app:tauri::AppHandle, config:String, state:tauri::State<State>)->Result<(),String>{
    if config.trim().is_empty(){return Err("Empty Xray configuration".into())}
    let mut guard=state.0.lock().map_err(|_|"State lock failed")?;
    if *guard{return Err("VPN is already running".into())}
    let dir=runtime_dir(&app)?;
    let cfg=dir.join("config.json");
    fs::write(&cfg,&config).map_err(|e|format!("Cannot write config: {e}"))?;
    let resource=app.path().resource_dir().map_err(|e|e.to_string())?;
    let helper=resource.join("ega-vpn-helper.exe");
    let xray=resource.join("xray.exe");
    if !helper.exists(){return Err(format!("VPN helper not found: {}",helper.display()))}
    if !xray.exists(){return Err(format!("Xray core not found: {}",xray.display()))}
    let ps=format!("Start-Process -FilePath '{}' -ArgumentList @('start','{}','{}','{}') -Verb RunAs -Wait", helper.display().to_string().replace("'","''"), cfg.display().to_string().replace("'","''"), xray.display().to_string().replace("'","''"), dir.display().to_string().replace("'","''"));
    let out=Command::new("powershell").args(["-NoProfile","-NonInteractive","-Command",&ps]).output().map_err(|e|format!("Cannot elevate VPN helper: {e}"))?;
    if !out.status.success(){return Err("Windows elevation was cancelled or failed".into())}
    let result=dir.join("helper-result.txt");
    let _=fs::remove_file(&result);
    let _=fs::remove_file(dir.join("xray.log"));
    let mut text=String::new();
    for _ in 0..30 {
        if let Ok(t)=fs::read_to_string(&result) {
            if !t.trim().is_empty() { text=t; break; }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !text.starts_with("OK") {
        let detail=trimmed_or_default(&text);
        let xlog=fs::read_to_string(dir.join("xray.log")).unwrap_or_default();
        let tail=xlog.lines().rev().take(40).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
        return Err(if tail.is_empty(){detail}else{format!("{}\n\nXray log:\n{}",detail,tail)});
    }
    *guard=true;
    Ok(())
}

#[tauri::command]
fn xray_stop(app:tauri::AppHandle, state:tauri::State<State>)->Result<(),String>{
    let dir=runtime_dir(&app)?;
    let resource=app.path().resource_dir().map_err(|e|e.to_string())?;
    let helper=resource.join("ega-vpn-helper.exe");
    if helper.exists(){
        let ps=format!("Start-Process -FilePath '{}' -ArgumentList @('stop','{}') -Verb RunAs -Wait", helper.display().to_string().replace("'","''"), dir.display().to_string().replace("'","''"));
        let out=Command::new("powershell").args(["-NoProfile","-NonInteractive","-Command",&ps]).output().map_err(|e|format!("Cannot elevate VPN helper: {e}"))?;
        if !out.status.success(){return Err("Windows elevation was cancelled or failed".into())}
        let result=dir.join("helper-result.txt");
        let text=fs::read_to_string(&result).unwrap_or_default();
        if !text.starts_with("OK"){return Err(trimmed_or_default(&text));}
    }
    let mut g=state.0.lock().map_err(|_|"State lock failed")?;
    *g=false;
    Ok(())
}

#[tauri::command]
fn xray_status(state:tauri::State<State>)->bool{state.0.lock().map(|g|*g).unwrap_or(false)}

#[tauri::command]
fn xray_ping(host:String,_port:u16)->Result<u32,String>{
    use std::process::Command;
    let out=Command::new("ping")
        .args(["-n","1","-w","3000",&host])
        .output()
        .map_err(|e|format!("Cannot start Windows ping: {e}"))?;
    let text=format!("{}\n{}",String::from_utf8_lossy(&out.stdout),String::from_utf8_lossy(&out.stderr));
    let re=regex::Regex::new(r"(?i)(?:<\s*)?(\d+)\s*ms").map_err(|e|e.to_string())?;
    if let Some(c)=re.captures(&text){
        return c.get(1).and_then(|m|m.as_str().parse::<u32>().ok()).ok_or_else(||"Invalid ping value".into());
    }
    Err(format!("Ping failed: {}",text.lines().filter(|x|!x.trim().is_empty()).last().unwrap_or("no response").trim()))
}

#[derive(serde::Serialize)] struct Stats{received:u64,sent:u64}
#[tauri::command]
fn xray_stats()->Result<Stats,String>{
 let ps=r#"$a=Get-NetAdapterStatistics | Where-Object {$_.Name -like 'EGA-VPN*'} | Select-Object -First 1; if($a){Write-Output ($a.ReceivedBytes.ToString() + '|' + $a.SentBytes.ToString())}"#;
 let o=Command::new("powershell").args(["-NoProfile","-NonInteractive","-Command",ps]).output().map_err(|e|e.to_string())?;
 let s=String::from_utf8_lossy(&o.stdout).trim().to_string(); let p:Vec<_>=s.split('|').collect();if p.len()!=2{return Ok(Stats{received:0,sent:0})}Ok(Stats{received:p[0].trim().parse().unwrap_or(0),sent:p[1].trim().parse().unwrap_or(0)})
}

fn trimmed_or_default(text:&str)->String{ let v=text.lines().skip(1).collect::<Vec<_>>().join("\n").trim().to_string(); if v.is_empty(){"VPN helper failed: helper-result.txt contained no diagnostic details".into()}else{v} }

pub fn run(){
    tauri::Builder::default()
        .manage(State(Mutex::new(false)))
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_effects(
                    EffectsBuilder::new()
                        .effect(Effect::Acrylic)
                        .state(EffectState::Active)
                        .color(Color(18, 20, 26, 225))
                        .build(),
                );
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![fetch_subscription,xray_start,xray_stop,xray_status,xray_ping,xray_stats])
        .run(tauri::generate_context!())
        .expect("error while running EGA VPN");
}

extern crate x11;

use x11::xlib::*;
use x11::xss::*;
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{process, thread};
use std::time::Duration;
use paho_mqtt::{Client, ConnectOptionsBuilder};
use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    idle_threshold: Option<u64>,
    #[arg(short, long)]
    server_address: Option<String>,
    #[arg(short, long)]
    user_name: Option<String>,
    #[arg(short, long)]
    password: Option<String>,
}

fn get_idle_time(display: *mut Display) -> Option<u64> {
    let xss_info = unsafe { XScreenSaverAllocInfo() };
    if xss_info.is_null() {
        return None;
    }

    let root_window = unsafe { XDefaultRootWindow(display) };
    let status = unsafe { XScreenSaverQueryInfo(display, root_window, xss_info) };
    if status == 0 {
        unsafe { XFree(xss_info as *mut _) };
        return None;
    }

    let idle_time = unsafe { (*xss_info).idle };
    unsafe { XFree(xss_info as *mut _) };
    Some(idle_time)
}

fn send_idle_state(state: bool, cli: &Client) {
    let payload: &str;
    match state {
        true => {
            println!("Computer is idle");
            payload = "idle"
        }
        false => {
            println!("Computer is active");
            payload = "active"
        }
    }
    let msg = paho_mqtt::MessageBuilder::new()
        .topic("battlestation")
        .payload(payload)
        .qos(0)
        .finalize();

    if let Err(e) = cli.publish(msg) {
        println!("Error sending message: {:?}", e);
    }
}

fn main() {
    let cli = Cli::parse();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    let idle_threshold = match cli.idle_threshold {
        None => {
            println!("No idle threshold set");
            process::exit(1)
        }
        Some(threshold) => { threshold }
    };

    let server_address = match cli.server_address {
        None => {
            println!("No server address set");
            process::exit(1);
        }
        Some(address) => {
            address
        }
    };

    let username = match cli.user_name {
        None => {
            println!("No username set");
            process::exit(1);
        }
        Some(username) => {
            username
        }
    };

    let password = match cli.password {
        None => {
            println!("No password set");
            process::exit(1);
        }
        Some(password) => {
            password
        }
    };

    let mut client = Client::new(server_address.to_string()).unwrap_or_else(|e| {
        println!("Error creating the client: {:?}", e);
        process::exit(1);
    });

    client.set_timeout(Duration::from_secs(5));

    let connect_opts = ConnectOptionsBuilder::new()
        .user_name(username)
        .password(password)
        .finalize();

    if let Err(e) = client.connect(connect_opts) {
        println!("Unable to connect: {:?}", e);
        process::exit(1);
    }

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting CTRL-C handler");

    let display = unsafe { XOpenDisplay(null_mut()) };
    if display.is_null() {
        panic!("Unable to open X display");
    }

    while running.load(Ordering::SeqCst) {
        match get_idle_time(display) {
            Some(idle_time) => {
                println!("Idle time: {} milliseconds", idle_time);
                if idle_time > idle_threshold { send_idle_state(true, &client) } else { send_idle_state(false, &client) }
            }
            None => eprintln!("Failed to query idle time"),
        }

        thread::sleep(Duration::from_secs(1));
    }

    println!("Exit signal received, cleaning up..");

    unsafe { XCloseDisplay(display) };
}

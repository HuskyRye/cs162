use std::env;
use std::path::Path;
use std::sync::Arc;

use crate::args;

use crate::http::*;
use crate::stats::*;

use clap::Parser;
use tokio::fs;
use tokio::fs::{read_dir, File};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use bytes::BytesMut;

use anyhow::Result;

pub fn main() -> Result<()> {
    // Configure logging
    // You can print logs (to stderr) using
    // `log::info!`, `log::warn!`, `log::error!`, etc.
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Parse command line arguments
    let args = args::Args::parse();

    // Set the current working directory
    env::set_current_dir(&args.files)?;

    // Print some info for debugging
    log::info!("HTTP server initializing ---------");
    log::info!("Port:\t\t{}", args.port);
    log::info!("Num threads:\t{}", args.num_threads);
    log::info!("Directory:\t\t{}", &args.files);
    log::info!("----------------------------------");

    // Initialize a new StatsPtr instance
    let stats_ptr = StatsPtr::new(RwLock::new(Stats::new()));

    // Initialize a thread pool that starts running `listen`
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(args.num_threads)
        .build()?
        .block_on(listen(args.port, stats_ptr))
}

async fn listen(port: u16, stats_ptr: StatsPtr) -> Result<()> {
    // Hint: you should call `handle_socket` in this function.
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    loop {
        let (socket, _) = listener.accept().await?;
        let cloned = Arc::clone(&stats_ptr);
        tokio::spawn(async move { handle_socket(socket, cloned).await });
    }
}

async fn serve_file(mut socket: TcpStream, path: &str) -> Result<()> {
    start_response(&mut socket, 200).await?;
    send_header(&mut socket, "Content-Type", get_mime_type(path)).await?;
    let len = fs::metadata(path).await?.len();
    send_header(&mut socket, "Content-Length", &(len.to_string())).await?;
    end_headers(&mut socket).await?;

    let mut file = File::open(path).await?;
    let mut buffer = BytesMut::with_capacity(1024);

    while file.read_buf(&mut buffer).await? > 0 {
        socket.write_all_buf(&mut buffer).await?;
    }
    Ok(())
}

async fn serve_directory(mut socket: TcpStream, path: &str) -> Result<()> {
    let mut content = String::new();
    let mut dir = read_dir(path).await?;
    content.push_str("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"UTF-8\"\n</head>\n<body>\n");
    content.push_str(&format_href(
        Path::new(&format!("{}/../", path)).to_str().unwrap(),
        "..",
    ));
    content.push_str(&format_href(path, "."));
    while let Some(entry) = dir.next_entry().await? {
        content.push_str(&format_href(
            entry.path().to_str().unwrap(),
            entry.file_name().to_str().unwrap(),
        ));
    }
    content.push_str("\n</body>\n</html>\n");
    start_response(&mut socket, 200).await?;
    send_header(&mut socket, "Content-Type", "text/html").await?;
    send_header(&mut socket, "Content-Length", &(content.len().to_string())).await?;
    end_headers(&mut socket).await?;
    socket.write_all(content.as_bytes()).await?;
    Ok(())
}

// Handles a single connection via `socket`.
async fn handle_socket(mut socket: TcpStream, stats_ptr: StatsPtr) -> Result<()> {
    let request = parse_request(&mut socket).await?;
    if request.path == "/stats" {
        let stats = stats_ptr.read().await;
        start_response(&mut socket, 200).await?;
        send_header(&mut socket, "Content-Type", "text/plain").await?;
        end_headers(&mut socket).await?;
        for (status_code, counts) in stats.items() {
            let msg = format!("{}: {}\n", response_message(status_code), counts);
            socket.write_all((&msg).as_bytes()).await?;
        }
    } else {
        let request_path = format!(".{}", request.path);
        let path = Path::new(&request_path);
        if path.exists() {
            if path.is_dir() {
                let index_path = format_index(&request_path);
                if Path::new(&index_path).exists() {
                    serve_file(socket, &index_path).await?;
                } else {
                    serve_directory(socket, &request_path).await?;
                }
            } else if path.is_file() {
                serve_file(socket, &request_path).await?;
            }
            incr(&stats_ptr, 200).await;
        } else {
            start_response(&mut socket, 404).await?;
            end_headers(&mut socket).await?;
            incr(&stats_ptr, 404).await;
        }
    }
    Ok(())
}

// You are free (and encouraged) to add other funtions to this file.
// You can also create your own modules as you see fit.

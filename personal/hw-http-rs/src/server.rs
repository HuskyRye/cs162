use std::env;

use crate::args;

use crate::http::*;
use crate::stats::*;

use clap::Parser;
use tokio::fs;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

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

    // Initialize a thread pool that starts running `listen`
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(args.num_threads)
        .build()?
        .block_on(listen(args.port))
}

async fn listen(port: u16) -> Result<()> {
    // Hint: you should call `handle_socket` in this function.
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    loop {
        let (socket, _) = listener.accept().await?;
        tokio::spawn(async move { handle_socket(socket).await });
    }
}

// Handles a single connection via `socket`.
async fn handle_socket(mut socket: TcpStream) -> Result<()> {
    let request = parse_request(&mut socket).await?;
    let path = format!(".{}", request.path);
    match fs::metadata(&path).await {
        Ok(metadata) => {
            start_response(&mut socket, 200).await?;
            send_header(&mut socket, "Content-Type", get_mime_type(&path)).await?;
            send_header(&mut socket, "Content-Length", &metadata.len().to_string()).await?;
            end_headers(&mut socket).await?;

            let mut file = File::open(&path).await?;
            let mut buffer = BytesMut::with_capacity(1024);

            while file.read_buf(&mut buffer).await? > 0 {
                println!("write {} bytes", buffer.len());
                socket.write_all_buf(&mut buffer).await?;
            }
        }
        Err(_) => {
            start_response(&mut socket, 404).await?;
            end_headers(&mut socket).await?;
        }
    };
    Ok(())
}

// You are free (and encouraged) to add other funtions to this file.
// You can also create your own modules as you see fit.

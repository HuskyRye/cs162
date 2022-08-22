//! A MapReduce worker.
//!

use std::net::SocketAddr;

use crate::rpc::coordinator::coordinator_client::CoordinatorClient;
use crate::rpc::worker::*;
use crate::*;
use tonic::transport::{Channel, Server};

use crate::rpc::worker::*;

use anyhow::Result;

pub mod args;

pub struct WorkerState {
    // Add your own fields
}

#[derive(Clone)]
pub struct Worker {
    id: u32,
    // Add your own fields
}

impl Worker {
    pub async fn new() -> Result<Self> {
        // Connect to the coordinator
        let mut client = CoordinatorClient::connect(format!("http://{}", COORDINATOR_ADDR)).await?;
        todo!()
    }

    pub async fn run(mut self) -> Result<()> {
        todo!()
    }
}

#[tonic::async_trait]
impl worker_server::Worker for Worker {
    // TODO: implement Worker RPCs
}

async fn worker_server(worker: Worker) -> Result<()> {
    let addr = get_addr(worker.id);
    let svc = worker_server::WorkerServer::new(worker);
    Server::builder().add_service(svc).serve(addr).await?;

    Ok(())
}

pub async fn start(_args: args::Args) -> Result<()> {
    let worker: Worker = todo!("Create a worker");

    let server = worker.clone();
    tokio::spawn(async move { worker_server(server).await });

    worker.run().await?;

    Ok(())
}

fn get_port(id: WorkerId) -> u16 {
    let port = INITIAL_WORKER_PORT as WorkerId + id;
    assert!(port <= u16::MAX as WorkerId);
    port as u16
}

fn get_addr(id: WorkerId) -> SocketAddr {
    format!("127.0.0.1:{}", get_port(id)).parse().unwrap()
}

async fn connect(id: WorkerId) -> Result<worker_client::WorkerClient<Channel>> {
    let client =
        worker_client::WorkerClient::connect(format!("http://127.0.0.1:{}", get_port(id))).await?;
    Ok(client)
}

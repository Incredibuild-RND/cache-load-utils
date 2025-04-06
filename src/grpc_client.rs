use std::cmp;
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context};
use bazel_remote_apis_rs::build::bazel::remote::execution::v2::ActionResult;
use bazel_remote_apis_rs::build::bazel::remote::execution::v2::Digest;
use bazel_remote_apis_rs::build::bazel::remote::execution::v2::FindMissingBlobsRequest;
use bazel_remote_apis_rs::build::bazel::remote::execution::v2::GetActionResultRequest;
use bazel_remote_apis_rs::build::bazel::remote::execution::v2::GetCapabilitiesRequest;
use bazel_remote_apis_rs::build::bazel::remote::execution::v2::OutputFile;
use bazel_remote_apis_rs::build::bazel::remote::execution::v2::RequestMetadata;
use bazel_remote_apis_rs::build::bazel::remote::execution::v2::ServerCapabilities;
use bazel_remote_apis_rs::build::bazel::remote::execution::v2::ToolDetails;
use bazel_remote_apis_rs::build::bazel::remote::execution::v2::UpdateActionResultRequest;
use bazel_remote_apis_rs::build::bazel::remote::execution::v2::action_cache_client::ActionCacheClient;
use bazel_remote_apis_rs::build::bazel::remote::execution::v2::capabilities_client::CapabilitiesClient;
use bazel_remote_apis_rs::build::bazel::remote::execution::v2::content_addressable_storage_client::ContentAddressableStorageClient;
use bazel_remote_apis_rs::google::bytestream::byte_stream_client::ByteStreamClient;
use bazel_remote_apis_rs::google::bytestream::{ReadRequest, WriteRequest};
use prost::Message;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::codegen::InterceptedService;
use tonic::metadata::{Ascii, Binary, MetadataValue};
use tonic::{Request, Status};
use tonic::service::Interceptor;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Uri};
use uuid::Uuid;
use crate::{blob, prom};
use crate::bench_config::BenchmarkConfig;
use crate::prom::{BS_BYTES_READ_COLLECTOR, BS_BYTES_WRITTEN_COLLECTOR, CONNECT_COLLECTOR, TrackedResult};
use crate::prom::CAS_FIND_MISSING_COLLECTOR;
use crate::prom::BS_WRITE_COLLECTOR;
use crate::prom::BS_READ_COLLECTOR;
use crate::prom::AC_WRITE_COLLECTOR;
use crate::prom::AC_READ_COLLECTOR;
use crate::prom::GET_CAPS_COLLECTOR;

#[derive(Clone, Debug)]
pub(crate) struct RemoteClient {
    cfg: BenchmarkConfig,
    cc: CapabilitiesClient<AuthenticatedService>,
    ac: ActionCacheClient<AuthenticatedService>,
    bs: ByteStreamClient<AuthenticatedService>,
    cas: ContentAddressableStorageClient<AuthenticatedService>
}

type AuthenticatedService = InterceptedService<Channel, BenchmarkInterceptor>;

#[derive(Clone, Debug)]
pub(crate) struct BenchmarkInterceptor {
    pub(crate) token: Option<MetadataValue<Ascii>>,
    pub(crate) rmd_header: MetadataValue<Binary>
}

impl Interceptor for BenchmarkInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(token) = self.token.clone() {
            request.metadata_mut().insert("authorization", token);
        }
        request.metadata_mut().insert_bin("build.bazel.remote.execution.v2.requestmetadata-bin", self.rmd_header.clone());
        Ok(request)
    }
}

impl RemoteClient {

    pub async fn connect(cfg: &BenchmarkConfig) -> anyhow::Result<RemoteClient> {
        let token_md: Option<MetadataValue<Ascii>> = match &cfg.auth_header {
            None => None,
            Some(t) => Some(t.parse()?)
        };
        
        let iid = Uuid::new_v4().to_string();
        let rmd = RequestMetadata{
            tool_details: Some(ToolDetails{
                tool_name: "bazelbench".to_string(),
                tool_version: "".to_string()
            }),
            action_id: "".to_string(),
            tool_invocation_id: iid.clone(),
            correlated_invocations_id: "".to_string(),
            action_mnemonic: "".to_string(),
            target_id: "".to_string(),
            configuration_id: "".to_string(),
        };
        let mut buf = vec![];
        rmd.encode(&mut buf)?;
        let rmd_header = MetadataValue::from_bytes(buf.as_slice());
        
        let interceptor = BenchmarkInterceptor {token: token_md.clone(), rmd_header};
        let chan = connect_inner(cfg.target_endpoint.as_str())
            .await
            .track_err(&CONNECT_COLLECTOR, cfg.label.as_str())?;

        Ok(RemoteClient {
            cfg: cfg.clone(),
            cc: CapabilitiesClient::with_interceptor(chan.clone(), interceptor.clone()),
            ac: ActionCacheClient::with_interceptor(chan.clone(), interceptor.clone()),
            bs: ByteStreamClient::with_interceptor(chan.clone(), interceptor.clone()),
            cas: ContentAddressableStorageClient::with_interceptor(chan.clone(), interceptor.clone()),
        })
    }

    pub(crate) async fn call_capabilities(&mut self) -> anyhow::Result<ServerCapabilities> {
        let now = Instant::now();
        let caps = self.cc.get_capabilities(GetCapabilitiesRequest {
            instance_name: self.cfg.remote_instance_name.clone(),
        }).await?.into_inner();
        prom::track_rpc_success(&GET_CAPS_COLLECTOR, now, self.cfg.label.as_str());
        // todo: verify caps someday?
        Ok(caps)
    }

    pub(crate) async fn call_ac_write(&mut self, output_files: &Vec<OutputFile>) -> anyhow::Result<(Digest, ActionResult)> {
        let (digest, result) = self.create_fake_action_result(output_files)?;
        let now = Instant::now();
        let reply_result = self.ac.update_action_result(UpdateActionResultRequest {
            instance_name: self.cfg.remote_instance_name.clone(),
            action_digest: Some(digest.clone()),
            action_result: Some(result.clone()),
            results_cache_policy: None,
            digest_function: self.cfg.digest_function.clone().into(),
        }).await?.into_inner();
        prom::track_rpc_success(&AC_WRITE_COLLECTOR, now, self.cfg.label.as_str());
        Ok((digest, reply_result))
    }

    pub(crate) async fn call_write(&mut self, file_blob_tups: Vec<(OutputFile, Vec<u8>)>) -> anyhow::Result<()> {
        let id = Uuid::new_v4();
        for (file, blob) in file_blob_tups {
            // create reqs for this file
            let blob_size = blob.len() as usize;
            let digest = file.digest.unwrap();
            let mut messages = vec![];
            let mut offset: usize = 0;

            while offset < blob_size {
                let seek = cmp::min(blob_size - offset, self.cfg.chunk_size);
                let rn =  match offset == 0 {
                    true => format!("{}/uploads/{}/blobs/{}/{}",
                                         self.cfg.remote_instance_name.clone(),
                                         id.to_string(),
                                         digest.hash,
                                         digest.size_bytes),
                    false => "".to_string()
                };
                messages.push(WriteRequest {
                    resource_name: rn,
                    write_offset: offset as i64,
                    finish_write: offset >= blob_size-seek,
                    data: blob[offset..offset+seek].to_owned(),
                });
                offset += seek;
            }
            // send the reqs
            let now = Instant::now();
            let r = Request::new(tokio_stream::iter(messages));
            let committed = self.bs.write(r).await.unwrap().into_inner().committed_size;
            prom::track_rpc_success(
                &BS_WRITE_COLLECTOR,
                now,
                self.cfg.label.as_str()
            );
            if committed != blob_size as i64 {
                bail!("server committed wrong size")
            }
            BS_BYTES_WRITTEN_COLLECTOR
                .with_label_values(&[self.cfg.label.as_str()])
                .inc_by(blob_size as u64);
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) async fn call_write_fast(&mut self, file_blob_tups: Vec<(OutputFile, Vec<u8>)>) -> anyhow::Result<()> {
        let id = Uuid::new_v4();
        let cfg_chunk_size = self.cfg.chunk_size.clone();
        let cfg_label = self.cfg.label.clone();
        let cfg_remote_instance_name = self.cfg.remote_instance_name.clone();
        let channel_size_1gib = 1073741824 / self.cfg.chunk_size;

        for (file, blob) in file_blob_tups {
            let cfg_remote_instance_name = cfg_remote_instance_name.clone();
            let blob_size = blob.len() as usize;
            let digest = file.digest.unwrap();
            let (tx, rx) = mpsc::channel(channel_size_1gib);

            tokio::spawn(async move {
                let mut offset = 0;
                while offset < blob_size {
                    let seek = cmp::min(blob_size - offset, cfg_chunk_size);
                    let rn = if offset == 0 {
                        format!("{}/uploads/{}/blobs/{}/{}", cfg_remote_instance_name, id.to_string(), digest.hash, digest.size_bytes)
                    } else {
                        "".to_string()
                    };

                    let data_chunk = blob[offset..offset + seek].to_vec();
                    let write_request = WriteRequest {
                        resource_name: rn,
                        write_offset: offset as i64,
                        finish_write: offset + seek >= blob_size,
                        data: data_chunk,
                    };

                    if tx.send(write_request).await.is_err() {
                        eprintln!("Error sending message through channel");
                        break;
                    }
                    offset += seek;
                }
            });

            let now = Instant::now();
            let request_stream = ReceiverStream::new(rx);
            let request = Request::new(request_stream);
            let response = self.bs.write(request).await?;
            let committed = response.into_inner().committed_size;
            prom::track_rpc_success(&BS_WRITE_COLLECTOR, now, cfg_label.as_str());

            if committed != blob_size as i64 {
                bail!("server committed wrong size");
            }
            BS_BYTES_WRITTEN_COLLECTOR.with_label_values(&[cfg_label.as_str()]).inc_by(blob_size as u64);
        }
        Ok(())
    }

    pub(crate) async fn call_ac_read(&mut self, action_digest: Digest, expected_outs: &Vec<OutputFile>) -> anyhow::Result<()> {
        let now = Instant::now();
        let returned_action = self.ac.get_action_result(GetActionResultRequest{
            instance_name: self.cfg.remote_instance_name.clone(),
            action_digest: Some(action_digest),
            inline_stdout: false,
            inline_stderr: false,
            inline_output_files: vec![],
            digest_function: self.cfg.digest_function.clone().into(),
        }).await?.into_inner();
        prom::track_rpc_success(&AC_READ_COLLECTOR, now, self.cfg.label.as_str());
        match &returned_action.output_files == expected_outs {
            true => Ok(()),
            false => Err(anyhow!("unexpected action returned"))
        }
    }

    pub(crate) async fn call_read(&mut self, files: Vec<OutputFile>, verify_hash: bool) -> anyhow::Result<()> {
        let now = Instant::now();
        for file in files {
            let digest = file.digest.clone().unwrap();
            let mut assembled = Vec::with_capacity(digest.size_bytes as usize);
            let r = ReadRequest{
                resource_name: format!("{}/blobs/{}/{}", self.cfg.remote_instance_name.clone(), digest.hash, digest.size_bytes),
                read_offset: 0,
                read_limit: 0,
            };
            let mut s = self.bs.read(r).await?.into_inner();
            while let Some(Ok(mut chunk)) = s.next().await {
                assembled.append(&mut chunk.data);
            }
            prom::track_rpc_success(
                &BS_READ_COLLECTOR,
                now,
                self.cfg.label.as_str(),
            );
            if verify_hash {
                let assembled_digest = blob::blob_to_digest(&assembled, self.cfg.digest_function.clone())?;
                if assembled_digest.hash != digest.hash {
                    bail!("data corruption; wanted {}/{}, got {}/{}", digest.hash, digest.size_bytes, assembled_digest.hash, assembled_digest.size_bytes)
                }
            }
            BS_BYTES_READ_COLLECTOR
                .with_label_values(&[self.cfg.label.as_str()])
                .inc_by(digest.size_bytes as u64);
        }
        Ok(())
    }

    pub(crate) async fn call_find_missing(&mut self, files: &Vec<OutputFile>) -> anyhow::Result<()> {
        let mut digests = files
            .iter()
            .map(|f|f.digest.clone().unwrap()).
            collect::<Vec<Digest>>();
        // ensure find missing works as expected
        let missing_hash = digests[0].hash.chars().rev().collect::<String>();
        digests.push( Digest { hash: missing_hash.clone(), size_bytes: 1234 });
        // call remote
        let now = Instant::now();
        let missing = self.cas.find_missing_blobs(FindMissingBlobsRequest{
            instance_name: self.cfg.remote_instance_name.clone(),
            blob_digests: digests,
            digest_function: self.cfg.digest_function.clone().into(),
        }).await?.into_inner().missing_blob_digests;
        prom::track_rpc_success(&CAS_FIND_MISSING_COLLECTOR, now, self.cfg.label.as_str());
        // verify
        match missing.len() == 1 && missing.first().unwrap().hash == missing_hash {
            true => Ok(()),
            false => Err(anyhow!("find_missing returned unexpected response: {:?}", missing))
        }
    }

    fn create_fake_action_result(&self, output_files: &Vec<OutputFile>) -> anyhow::Result<(Digest, ActionResult)> {
        #[allow(deprecated)] let result = ActionResult {
            output_files: output_files.clone(),
            output_file_symlinks: vec![],
            output_symlinks: vec![],
            output_directories: vec![],
            output_directory_symlinks: vec![],
            exit_code: 1337,
            stdout_raw: vec![],
            stdout_digest: None,
            stderr_raw: vec![],
            stderr_digest: None,
            execution_metadata: None,
        };
        let digest = blob::to_digest(result.clone(), self.cfg.digest_function.clone())?;
        Ok((digest, result))
    }
}

pub(crate) async fn connect_inner(target_endpoint: &str) -> anyhow::Result<Channel> {
    let uri = Uri::from_str(target_endpoint)?;
    let mut builder = Channel::builder(uri.clone())
        .connect_timeout(Duration::from_secs(10));
    // enable SSL if secure endpoint
    if uri.scheme().unwrap().as_str().ends_with("s") {
        let root_ca_cert_path = match std::env::consts::OS {
            "macos" => "/etc/ssl/cert.pem",
            "linux" => "/etc/ssl/certs/ca-certificates.crt",
            _ => "",
        };
        let pem = tokio::fs::read(root_ca_cert_path)
            .await.context(format!("couldn't load root CA cert from {}", root_ca_cert_path))?;
        let cert = Certificate::from_pem(pem);
        builder = builder.tls_config(ClientTlsConfig::new().ca_certificate(cert))?
    }
    // connect
    let chan = builder.connect().await?;
    Ok(chan)
}
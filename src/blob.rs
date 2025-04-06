use std::iter::repeat_with;

use bazel_remote_apis_rs::build::bazel::remote::execution::v2::{Digest as re_Digest, OutputFile};
use fastrand::Rng;
use lazy_static::lazy_static;
use prost::Message;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::bench_config::{BenchmarkConfig, SupportedDigestFunction};
use crate::blob;

pub(crate) fn to_digest<T: Message>(msg: T, digest_fn: SupportedDigestFunction) -> anyhow::Result<re_Digest> {
    let mut buf = vec![];
    msg.encode(&mut buf)?;
    blob_to_digest(&buf, digest_fn)
}

pub(crate) fn blob_to_digest(buf: &Vec<u8>, digest_fn: SupportedDigestFunction) -> anyhow::Result<re_Digest> {
    let l = buf.len() as i64;
    let hash = match digest_fn {
        SupportedDigestFunction::Sha256 => hex::encode(Sha256::digest(buf)),
        SupportedDigestFunction::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            hasher.update_rayon(&buf);
            let hash = hasher.finalize();
            hex::encode(hash.as_bytes())
        }
    };
    Ok(re_Digest { hash, size_bytes: l })
}

pub(crate) fn generate_outputs(
    num_files: usize,
    cfg: &BenchmarkConfig,
    rng_gen: &mut Rng,
    gpu_rng_gen: &mut Option<Box<dyn RngCore + Send>>,
) -> anyhow::Result<Vec<(OutputFile, Vec<u8>)>> {
    let mut r = vec![];
    for _ in 0..num_files {
        let (blob, digest) = generate_blob(cfg, rng_gen, gpu_rng_gen)?;
        r.push((
            OutputFile{
                path: format!("bazelbench/{}", digest.hash),
                digest: Some(digest.clone()),
                is_executable: false,
                contents: vec![],
                node_properties: None,
            },
            blob
        ));
    }
    Ok(r)
}

lazy_static! {
    // 1 GiB of randomized data for use within generate_blob_fast
    pub static ref SHARED_BLOB_DATA: Vec<u8> = repeat_with(|| fastrand::Rng::new().u8(..)).take(1073741824).collect();
}

pub fn generate_blob(
    cfg: &BenchmarkConfig,
    rng_gen: &mut Rng,
    gpu_rng_gen: &mut Option<Box<dyn RngCore + Send>>) -> anyhow::Result<(Vec<u8>, re_Digest)>
{
    let num_random_bytes = cfg.blob_size_bytes * (100 - cfg.zero_pad_blob_pct) / 100;

    let blob: Vec<u8> = if cfg.fast_rng {
        // to ensure no fully duplicated files are sent up, consider always generating a truly
        // fully randomized chunk here?
        generate_blob_fast(num_random_bytes, cfg.pseudorandom_chunk_count, rng_gen)?
    } else {
        if let Some(ref mut rand) = gpu_rng_gen {
            let mut v = Vec::with_capacity(num_random_bytes);
            rand.fill_bytes(&mut v);
            v
        } else {
            repeat_with(|| rng_gen.u8(..)).take(num_random_bytes).collect()
        }
    };

    let remaining_bytes = cfg.blob_size_bytes - blob.len();
    let mut full_blob = blob;
    full_blob.extend(vec![0; remaining_bytes]);
    let d = blob::blob_to_digest(&full_blob, cfg.digest_function.clone())?;
    Ok((full_blob, d))
}

/// This method of RNG is much faster as pre-generated random blob data is reused, with slicing and
/// shuffling in use to "randomize" the static data. As this is subject to collisions, 1 of the chunks
/// is always generated randomly
pub fn generate_blob_fast(
    size: usize,
    chunks: usize,
    rng_gen: &mut Rng,
) -> anyhow::Result<Vec<u8>> {
    let chunk_size = size / chunks;
    let mut indices = Vec::with_capacity(chunks);

    // calculate indices for each chunk
    for i in 0..chunks {
        let start_index = i * chunk_size;
        if start_index < SHARED_BLOB_DATA.len() {
            indices.push(start_index);
        }
    }

    // shuffle the indices
    rng_gen.shuffle(&mut indices);
    let mut blob = Vec::with_capacity(size);

    for &index in &indices {
        let end_index = std::cmp::min(index + chunk_size, SHARED_BLOB_DATA.len());
        blob.extend_from_slice(&SHARED_BLOB_DATA[index..end_index]);
    }

    // handle any remaining bytes if blob_size_bytes is not perfectly divisible by chunk_count
    let remaining_bytes = size % chunks;
    if remaining_bytes > 0 {
        let start_index = rng_gen.usize(0..SHARED_BLOB_DATA.len() - remaining_bytes);
        let remaining_chunk = &SHARED_BLOB_DATA[start_index..start_index + remaining_bytes];
        blob.extend_from_slice(remaining_chunk);
    }

    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_blob_cpu() -> anyhow::Result<()> {
        let cfg = BenchmarkConfig::default();
        fastrand::seed(42);
        let mut rng_gen = fastrand::Rng::new();
        let mut gpu_rng_gen: Option<Box<dyn RngCore + Send>> = None;
        let (blob, digest) = generate_blob(&cfg, &mut rng_gen, &mut gpu_rng_gen)?;

        let num_random_bytes = cfg.blob_size_bytes * (100 - cfg.zero_pad_blob_pct) / 100;
        assert_eq!(blob.len(), 1048576);
        assert_eq!(blob[num_random_bytes..].iter().all(|&x| x == 0), true, "Padding bytes should be zero.");
        Ok(())
    }

    #[test]
    fn test_generate_blob_cpu_large() -> anyhow::Result<()> {
        let cfg = BenchmarkConfig::default_large();
        fastrand::seed(42);
        let mut rng_gen = fastrand::Rng::new();
        let mut gpu_rng_gen: Option<Box<dyn RngCore + Send>> = None;
        let (blob, digest) = generate_blob(&cfg, &mut rng_gen, &mut gpu_rng_gen)?;

        let num_random_bytes = cfg.blob_size_bytes * (100 - cfg.zero_pad_blob_pct) / 100;
        assert_eq!(blob.len(), 1048576);
        assert_eq!(blob[num_random_bytes..].iter().all(|&x| x == 0), true, "Padding bytes should be zero.");
        Ok(())
    }
}
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::Parser;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::ClientBuilder;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;

const VERSION: &str = "1.0";

// =========================================================================
// 1. DNS 适配器
// =========================================================================
#[derive(Debug, Clone)]
pub struct HickoryDnsResolver {
    resolver: TokioAsyncResolver,
}

impl HickoryDnsResolver {
    pub fn new(dns_ip: IpAddr) -> Self {
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new(
            SocketAddr::new(dns_ip, 53),
            Protocol::Udp,
        ));
        let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default());
        Self { resolver }
    }
}

impl Resolve for HickoryDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let lookup = resolver
                .lookup_ip(name.as_str())
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

            let addrs: Addrs = Box::new(lookup.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

pub trait ClientBuilderDnsExt {
    fn set_custom_dns(self, dns_ip: Option<&str>) -> Self;
}

impl ClientBuilderDnsExt for ClientBuilder {
    fn set_custom_dns(mut self, dns_ip: Option<&str>) -> Self {
        if let Some(ip_str) = dns_ip {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                let custom_resolver = HickoryDnsResolver::new(ip);
                self = self.dns_resolver(Arc::new(custom_resolver));
            }
        }
        self
    }
}

// =========================================================================
// 2. Auth 认证逻辑
// =========================================================================
fn parse_www_authenticate(header_val: &str) -> (Option<String>, HashMap<String, String>) {
    let mut params = HashMap::new();
    if !header_val.starts_with("Bearer ") && !header_val.starts_with("bearer ") {
        return (None, params);
    }

    let auth_str = &header_val[7..];
    for part in auth_str.split(',') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            let k = k.trim().to_string();
            let v = v.trim().trim_matches('"').to_string();
            params.insert(k, v);
        }
    }

    let realm = params.remove("realm");
    (realm, params)
}

async fn get_auth_headers(
    client: &reqwest::Client,
    accept_type: &str,
    registry: &str,
    repository: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::ACCEPT, accept_type.parse().unwrap());

    let test_url = format!("https://{}/v2/", registry);
    let resp = client.get(&test_url).send().await;

    let mut realm = None;
    let mut service = None;

    if let Ok(r) = resp {
        if let Some(auth_header) = r.headers().get(reqwest::header::WWW_AUTHENTICATE) {
            if let Ok(auth_str) = auth_header.to_str() {
                let (r_url, params) = parse_www_authenticate(auth_str);
                realm = r_url;
                service = params.get("service").cloned();
            }
        }
    }

    let token_endpoint = realm.unwrap_or_else(|| format!("https://{}/v2/token", registry));
    let service_param = service.unwrap_or_else(|| registry.to_string());

    let token_url = format!(
        "{}?service={}&scope=repository:{}:pull",
        token_endpoint, service_param, repository
    );

    let mut token_req = client.get(&token_url);

    if let (Some(u), Some(p)) = (username, password) {
        let creds = BASE64.encode(format!("{}:{}", u, p));
        token_req = token_req.header(
            reqwest::header::AUTHORIZATION,
            format!("Basic {}", creds),
        );
    }

    if let Ok(token_resp) = token_req.send().await {
        if token_resp.status().is_success() {
            if let Ok(json) = token_resp.json::<Value>().await {
                let token = json
                    .get("token")
                    .or_else(|| json.get("access_token"))
                    .and_then(|v| v.as_str());

                if let Some(t) = token {
                    headers.insert(
                        reqwest::header::AUTHORIZATION,
                        format!("Bearer {}", t).parse().unwrap(),
                    );
                }
            }
        }
    }

    headers
}

// =========================================================================
// 3. CLI 参数
// =========================================================================
#[derive(Parser, Debug)]
#[command(name = "docker-image-download", version = VERSION)]
struct Args {
    image: Option<String>,

    #[arg(short, long)]
    platform: Option<String>,

    #[arg(long)]
    dns: Option<String>,

    #[arg(long, default_value_t = 3)]
    max_concurrent_downloads: usize,

    #[arg(short, long)]
    username: Option<String>,

    #[arg(short, long)]
    password: Option<String>,

    #[arg(long)]
    cache_dir: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    no_cache: bool,
}

fn parse_image_name(image_str: &str) -> (String, String, String) {
    let mut parts: Vec<&str> = image_str.split('/').collect();
    let last = parts.pop().unwrap();

    let (img, tag) = if let Some((i, t)) = last.split_once('@') {
        (i.to_string(), t.to_string())
    } else if let Some((i, t)) = last.split_once(':') {
        (i.to_string(), t.to_string())
    } else {
        (last.to_string(), "latest".to_string())
    };

    let (registry, repo) = if !parts.is_empty() && (parts[0].contains('.') || parts[0].contains(':'))
    {
        let reg = parts.remove(0).to_string();
        let repository = if parts.is_empty() {
            img.clone()
        } else {
            format!("{}/{}", parts.join("/"), img)
        };
        (reg, repository)
    } else {
        let repository = if parts.is_empty() {
            format!("library/{}", img)
        } else {
            format!("{}/{}", parts.join("/"), img)
        };
        ("registry-1.docker.io".to_string(), repository)
    };

    (registry, repo, tag)
}

// =========================================================================
// 4. 标准离线 Tar 打包
// =========================================================================
async fn export_docker_image_tar(
    client: &reqwest::Client,
    headers: &reqwest::header::HeaderMap,
    registry: &str,
    repository: &str,
    tag: &str,
    manifest: &Value,
    cache_dir: &Path,
    output_tar_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📦 正在构建符合 docker load 规范的标准镜像包...");

    let config_digest = manifest["config"]["digest"]
        .as_str()
        .ok_or("Manifest 中缺少 config digest")?;

    let config_url = format!("https://{}/v2/{}/blobs/{}", registry, repository, config_digest);
    let config_resp = client.get(&config_url).headers(headers.clone()).send().await?;
    let config_bytes = config_resp.bytes().await?;

    let config_hash = config_digest.trim_start_matches("sha256:");
    let config_filename = format!("{}.json", config_hash);

    let tar_file = File::create(output_tar_path)?;
    let mut tar_builder = tar::Builder::new(tar_file);

    // 写入 config.json
    let mut header = tar::Header::new_gnu();
    header.set_size(config_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar_builder.append_data(&mut header, &config_filename, &config_bytes[..])?;

    let layers = manifest["layers"]
        .as_array()
        .ok_or("Manifest 中缺少 layers")?;

    let mut layer_paths_in_tar = Vec::new();

    for layer in layers {
        let digest = layer["digest"].as_str().unwrap_or_default();
        let safe_digest = digest.replace(':', "_");
        let layer_blob_path = cache_dir.join("layers").join(&safe_digest).join("layer.blob");

        if !layer_blob_path.exists() {
            return Err(format!("找不到层文件: {:?}", layer_blob_path).into());
        }

        let layer_hash = digest.trim_start_matches("sha256:");
        let path_in_tar = format!("{}/layer.tar", layer_hash);

        let mut blob_file = File::open(&layer_blob_path)?;
        tar_builder.append_file(&path_in_tar, &mut blob_file)?;

        layer_paths_in_tar.push(path_in_tar);
    }

    let repo_tag = format!("{}/{}:{}", registry, repository, tag);
    let manifest_json = json!([{
        "Config": config_filename,
        "RepoTags": [repo_tag],
        "Layers": layer_paths_in_tar
    }]);

    let manifest_bytes = serde_json::to_vec_pretty(&manifest_json)?;
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar_builder.append_data(&mut header, "manifest.json", &manifest_bytes[..])?;

    tar_builder.into_inner()?.flush()?;

    println!("✨ 成功导出标准镜像包: {:?}", output_tar_path);
    println!("💡 现在可以直接运行: docker load -i {:?}", output_tar_path);

    Ok(())
}

// =========================================================================
// 5. 主程序
// =========================================================================
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let cache_dir = args.cache_dir.clone().unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_default()
            .join("docker_images_cache")
    });

    let image_str = match &args.image {
        Some(img) => img,
        None => {
            println!("💡 请提供镜像名称参数 (例如: mysql:8)");
            return Ok(());
        }
    };

    let (registry, repository, tag) = parse_image_name(image_str);
    println!("Registry: {}, Repository: {}, Tag: {}", registry, repository, tag);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .user_agent("Docker-Pull-Script/1.0-Rust")
        .set_custom_dns(args.dns.as_deref())
        .build()?;

    let accept_types = vec![
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
    .join(", ");

    let headers = get_auth_headers(
        &client,
        &accept_types,
        &registry,
        &repository,
        args.username.as_deref(),
        args.password.as_deref(),
    )
    .await;

    let manifest_url = format!("https://{}/v2/{}/manifests/{}", registry, repository, tag);
    let resp = client.get(&manifest_url).headers(headers.clone()).send().await?;

    if !resp.status().is_success() {
        eprintln!("Cannot fetch manifest for {} [HTTP {}]", repository, resp.status());
        std::process::exit(1);
    }

    let mut manifest: Value = resp.json().await?;

    // 多平台处理
    if let Some(manifests) = manifest.get("manifests").and_then(|m| m.as_array()) {
        if let Some(target_platform) = &args.platform {
            let mut matched_digest = None;
            for m in manifests {
                let platform = m.get("platform");
                let os = platform.and_then(|p| p.get("os")).and_then(|v| v.as_str()).unwrap_or("linux");
                let arch = platform.and_then(|p| p.get("architecture")).and_then(|v| v.as_str()).unwrap_or("amd64");
                let p_str = format!("{}/{}", os, arch);

                if &p_str == target_platform {
                    matched_digest = m.get("digest").and_then(|d| d.as_str()).map(|s| s.to_string());
                    break;
                }
            }

            if let Some(digest) = matched_digest {
                let plat_manifest_url = format!("https://{}/v2/{}/manifests/{}", registry, repository, digest);
                let p_resp = client.get(&plat_manifest_url).headers(headers.clone()).send().await?;
                manifest = p_resp.json().await?;
            }
        }
    }

    let layers = manifest
        .get("layers")
        .and_then(|l| l.as_array())
        .cloned()
        .unwrap_or_default();

    println!("发现 {} 个层需要处理...", layers.len());

    let semaphore = Arc::new(Semaphore::new(args.max_concurrent_downloads));
    let multi_progress = Arc::new(MultiProgress::new());
    let hits = Arc::new(AtomicU64::new(0));
    let misses = Arc::new(AtomicU64::new(0));

    let mut tasks = vec![];

    for layer in layers.iter() {
        let digest = layer.get("digest").and_then(|v| v.as_str()).unwrap_or_default().to_string();

        let sem = Arc::clone(&semaphore);
        let mp = Arc::clone(&multi_progress);
        let client_clone = client.clone();
        let headers_clone = headers.clone();
        let reg_clone = registry.clone();
        let repo_clone = repository.clone();
        let cache_dir_clone = cache_dir.clone();
        let hits_clone = Arc::clone(&hits);
        let misses_clone = Arc::clone(&misses);
        let use_cache = !args.no_cache;

        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let short_id = if digest.len() >= 19 { &digest[7..19] } else { &digest };
            let pb = mp.add(ProgressBar::new(0));
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{prefix:.bold} [{bar:30.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                    .unwrap()
                    .progress_chars("█-"),
            );
            pb.set_prefix(short_id.to_string());

            let safe_digest = digest.replace(':', "_");
            let target_layer_dir = cache_dir_clone.join("layers").join(&safe_digest);
            let target_blob_path = target_layer_dir.join("layer.blob");

            if use_cache && target_blob_path.exists() {
                if let Ok(meta) = fs::metadata(&target_blob_path) {
                    if meta.len() > 0 {
                        pb.finish_with_message("Using cached layer");
                        hits_clone.fetch_add(1, Ordering::Relaxed);
                        return Ok::<(), String>(());
                    }
                }
            }

            misses_clone.fetch_add(1, Ordering::Relaxed);

            let layer_url = format!("https://{}/v2/{}/blobs/{}", reg_clone, repo_clone, digest);
            let mut response = client_clone.get(&layer_url).headers(headers_clone).send().await.map_err(|e| e.to_string())?;

            if let Some(len) = response.content_length() {
                pb.set_length(len);
            }

            fs::create_dir_all(&target_layer_dir).map_err(|e| e.to_string())?;

            // 直接流式落盘保存原始二进制文件
            {
                let file = File::create(&target_blob_path).map_err(|e| e.to_string())?;
                let mut writer = BufWriter::new(file);

                while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
                    writer.write_all(&chunk).map_err(|e| e.to_string())?;
                    pb.inc(chunk.len() as u64);
                }
                writer.flush().map_err(|e| e.to_string())?;
            }

            pb.finish_with_message("完成");
            Ok(())
        }));
    }

    for task in tasks {
        let _ = task.await?;
    }

    println!("\n✅ 所有镜像层下载完成！");
    println!("📊 缓存命中: {}, 缺失: {}", hits.load(Ordering::Relaxed), misses.load(Ordering::Relaxed));

    let output_tar_name = format!("{}_{}.tar", repository.replace('/', "_"), tag);
    let output_tar_path = std::env::current_dir()?.join(&output_tar_name);

    export_docker_image_tar(
        &client,
        &headers,
        &registry,
        &repository,
        &tag,
        &manifest,
        &cache_dir,
        &output_tar_path,
    )
    .await?;

    Ok(())
}

//! Hardened static file handler for the public dashboard routes.
//!
//! Port of `src/console/dashboard-assets.ts`: serves the shared index document
//! at `/`, `/share/*`, and `/console/*`, real files from the build root, and
//! the same cache and security headers. The reserved `/console/api` namespace
//! is rejected defensively even though the API router is registered first.

use std::path::{Component, Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use regex::Regex;
use sha2::{Digest, Sha256};

/// Document served for each URL prefix. The root entry matches `/` only, so an
/// unknown extensionless path at the origin root is a 404, not the SPA.
const DEFAULT_ENTRY_DOCUMENTS: &[(&str, &str)] = &[
    ("/", "index.html"),
    ("/share", "index.html"),
    ("/console", "index.html"),
];

include!(concat!(env!("OUT_DIR"), "/embedded_assets.rs"));

fn embedded_file(relative: &str) -> Option<&'static [u8]> {
    EMBEDDED_ASSETS
        .iter()
        .find(|(name, _)| *name == relative)
        .map(|(_, bytes)| *bytes)
}

/// Social card for the public enrollment page (`/share/*`), injected because
/// crawlers do not execute the client bundle.
const SHARE_TITLE: &str = "Keyla Everywhere — Akses bersama";
const SHARE_DESCRIPTION: &str =
    "Akses gateway pribadi dengan kuota, penggunaan nyata, dan model yang diizinkan.";
const SHARE_IMAGE: &str = "/keyla-social.svg";
const SHARE_IMAGE_WIDTH: u32 = 1200;
const SHARE_IMAGE_HEIGHT: u32 = 630;
const SHARE_IMAGE_ALT: &str = "Keyla Everywhere — gateway AI pribadi";

const BADGE_IMAGE_ORIGIN: &str = "https://img.shields.io";

/// Content-Security-Policy for non-document (JSON/API) responses.
pub const API_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";

/// Legacy clickjacking guard for clients that predate CSP `frame-ancestors`.
pub const X_FRAME_OPTIONS: &str = "DENY";

/// One static response, before it is converted to an axum response.
#[derive(Debug)]
pub struct StaticResult {
    pub status: u16,
    pub body: Option<Vec<u8>>,
    pub headers: Vec<(&'static str, String)>,
}

impl StaticResult {
    fn not_found() -> Self {
        Self {
            status: 404,
            body: None,
            headers: Vec::new(),
        }
    }
}

/// Static handler rooted at one build directory.
#[derive(Debug, Clone)]
pub struct StaticAssets {
    build_dir: PathBuf,
    build_dir_norm: String,
    entries: Vec<(&'static str, &'static str)>,
}

impl StaticAssets {
    pub fn new(build_dir: impl Into<PathBuf>) -> Self {
        let build_dir = build_dir.into();
        let build_dir_norm = normalize_separators(&build_dir.to_string_lossy());
        Self {
            build_dir,
            build_dir_norm,
            entries: DEFAULT_ENTRY_DOCUMENTS.to_vec(),
        }
    }

    pub fn build_dir(&self) -> &Path {
        &self.build_dir
    }

    /// Serves one request path (percent-encoded, as it appears on the wire).
    pub async fn serve(&self, pathname: &str) -> StaticResult {
        self.serve_with_headers(pathname).await
    }

    async fn serve_with_headers(&self, pathname: &str) -> StaticResult {
        // Reject the reserved API namespace, including its bare prefix.
        if pathname == "/console/api" || pathname.starts_with("/console/api/") {
            return StaticResult {
                status: 404,
                body: None,
                headers: vec![("content-type", "application/json".to_owned())],
            };
        }

        let decoded = match percent_encoding::percent_decode_str(pathname).decode_utf8() {
            Ok(decoded) => decoded.into_owned(),
            Err(_) => return self.with_security_headers(StaticResult::not_found()),
        };
        let normalized = normalize_separators(&decoded);

        // The console document is mounted under `/console`, but the Vite build
        // emits assets at the origin root. Strip the mount prefix so
        // `/console/assets/app.js` resolves to the same file as
        // `/assets/app.js`.
        let relative_path = match normalized.strip_prefix("/console/") {
            Some(rest) => rest.to_owned(),
            None => normalized.trim_start_matches('/').to_owned(),
        };

        // The resolved path must stay inside the build directory. This rejects
        // `..` traversal, absolute paths, and normalized backslashes.
        let full_path = resolve_lexical(&self.build_dir, &relative_path);
        let full_path_norm = normalize_separators(&full_path.to_string_lossy());
        let build_dir_with_slash = format!("{}/", self.build_dir_norm.trim_end_matches('/'));
        let inside_build_dir = full_path_norm == self.build_dir_norm
            || full_path_norm.starts_with(&build_dir_with_slash);
        if !inside_build_dir {
            return self.with_security_headers(StaticResult::not_found());
        }

        let entry_document = entry_document_for(&normalized, &self.entries);
        let last_segment = relative_path.rsplit('/').next().unwrap_or_default();
        // A missing path with a dot is an asset request and must 404 rather
        // than falling back to the SPA document.
        let is_asset_like = last_segment.contains('.');

        if !relative_path.is_empty() {
            if let Some(data) = embedded_file(&relative_path) {
                let mime_type = mime_type(&full_path);
                let cache_control =
                    if relative_path == "index.html" || relative_path.ends_with("/index.html") {
                        "no-store, no-cache, must-revalidate"
                    } else if has_hash_in_filename(&full_path) {
                        "public, max-age=31536000, immutable"
                    } else if !relative_path.contains('.') {
                        "no-store, no-cache, must-revalidate"
                    } else {
                        "public, max-age=3600"
                    };
                return self.with_security_headers(StaticResult {
                    status: 200,
                    body: Some(data.to_vec()),
                    headers: vec![
                        ("content-type", mime_type.to_owned()),
                        ("cache-control", cache_control.to_owned()),
                    ],
                });
            }
            if let Ok(metadata) = tokio::fs::metadata(&full_path).await {
                if metadata.is_file() {
                    match tokio::fs::read(&full_path).await {
                        Ok(data) => {
                            let mime_type = mime_type(&full_path);
                            let cache_control = if relative_path == "index.html"
                                || relative_path.ends_with("/index.html")
                            {
                                "no-store, no-cache, must-revalidate"
                            } else if has_hash_in_filename(&full_path) {
                                "public, max-age=31536000, immutable"
                            } else if !relative_path.contains('.') {
                                "no-store, no-cache, must-revalidate"
                            } else {
                                "public, max-age=3600"
                            };
                            return self.with_security_headers(StaticResult {
                                status: 200,
                                body: Some(data),
                                headers: vec![
                                    ("content-type", mime_type.to_owned()),
                                    ("cache-control", cache_control.to_owned()),
                                ],
                            });
                        }
                        Err(_) => return self.with_security_headers(StaticResult::not_found()),
                    }
                }
            }
        }

        // No file on disk: hand the route to its SPA document when one owns it.
        if let Some(document) = entry_document {
            if !is_asset_like {
                return self
                    .with_security_headers(self.serve_document(document, &normalized).await);
            }
        }

        self.with_security_headers(StaticResult::not_found())
    }

    async fn serve_document(&self, document: &str, pathname: &str) -> StaticResult {
        let path = self.build_dir.join(document);
        let html = match tokio::fs::read_to_string(&path).await {
            Ok(html) => html,
            Err(_) => match embedded_file(document) {
                Some(bytes) => String::from_utf8_lossy(bytes).into_owned(),
                None => return StaticResult::not_found(),
            },
        };
        let html = apply_social_meta(&html, pathname);
        StaticResult {
            status: 200,
            body: Some(html.into_bytes()),
            headers: vec![
                ("content-type", "text/html; charset=utf-8".to_owned()),
                (
                    "cache-control",
                    "no-store, no-cache, must-revalidate".to_owned(),
                ),
                ("pragma", "no-cache".to_owned()),
                ("expires", "0".to_owned()),
            ],
        }
    }

    /// Adds the browser-hardening headers shared by every public static
    /// response. Documents get the dashboard CSP (inline scripts allowed only
    /// by hash); non-document assets get the locked-down API policy.
    fn with_security_headers(&self, mut result: StaticResult) -> StaticResult {
        let content_type = result
            .headers
            .iter()
            .find(|(name, _)| *name == "content-type")
            .map(|(_, value)| value.as_str())
            .unwrap_or("");
        let is_html = content_type.contains("text/html");
        let csp = if is_html {
            let html = result.body.as_deref().unwrap_or_default();
            dashboard_content_security_policy(html)
        } else {
            API_CONTENT_SECURITY_POLICY.to_owned()
        };
        result.headers.extend([
            ("x-content-type-options", "nosniff".to_owned()),
            ("x-frame-options", X_FRAME_OPTIONS.to_owned()),
            ("referrer-policy", "no-referrer".to_owned()),
            ("content-security-policy", csp),
        ]);
        result
    }
}

fn normalize_separators(path: &str) -> String {
    path.replace('\\', "/")
}

/// Lexically resolves `relative` against `base` the way Node's `path.resolve`
/// does for a relative path: `.` is dropped and `..` pops a component. No
/// filesystem access and no symlink resolution, matching the original.
fn resolve_lexical(base: &Path, relative: &str) -> PathBuf {
    let mut out = base.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            // The relative path is stripped of leading slashes before it gets
            // here, so a root component means the caller escaped containment.
            Component::RootDir | Component::Prefix(_) => {
                out = Path::new("/").to_path_buf();
            }
        }
    }
    out
}

/// Longest-prefix match of an SPA route against the entry documents.
fn entry_document_for<'a>(
    pathname: &str,
    entries: &'a [(&'static str, &'static str)],
) -> Option<&'a str> {
    let mut matched: Option<(&'a str, usize)> = None;
    for (prefix, document) in entries {
        let matches = if *prefix == "/" {
            pathname == "/"
        } else {
            pathname == *prefix || pathname.starts_with(&format!("{prefix}/"))
        };
        if !matches {
            continue;
        }
        if matched.is_none_or(|(_, length)| prefix.len() > length) {
            matched = Some((document, prefix.len()));
        }
    }
    matched.map(|(document, _)| document)
}

fn mime_type(path: &Path) -> &'static str {
    let extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "eot" => "application/vnd.ms-fontobject",
        "otf" => "font/otf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "gz" => "application/gzip",
        _ => "application/octet-stream",
    }
}

/// Heuristic matching `name.<hex6+>.ext`, the Vite content-hash pattern.
fn has_hash_in_filename(path: &Path) -> bool {
    let filename = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let bytes = filename.as_bytes();
    let mut index = 0;
    while let Some(dot) = bytes[index..].iter().position(|byte| *byte == b'.') {
        let start = index + dot + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
            end += 1;
        }
        if end - start >= 6 && end < bytes.len() && bytes[end] == b'.' {
            return true;
        }
        index = start;
        if index >= bytes.len() {
            break;
        }
    }
    false
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render_social_meta() -> String {
    let title = escape_html(SHARE_TITLE);
    let description = escape_html(SHARE_DESCRIPTION);
    let image = escape_html(SHARE_IMAGE);
    let image_alt = escape_html(SHARE_IMAGE_ALT);
    [
        "<!-- keyla:social-meta:start -->".to_owned(),
        "<meta property=\"og:type\" content=\"website\" />".to_owned(),
        format!("<meta property=\"og:title\" content=\"{title}\" />"),
        format!("<meta property=\"og:description\" content=\"{description}\" />"),
        format!("<meta property=\"og:image\" content=\"{image}\" />"),
        "<meta property=\"og:image:type\" content=\"image/svg+xml\" />".to_owned(),
        format!("<meta property=\"og:image:width\" content=\"{SHARE_IMAGE_WIDTH}\" />"),
        format!("<meta property=\"og:image:height\" content=\"{SHARE_IMAGE_HEIGHT}\" />"),
        format!("<meta property=\"og:image:alt\" content=\"{image_alt}\" />"),
        "<meta name=\"twitter:card\" content=\"summary_large_image\" />".to_owned(),
        format!("<meta name=\"twitter:title\" content=\"{title}\" />"),
        format!("<meta name=\"twitter:description\" content=\"{description}\" />"),
        format!("<meta name=\"twitter:image\" content=\"{image}\" />"),
        format!("<meta name=\"twitter:image:alt\" content=\"{image_alt}\" />"),
        "<!-- keyla:social-meta:end -->".to_owned(),
    ]
    .join("\n    ")
}

/// Rewrites the document's social card and title for a public share route.
fn apply_social_meta(html: &str, pathname: &str) -> String {
    if pathname != "/share" && !pathname.starts_with("/share/") {
        return html.to_owned();
    }
    let block =
        Regex::new(r"(?s)<!-- keyla:social-meta:start -->.*?<!-- keyla:social-meta:end -->")
            .expect("social meta pattern is valid");
    let description = Regex::new(r#"(?i)<meta\s+name="description"\s+content="[^"]*"\s*/>"#)
        .expect("description pattern is valid");
    let title = Regex::new(r"(?is)<title>.*?</title>").expect("title pattern is valid");
    let with_block = block.replace(html, render_social_meta());
    let with_description = description.replace(
        &with_block,
        format!(
            "<meta name=\"description\" content=\"{}\" />",
            escape_html(SHARE_DESCRIPTION)
        )
        .as_str(),
    );
    title
        .replace(
            &with_description,
            format!("<title>{}</title>", escape_html(SHARE_TITLE)).as_str(),
        )
        .into_owned()
}

/// Bodies of inline `<script>` tags (those without a `src` attribute).
fn inline_script_bodies(html: &str) -> Vec<String> {
    let mut bodies = Vec::new();
    let haystack = html.as_bytes();
    let lower = html.to_ascii_lowercase();
    let mut cursor = 0;
    while let Some(relative) = lower[cursor..].find("<script") {
        let start = cursor + relative;
        let Some(open_end_rel) = lower[start..].find('>') else {
            break;
        };
        let open_end = start + open_end_rel;
        let open_tag = &lower[start + "<script".len()..open_end];
        let has_src = open_tag.contains("src=") || open_tag.contains("src =");
        let body_start = open_end + 1;
        let Some(close_rel) = lower[body_start..].find("</script") else {
            break;
        };
        let close = body_start + close_rel;
        if !has_src {
            let body = &html[body_start..close];
            if !body.trim().is_empty() {
                bodies.push(body.to_owned());
            }
        }
        cursor = close + "</script".len();
        if cursor >= haystack.len() {
            break;
        }
    }
    bodies
}

fn inline_script_hash(script_body: &str) -> String {
    let digest = Sha256::digest(script_body.as_bytes());
    format!("'sha256-{}'", BASE64.encode(digest))
}

/// Content-Security-Policy for the dashboard document. Scripts are restricted
/// to the bundled same-origin modules plus hashes of the static inline theme
/// bootstrap; styles allow inline (React `style` props) and Google Fonts.
pub fn dashboard_content_security_policy(html: &[u8]) -> String {
    let hashes: Vec<String> = inline_script_bodies(&String::from_utf8_lossy(html))
        .iter()
        .map(|body| inline_script_hash(body))
        .collect();
    let script_src = if hashes.is_empty() {
        "script-src 'self'".to_owned()
    } else {
        format!("script-src 'self' {}", hashes.join(" "))
    };
    [
        "default-src 'self'".to_owned(),
        script_src,
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com".to_owned(),
        "font-src 'self' https://fonts.gstatic.com".to_owned(),
        format!("img-src 'self' data: blob: https: {BADGE_IMAGE_ORIGIN}"),
        "connect-src 'self'".to_owned(),
        "object-src 'none'".to_owned(),
        "base-uri 'self'".to_owned(),
        "form-action 'self'".to_owned(),
        "frame-ancestors 'none'".to_owned(),
    ]
    .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const INDEX: &str = "<!doctype html><html><head><meta name=\"description\" content=\"old\" /><title>Old</title><!-- keyla:social-meta:start --><!-- keyla:social-meta:end --></head><body><script>window.__theme='dark'</script><script src=\"/assets/app.js\"></script></body></html>";

    fn fixture() -> (tempfile::TempDir, StaticAssets) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), INDEX).unwrap();
        std::fs::create_dir_all(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("assets/app.abc123.js"), "console.log(1)").unwrap();
        let assets = StaticAssets::new(dir.path());
        (dir, assets)
    }

    #[test]
    fn hash_detection_matches_vite_names() {
        assert!(has_hash_in_filename(Path::new("app.abc123def.js")));
        assert!(has_hash_in_filename(Path::new("index.a1b2c3d4.css")));
        assert!(!has_hash_in_filename(Path::new("app.js")));
        assert!(!has_hash_in_filename(Path::new("provider.anthropic.svg")));
    }

    #[test]
    fn social_meta_replaces_the_sentinel_block_only_for_share() {
        let unchanged = apply_social_meta(INDEX, "/console");
        assert_eq!(unchanged, INDEX);

        let replaced = apply_social_meta(INDEX, "/share/token");
        assert!(replaced.contains(SHARE_TITLE));
        assert!(!replaced.contains("content=\"old\""));
    }

    #[test]
    fn inline_script_bodies_skip_src_and_hash_them() {
        let bodies = inline_script_bodies(INDEX);
        assert_eq!(bodies, vec!["window.__theme='dark'".to_owned()]);
        let csp = dashboard_content_security_policy(INDEX.as_bytes());
        assert!(csp.contains("'sha256-"));
        assert!(!csp.contains("unsafe-eval"));
    }

    #[tokio::test]
    async fn serves_documents_assets_and_rejects_namespaces() {
        let (_dir, assets) = fixture();

        let root = assets.serve("/").await;
        assert_eq!(root.status, 200);
        assert!(
            root.headers
                .iter()
                .any(|(name, value)| *name == "content-type" && value.starts_with("text/html"))
        );

        let console_route = assets.serve("/console/settings").await;
        assert_eq!(console_route.status, 200);

        let asset = assets.serve("/console/assets/app.abc123.js").await;
        assert_eq!(asset.status, 200);
        assert!(asset.headers.iter().any(|(name, value)| {
            *name == "cache-control" && value == "public, max-age=31536000, immutable"
        }));

        let reserved = assets.serve("/console/api/keys").await;
        assert_eq!(reserved.status, 404);
        assert!(
            reserved
                .headers
                .iter()
                .any(|(name, value)| *name == "content-type" && value == "application/json")
        );

        let traversal = assets.serve("/%2e%2e/%2e%2e/etc/passwd").await;
        assert_eq!(traversal.status, 404);
    }
}

// Copyright (c) Altare Technologies Limited. All rights reserved.

use hyper::StatusCode;
use serde_json::json;

/// Generate a fancy HTML error page
pub fn generate_html_error(status: StatusCode, message: &str) -> String {
    let (title, description) = match status {
        StatusCode::BAD_REQUEST => (
            "400 Bad Request",
            "The request could not be understood by the server. Please check your request and try again.",
        ),
        StatusCode::FORBIDDEN => (
            "403 Forbidden",
            "Access to this resource is forbidden. You don't have permission to access this resource.",
        ),
        StatusCode::NOT_FOUND => (
            "404 Not Found",
            "The requested resource could not be found on this server.",
        ),
        StatusCode::REQUEST_TIMEOUT => (
            "408 Request Timeout",
            "The server timed out waiting for the request. Please try again.",
        ),
        StatusCode::TOO_MANY_REQUESTS => (
            "429 Too Many Requests",
            "You have sent too many requests in a given amount of time. Please slow down and try again later.",
        ),
        StatusCode::BAD_GATEWAY => (
            "502 Bad Gateway",
            "Hmm... something went wrong while loading the page. We're sorry - and we'll look into it.",
        ),
        StatusCode::SERVICE_UNAVAILABLE => (
            "503 Service Unavailable",
            "The service is temporarily unavailable. Please try again in a few moments.",
        ),
        StatusCode::GATEWAY_TIMEOUT => (
            "504 Gateway Timeout",
            "The server didn't respond in time. Please try again later.",
        ),
        _ => (
            "500 Internal Server Error",
            "An unexpected error occurred. We're working to fix this issue.",
        ),
    };

    format!(
        r#"<!doctype html>
<html>
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Altare - {title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400;1,700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
<link rel="preconnect" href="https://rsms.me/">
<link rel="stylesheet" href="https://rsms.me/inter/inter.css">
  </head>
<style>
html {{
  font-family: 'Inter', sans-serif;
  font-feature-settings: "cv11" 1, "cv06" 1, "cv10" 1, "ss08" 1;
  letter-spacing: -0.15px;
}}
</style>
<body>
<div class="relative grid min-h-screen grid-cols-[1fr_2.5rem_auto_2.5rem_1fr] grid-rows-[1fr_1px_auto_1px_1fr] bg-white [--pattern-fg:var(--color-neutral-950)]/5 dark:bg-neutral-950 dark:[--pattern-fg:var(--color-white)]/10">
  <div class="col-start-3 row-start-3 flex max-w-lg flex-col bg-neutral-100 p-2 dark:bg-white/10">
    <div class="rounded-xl bg-white p-10 text-sm/7 text-neutral-700 dark:bg-neutral-950 dark:text-neutral-300">
      <h1 class="text-lg font-medium text-black dark:text-white mb-2">{title}</h1>
      <div class="space-y-4">
        <p>{description}</p>
        <p class="text-xs text-neutral-500 dark:text-neutral-400">{message}</p>
        <code style="font-family: 'Space Mono'" class="text-xs text-neutral-300 dark:text-neutral-400 uppercase">POWERED BY ALTARE CRUCIBLE / V1.0.0</code>
      </div>
      <hr class="my-6 w-full border-(--pattern-fg)" />
      <p class="mb-3">If you'd like to see updates regarding Altare's status:</p>
      <p class="font-semibold">
        <a href="https://status.altare.tech" class="text-neutral-950 underline decoration-sky-400 underline-offset-3 hover:decoration-2 dark:text-white">Join our Discord server &rarr;</a>
      </p>
    </div>
  </div>
  <div class="relative -right-px col-start-2 row-span-full row-start-1 border-x border-x-(--pattern-fg) bg-[image:repeating-linear-gradient(315deg,_var(--pattern-fg)_0,_var(--pattern-fg)_1px,_transparent_0,_transparent_50%)] bg-[size:10px_10px] bg-fixed"></div>
  <div class="relative -left-px col-start-4 row-span-full row-start-1 border-x border-x-(--pattern-fg) bg-[image:repeating-linear-gradient(315deg,_var(--pattern-fg)_0,_var(--pattern-fg)_1px,_transparent_0,_transparent_50%)] bg-[size:10px_10px] bg-fixed"></div>
  <div class="relative -bottom-px col-span-full col-start-1 row-start-2 h-px bg-(--pattern-fg)"></div>
  <div class="relative -top-px col-span-full col-start-1 row-start-4 h-px bg-(--pattern-fg)"></div>
</div>
</body>
</html>"#,
        title = title,
        description = description,
        message = message
    )
}

/// Generate a JSON error response for API endpoints
pub fn generate_json_error(status: StatusCode, message: &str) -> String {
    json!({
        "error": {
            "code": status.as_u16(),
            "status": status.canonical_reason().unwrap_or("Unknown"),
            "message": message,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "powered_by": "Altare Crucible v1.0.0"
        }
    })
    .to_string()
}

/// Determine if a request is for an API endpoint
pub fn is_api_request(path: &str) -> bool {
    path.starts_with("/api/") || path.starts_with("/api")
}

$ErrorActionPreference = "Stop"

$ts = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$token = (Invoke-RestMethod -Method Post -Uri ("https://" + $env:AUTH0_DOMAIN + "/oauth/token") `
    -ContentType "application/json" `
    -Body (@{
        grant_type    = "client_credentials"
        client_id     = $env:AUTH0_CLIENT_ID
        client_secret = $env:AUTH0_CLIENT_SECRET
        audience      = $env:AUTH0_AUDIENCE
    } | ConvertTo-Json)).access_token

$headers = @{
    Authorization  = "Bearer $token"
    "Content-Type" = "application/json"
}

$bulk = @{
    rulesets = @(
        @{ key = "CARD_AUTH"; version = 1; country = "global" },
        @{ key = "CARD_MONITORING"; version = 1; country = "global" }
    )
}
Write-Host "Bulk-load:"
Invoke-RestMethod -Method Post `
    -Uri http://localhost:8081/v1/evaluate/rulesets/bulk-load `
    -Headers $headers `
    -Body ($bulk | ConvertTo-Json -Depth 6)

$pre = @{
    transaction_id       = "txn-$ts"
    card_hash            = "abc123token"
    amount               = 150.0
    currency             = "USD"
    merchant_category_code = "5411"
    country_code         = "US"
    transaction_type     = "PURCHASE"
}
Write-Host "AUTH:"
Invoke-RestMethod -Method Post `
    -Uri http://localhost:8081/v1/evaluate/auth `
    -Headers $headers `
    -Body ($pre | ConvertTo-Json -Depth 6)

$post = @{
    transaction_id       = "txn-$ts"
    card_hash            = "abc123token"
    amount               = 150.0
    currency             = "USD"
    merchant_category_code = "5411"
    country_code         = "US"
    transaction_type     = "PURCHASE"
    decision             = "APPROVE"
}
Write-Host "MONITORING:"
Invoke-RestMethod -Method Post `
    -Uri http://localhost:8081/v1/evaluate/monitoring `
    -Headers $headers `
    -Body ($post | ConvertTo-Json -Depth 6)

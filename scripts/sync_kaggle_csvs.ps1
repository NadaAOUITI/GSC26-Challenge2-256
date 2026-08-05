# Copy Kaggle competition CSV metadata into data/
param(
    [string]$ZipPath = "$env:USERPROFILE\Downloads\detect-and-fix-vulnerabilities-in-github-actions.zip"
)

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$DataDir = Join-Path $Root "data"
$ExtractDir = Join-Path $Root "_kaggle_extract"

if (-not (Test-Path $ZipPath)) {
    Write-Error "Kaggle zip not found: $ZipPath"
    exit 1
}

New-Item -ItemType Directory -Force -Path $DataDir, $ExtractDir | Out-Null
Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force

foreach ($name in @("train.csv", "untrusted_data.csv", "sample_submission.csv")) {
    $src = Join-Path $ExtractDir $name
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $DataDir $name) -Force
        Write-Host "Synced $name"
    }
}

Write-Host "Done. Next: cd dataset; git pull origin main  (when validation/ is published)"

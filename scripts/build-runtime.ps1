[CmdletBinding()]
param(
    # 过渡用 Lab 打包器：从官方 npm 包组装，不得标记为源码构建或直接提升到 Stable。
    # 官方精确版本号(绝不写 latest)
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$')]
    [string]$Version,
    # 内部构建号；一旦产物存在，该版本+构建号不得覆盖或复用
    [ValidateRange(1, 999999)][int]$Build = 1,
    # 随包 node 版本(经 fnm 解析;亦可 -NodeExe 直接钉死路径)
    [string]$NodeVersion = '24.19.0',
    [string]$NodeExe = '',
    # 官方仓库检出(取 LICENSE/NOTICE)
    [string]$HarnessCheckout = 'C:\Agents\deepseek',
    # 产物目录
    [string]$OutDir = (Join-Path $PSScriptRoot '..\out'),
    # npm 镜像与缓存(构建机直连建议)
    [string]$NpmRegistry = 'https://registry.npmmirror.com',
    [string]$NpmCache = (Join-Path $env:TEMP 'ensou-dsh-build-npmcache'),
    # npm CLI(留空则随解析出的 node 自动定位)
    [string]$NpmCli = '',
    # 跳过 registry 校验(离线场景)
    [switch]$SkipRegistryCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# 经 fnm 解析钉版 node(构建机用 fnm 管理 Node;员工机不需要 fnm —— 镜像自带 node.exe)
if (-not $NodeExe) {
    $fnmCmd = Get-Command fnm.exe -ErrorAction SilentlyContinue
    if (-not $fnmCmd) { throw 'PATH 中未找到 fnm.exe；请用 -NodeExe 直接指定受控的 node.exe' }
    $fnmExe = $fnmCmd.Source
    $resolved = (& $fnmExe exec --using=$NodeVersion -- node -p 'process.execPath' 2>$null | Select-Object -Last 1)
    $NodeExe = "$resolved".Trim()
    if (-not (Test-Path $NodeExe)) { throw "fnm 无法解析 node $NodeVersion($resolved)" }
    Write-Host ("fnm 解析 node $NodeVersion -> $NodeExe")
}
if (-not $NpmCli) { $NpmCli = Join-Path (Split-Path $NodeExe -Parent) 'node_modules\npm\bin\npm-cli.js' }

$npmNode = Join-Path (Split-Path $NodeExe -Parent) 'node.exe'
if (-not (Test-Path $NpmCli)) { throw "npm CLI 缺失: $NpmCli" }
# 让生命周期脚本(如 koffi 的 cnoke.cjs)能找到 node
$env:Path = (Split-Path $NodeExe -Parent) + ';' + $env:Path

$assetName = "runtime-$Version+b$Build"
$buildDir = Join-Path $OutDir ("build\" + $assetName)
$zipPath = Join-Path $OutDir "$assetName.zip"
$metaPath = Join-Path $OutDir "$assetName.json"
$immutableOutputs = @($zipPath, "$zipPath.sha256", $metaPath)
$existingOutput = $immutableOutputs | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($existingOutput) {
    throw "发布 ID 不可复用：$assetName 已存在($existingOutput)。请递增 -Build，禁止覆盖同 ID 的字节。"
}

function Write-Step([string]$m) { Write-Host ("== {0} ==" -f $m) -ForegroundColor Cyan }

Write-Step "1/8 校验官方版本 $Version (npm-package-lab)"
if (-not (Test-Path (Join-Path $HarnessCheckout '.git'))) {
    throw "官方源码检出无效：$HarnessCheckout"
}
$officialCommit = (& git -C $HarnessCheckout rev-parse HEAD 2>$null | Select-Object -Last 1).Trim()
if ($LASTEXITCODE -ne 0 -or $officialCommit -notmatch '^[0-9a-f]{40}$') {
    throw "无法读取官方源码检出的完整 commit：$HarnessCheckout"
}
$officialTag = (& git -C $HarnessCheckout describe --tags --exact-match HEAD 2>$null | Select-Object -Last 1)
if ($LASTEXITCODE -ne 0) { $officialTag = $null }
else { $officialTag = "$officialTag".Trim() }
if (-not $SkipRegistryCheck) {
    $env:npm_config_cache = $NpmCache
    $versions = & $npmNode $NpmCli view @deepseek-ai/dsh versions --json --registry $NpmRegistry 2>$null
    if (-not $versions) { throw "无法访问 npm registry(可加 -SkipRegistryCheck 跳过)" }
    $list = $versions | ConvertFrom-Json
    if ($list -notcontains $Version) { throw "官方 registry 不存在版本 $Version" }
    Write-Host "registry OK: @deepseek-ai/dsh@$Version"
} else {
    Write-Host "已跳过 registry 校验(-SkipRegistryCheck)"
}

Write-Step "2/8 准备构建目录 $buildDir"
if (Test-Path $buildDir) {
    try { Remove-Item $buildDir -Recurse -Force }
    catch { Start-Sleep -Seconds 2; Remove-Item $buildDir -Recurse -Force }  # 上一轮失败残留可能短暂锁目录
}
New-Item -ItemType Directory -Path $buildDir -Force | Out-Null

Write-Step "3/8 安装官方包闭包(离线形态 = 官方 npm 包 + 依赖)"
$pkgJson = [ordered]@{ name = 'ensou-dsh-runtime'; private = $true; version = '0.0.0'
    dependencies = @{ '@deepseek-ai/dsh' = $Version } }
$pkgJson | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $buildDir 'package.json') -Encoding UTF8
$env:npm_config_cache = $NpmCache
$env:NO_PROXY = '*'
Push-Location $buildDir
try {
    & $npmNode $NpmCli install --registry $NpmRegistry --no-audit --no-fund 2>&1 | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) { throw "npm install 失败(exit $LASTEXITCODE)" }
    # npm 11 安装脚本白名单:与官方运行时所允许一致的 5 个原生/生命周期包(版本动态读取,不硬编码)
    $allow = [ordered]@{}
    foreach ($p in @('@deepseek-ai/dsh-subprocess-local', 'node-pty', 'koffi', '@google/genai', 'protobufjs')) {
        $pkgPath = Join-Path $buildDir "node_modules\$p\package.json"
        if (Test-Path $pkgPath) {
            $ver = (Get-Content $pkgPath -Raw | ConvertFrom-Json).version
            $allow["$p@$ver"] = $true
        }
    }
    Write-Host "allowScripts: $($allow.Keys -join ', ')"
    $pkgJson2 = [ordered]@{ name = 'ensou-dsh-runtime'; private = $true; version = '0.0.0'
        dependencies = @{ '@deepseek-ai/dsh' = $Version }; allowScripts = $allow }
    $pkgJson2 | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $buildDir 'package.json') -Encoding UTF8
    # 手动执行 node-pty 生命周期脚本(npm 从缓存恢复时不会补跑;post-install 负责把 conpty 复制到运行时位置)
    Write-Host "手动执行 node-pty 构建脚本..."
    Push-Location (Join-Path $buildDir 'node_modules\node-pty')
    try {
        & $npmNode 'scripts\prebuild.js' 2>&1 | ForEach-Object { Write-Host $_ }
        if ($LASTEXITCODE -ne 0) { throw 'node-pty prebuild 失败' }
        & $npmNode 'scripts\post-install.js' 2>&1 | ForEach-Object { Write-Host $_ }
    } finally { Pop-Location }
    # koffi 无需构建:预编译二进制随平台包 @koromix/koffi-win32-x64 分发(cnoke 仅作冷门平台回退)
    Push-Location (Join-Path $buildDir 'node_modules\@deepseek-ai\dsh-subprocess-local')
    try {
        & $npmNode 'scripts\ensure-spawn-helper.mjs' 2>&1 | ForEach-Object { Write-Host $_ }
    } finally { Pop-Location }
    # 验证原生模块产物真实存在(位置与文件名按实际分发形态)
    $conptyNode = Get-ChildItem (Join-Path $buildDir 'node_modules\node-pty\prebuilds\win32-x64') -Filter 'conpty.node' -ErrorAction SilentlyContinue | Select-Object -First 1
    $conptyDll = Get-ChildItem (Join-Path $buildDir 'node_modules\node-pty\build\Release\conpty') -Filter 'conpty.dll' -ErrorAction SilentlyContinue | Select-Object -First 1
    $koffi = Get-ChildItem (Join-Path $buildDir 'node_modules') -Recurse -Filter 'koffi.node' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $conptyNode) { throw '原生模块缺失: node-pty win32-x64 conpty.node' }
    if (-not $conptyDll) { throw '原生模块缺失: node-pty conpty.dll(build\Release)' }
    if (-not $koffi) { throw '原生模块缺失: koffi.node(应在 @koromix/koffi-win32-x64 平台包)' }
    Write-Host ("原生模块 OK: conpty.node + conpty.dll + koffi.node(" + $koffi.FullName + ")")
} finally { Pop-Location }

Write-Step "4/8 放入钉版本 node.exe"
Copy-Item $NodeExe (Join-Path $buildDir 'node.exe') -Force
$nodeVersion = (& (Join-Path $buildDir 'node.exe') --version).Trim()
Write-Host "bundled node: $nodeVersion"

Write-Step "5/8 启动脚本与许可证"
@'
[CmdletBinding()]
param([ValidateRange(1, 65535)][int]$Port = 3080)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$env:DSH_TELEMETRY_DISABLED = '1'
$exitCode = 0
Push-Location $PSScriptRoot
try {
    & (Join-Path $PSScriptRoot 'node.exe') 'node_modules\@deepseek-ai\dsh\lib\bin.js' web --host 127.0.0.1 --port $Port
    $exitCode = $LASTEXITCODE
}
finally { Pop-Location }
exit $exitCode
'@ | Set-Content (Join-Path $buildDir 'start-dsh.ps1') -Encoding UTF8
foreach ($f in @('LICENSE', 'THIRD_PARTY_NOTICES.md')) {
    $src = Join-Path $HarnessCheckout $f
    if (Test-Path $src) { Copy-Item $src $buildDir -Force } else { Write-Host "注意: 官方检出缺少 $f" -ForegroundColor Yellow }
}

Write-Step "6/8 冒烟:随包 node 运行 dsh --version"
$bin = Join-Path $buildDir 'node_modules\@deepseek-ai\dsh\lib\bin.js'
$smokeVersion = (& (Join-Path $buildDir 'node.exe') $bin --version 2>&1 | Out-String).Trim()
Write-Host "smoke version: $smokeVersion"
if ($smokeVersion -cne $Version) { throw "冒烟失败:期望 $Version,实际 $smokeVersion" }

Write-Step "7/8 打包 zip"
Compress-Archive -Path (Join-Path $buildDir '*') -DestinationPath $zipPath -Force

Write-Step "8/8 sha256 与元数据"
$hash = (Get-FileHash -Algorithm SHA256 $zipPath).Hash.ToLower()
Set-Content "$zipPath.sha256" ("{0}  {1}" -f $hash, (Split-Path $zipPath -Leaf)) -Encoding ASCII
$size = (Get-Item $zipPath).Length
$meta = [ordered]@{
    schemaVersion = 1
    buildMode    = 'npm-package-lab'
    sourceBuilt  = $false
    dshVersion   = $Version
    build        = $Build
    releaseId    = $assetName
    assetName    = (Split-Path $zipPath -Leaf)
    zipSha256    = $hash
    sizeBytes    = $size
    nodeVersion  = $nodeVersion
    upstreamCommit = $officialCommit
    upstreamTag  = $officialTag
    releasedAt   = (Get-Date).ToString('o')
}
$meta | ConvertTo-Json -Depth 3 | Set-Content $metaPath -Encoding UTF8

Write-Host ""
Write-Host ("完成: {0} ({1:N1} MB)" -f $zipPath, ($size / 1MB)) -ForegroundColor Green
Write-Host ("sha256: {0}" -f $hash) -ForegroundColor Green
Write-Host ("元数据: {0}" -f $metaPath)

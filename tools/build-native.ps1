#Requires -Version 5.1
<#
.SYNOPSIS
  不打开 Android Studio，直接用 NDK 把 C++ 内核编成三份 libsubconv.so，并逐项自检。

.DESCRIPTION
  本工程平时是用 Gradle（externalNativeBuild + CMake）编 native 的。这个脚本走的是同一条
  路，只是把 AGP 换成手写命令：同一个 CMakeLists、同一份 NDK、同一组 -D 开关，产物是
  build\native-so\<abi>\libsubconv.so。

  它存在的意义：
    * 上游一更新，就能在命令行上立刻验证「三份 ABI 都编得过」，不用等 Studio；
    * CI 上也能跑（.github/workflows/manual-build.yml 那条路走的是 Gradle）；
    * 产物会被逐项验：ELF 架构对不对、libc++ 是不是真的静态链进去了、
      JNI 入口符号在不在 —— 这三样错了都是「装到手机上才炸」的类型。

  参数来源都取自工程自己的配置（local.properties 的 sdk.dir、build.gradle.kts 的
  ndkVersion / minSdk），不另立一份，避免两处版本对不上。

.PARAMETER Abis
  要编的 ABI。默认 arm64-v8a,armeabi-v7a,x86_64（与 app/build.gradle.kts 的 abiFilters 一致）。

.PARAMETER Api
  ANDROID_PLATFORM（android-<Api>）。默认取 build.gradle.kts 里的 minSdk。

.PARAMETER CppDir / OutDir / BuildDir
  CMake 源目录 / 产物目录 / CMake 缓存目录。默认分别是
  app\src\main\cpp、build\native-so、build\native-so\.cmake（build\ 已在 .gitignore 里）。

.PARAMETER Sdk / Ndk / Cmake
  手工指定 SDK / NDK / CMake 路径。默认从工程配置推出来。

.PARAMETER Clean
  先删掉 BuildDir，全量重编。

.PARAMETER Install
  额外把产物拷进 app\src\main\jniLibs\<abi>\libsubconv.so。
  ⚠ 只有当 Gradle 侧的 externalNativeBuild 关掉时，jniLibs 里这份才会是进包的那份；
  两边同时产出会被资源合并挡下来。默认不开。

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\build-native.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\build-native.ps1 -Abis arm64-v8a -Clean
#>
[CmdletBinding()]
param(
  [string[]]$Abis = @('arm64-v8a', 'armeabi-v7a', 'x86_64'),
  [int]$Api = 0,
  [string]$CppDir,
  [string]$OutDir,
  [string]$BuildDir,
  [string]$Sdk,
  [string]$Ndk,
  [string]$Cmake,
  [switch]$Clean,
  [switch]$Install
)

$ErrorActionPreference = 'Stop'

# -Abis 允许两种写法：PS 里 `-Abis a,b,c`（本来是数组）和命令行 `powershell -File ... -Abis a,b,c`
# —— 后者是**一个**字符串，PowerShell 不会替你按逗号拆开，结果整串被当成一个 ABI 名送给 CMake，
# 报的是 "Invalid Android ABI: a,b,c"。这里统一拆一遍。
$Abis = @($Abis | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
if ($Abis.Count -eq 0) { throw "-Abis 是空的。" }

$ExpectedMachine = @{
  'arm64-v8a'   = 0xB7   # EM_AARCH64
  'armeabi-v7a' = 0x28   # EM_ARM
  'x86'         = 0x03   # EM_386
  'x86_64'      = 0x3E   # EM_X86_64
}
$JniSymbols = @(
  'Java_com_subconverter_NativeServer_nativeVersion',
  'Java_com_subconverter_NativeServer_nativeSetRuntimeDirs',
  'Java_com_subconverter_NativeServer_nativeStart',
  'Java_com_subconverter_NativeServer_nativeStop',
  'Java_com_subconverter_NativeServer_nativeLastError',
  'Java_com_subconverter_NativeServer_nativeRunning'
)

# 抓一个外部工具的输出：写个一次性 .cmd 让 cmd 重定向进文件。
# 不用 `$out = & $tool ...`：受限环境（起不了管道）下 PowerShell 抓原生命令输出会直接失败，
# 而且 $LASTEXITCODE 会变成 $null。必须用 `& $cmdFile` 直接执行，别夹 `cmd /c "..."`。
# 命令串里的 % 要写成 %%：批处理里 % 是变量展开符，连双引号里也照样展开。
function Invoke-Capture {
  param([string]$Exe, [string[]]$ExeArgs)
  $cmdFile = Join-Path $script:Work 'run.cmd'
  $logFile = Join-Path $script:Work 'run.log'
  if (Test-Path $logFile) { Remove-Item $logFile -Force }
  $parts = @('"' + $Exe + '"')
  foreach ($a in $ExeArgs) { $parts += '"' + $a + '"' }
  $cmdline = ($parts -join ' ').Replace('%', '%%')
  $log2 = $logFile.Replace('%', '%%')
  $body = "@echo off`r`n" + $cmdline + ' > "' + $log2 + '" 2>&1' + "`r`nexit /b %ERRORLEVEL%`r`n"
  Set-Content -Path $cmdFile -Value $body -Encoding ASCII
  & $cmdFile
  $code = $LASTEXITCODE
  $out = @()
  if (Test-Path $logFile) { $out = @(Get-Content $logFile) }
  # 结果走 $script:CapResult，函数本身什么都不输出 —— 理由见 tools/README.md「注意事项」
  # 里那条「脚本里的外部命令不捕获输出」：
  # 调用方一旦对函数返回值赋值/接管道，函数内的原生命令就会被接上管道，受限环境下起不来。
  $script:CapResult = [pscustomobject]@{ Code = $code; Out = @($out); Text = ($out -join "`n") }
}

function Get-GradleValue {
  param([string]$File, [string]$Pattern)
  # 显式 UTF-8：build.gradle.kts / CMakeLists.txt 里有中文注释，PS 5.1 的
  # Get-Content 默认按 ANSI(GBK) 解，多字节乱码会把换行吃掉（同 tools/README.md「注意事项」）。
  $text = [IO.File]::ReadAllText($File, (New-Object Text.UTF8Encoding($false)))
  $m = [regex]::Match($text, $Pattern)
  if ($m.Success) { return $m.Groups[1].Value }
  return ''
}

# ---------------------------------------------------------------------------
# 0. 定位
# ---------------------------------------------------------------------------
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $CppDir) { $CppDir = Join-Path $repoRoot 'app\src\main\cpp' }
if (-not (Test-Path (Join-Path $CppDir 'CMakeLists.txt'))) {
  throw "找不到 CMakeLists.txt，-CppDir 给错了？ 实际用的：$CppDir"
}
if (-not $OutDir) { $OutDir = Join-Path $repoRoot 'build\native-so' }
if (-not $BuildDir) { $BuildDir = Join-Path $OutDir '.cmake' }

$script:Work = Join-Path $env:TEMP ('subconv-native-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $script:Work -Force | Out-Null

$gradle = Join-Path $repoRoot 'app\build.gradle.kts'
$localProps = Join-Path $repoRoot 'local.properties'

if (-not $Sdk) {
  if (Test-Path $localProps) {
    foreach ($line in Get-Content $localProps) {
      if ($line -match '^\s*sdk\.dir\s*=\s*(.+)$') {
        # local.properties 里是 Properties 转义：`A\:\\AndroidSDK` -> `A:\AndroidSDK`
        $Sdk = $Matches[1].Trim().Replace('\:', ':').Replace('\\', '\')
        break
      }
    }
  }
  if (-not $Sdk) { $Sdk = $env:ANDROID_SDK_ROOT }
  if (-not $Sdk) { $Sdk = $env:ANDROID_HOME }
}
if (-not $Sdk -or -not (Test-Path $Sdk)) {
  throw "找不到 Android SDK。用 -Sdk 指定，或在 local.properties 里写好 sdk.dir。当前值：'$Sdk'"
}

if (-not $Ndk) {
  $ndkVersion = ''
  if (Test-Path $gradle) { $ndkVersion = Get-GradleValue -File $gradle -Pattern 'ndkVersion\s*=\s*"([^"]+)"' }
  if (-not $ndkVersion) { throw "build.gradle.kts 里没找到 ndkVersion，用 -Ndk 指定 NDK 路径。" }
  $Ndk = Join-Path $Sdk ('ndk\' + $ndkVersion)
}
if (-not (Test-Path (Join-Path $Ndk 'build\cmake\android.toolchain.cmake'))) {
  throw "NDK 不对（找不到 build\cmake\android.toolchain.cmake）：$Ndk"
}

if (-not $Api) {
  $Api = 24
  if (Test-Path $gradle) {
    $v = Get-GradleValue -File $gradle -Pattern 'minSdk\s*=\s*(\d+)'
    if ($v) { $Api = [int]$v }
  }
}

# CMake 优先用 SDK 里那份（Gradle 也是这么找的，版本一致才好复现），没有才退回 PATH。
$sdkCmake = ''
if (Test-Path (Join-Path $Sdk 'cmake')) {
  $cand = Get-ChildItem (Join-Path $Sdk 'cmake') -Directory | Sort-Object Name -Descending
  foreach ($c in $cand) {
    $exe = Join-Path $c.FullName 'bin\cmake.exe'
    if (Test-Path $exe) { $sdkCmake = $exe; break }
  }
}
if (-not $Cmake) {
  if ($sdkCmake) { $Cmake = $sdkCmake }
  else {
    $onPath = Get-Command cmake -ErrorAction SilentlyContinue
    if ($onPath) { $Cmake = $onPath.Source } else { throw "找不到 CMake：SDK 里没有，PATH 上也没有。用 -Cmake 指定。" }
  }
}
if (-not (Test-Path $Cmake)) { throw "CMake 不存在：$Cmake" }

$ninja = Join-Path (Split-Path $Cmake -Parent) 'ninja.exe'
if (-not (Test-Path $ninja)) {
  $onPath = Get-Command ninja -ErrorAction SilentlyContinue
  if ($onPath) { $ninja = $onPath.Source } else { throw "找不到 ninja。用 SDK 里那份（$Sdk\cmake\*\bin\ninja.exe）或把它放进 PATH。" }
}

$readelf = Join-Path $Ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe'
$haveReadelf = Test-Path $readelf

Write-Host 'subconv-android 编 native 内核' -ForegroundColor White
Write-Host ("  工程    : {0}" -f $repoRoot)
Write-Host ("  源码    : {0}" -f $CppDir)
Write-Host ("  NDK     : {0}" -f $Ndk)
Write-Host ("  CMake   : {0}" -f $Cmake)
Write-Host ("  ninja   : {0}" -f $ninja)
Write-Host ("  ABI/API : {0}  android-{1}" -f ($Abis -join ', '), $Api)
Write-Host ("  产物    : {0}" -f $OutDir)

if ($Clean -and (Test-Path $BuildDir)) { Remove-Item $BuildDir -Recurse -Force }

$results = @()
foreach ($abi in $Abis) {
  Write-Host ''
  Write-Host ("== {0}" -f $abi) -ForegroundColor Cyan
  $res = [ordered]@{ Abi = $abi; Ok = $false; So = ''; Size = 0; Machine = ''; Needed = ''; Jni = 0; Note = '' }
  $bdir = Join-Path $BuildDir $abi

  $cfgArgs = @(
    '-G', 'Ninja',
    '-S', $CppDir,
    '-B', $bdir,
    ('-DCMAKE_TOOLCHAIN_FILE=' + (Join-Path $Ndk 'build\cmake\android.toolchain.cmake')),
    ('-DCMAKE_MAKE_PROGRAM=' + $ninja),
    ('-DANDROID_ABI=' + $abi),
    ('-DANDROID_PLATFORM=android-' + $Api),
    '-DANDROID_STL=c++_static',
    '-DCMAKE_BUILD_TYPE=Release',
    '-DSUBCONV_USE_YAML=ON'
  )
  & $Cmake @cfgArgs
  if ($LASTEXITCODE -ne 0) { $res.Note = 'configure 失败'; $results += $res; continue }

  & $Cmake '--build' $bdir '--target' 'subconv'
  if ($LASTEXITCODE -ne 0) { $res.Note = 'build 失败'; $results += $res; continue }

  $built = Join-Path $bdir 'libsubconv.so'
  if (-not (Test-Path $built)) {
    $found = @(Get-ChildItem $bdir -Recurse -Filter 'libsubconv.so' -ErrorAction SilentlyContinue)
    if ($found.Count -gt 0) { $built = $found[0].FullName } else { $res.Note = 'build 说成功了但没找到 libsubconv.so'; $results += $res; continue }
  }

  $destDir = Join-Path $OutDir $abi
  New-Item -ItemType Directory -Path $destDir -Force | Out-Null
  $dest = Join-Path $destDir 'libsubconv.so'
  Copy-Item $built $dest -Force
  $res.So = $dest
  $res.Size = (Get-Item $dest).Length

  # --- 校验 1：ELF 头与架构 ---
  $bytes = [IO.File]::ReadAllBytes($dest)
  $isElf = ($bytes[0] -eq 0x7F -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0x4C -and $bytes[3] -eq 0x46)
  $machine = $bytes[18] + ($bytes[19] -shl 8)
  $res.Machine = ('0x{0:X2}' -f $machine)
  $machineOk = $isElf -and ($ExpectedMachine[$abi] -eq $machine)
  if (-not $isElf) { $res.Note = '不是 ELF'; $results += $res; continue }
  if (-not $machineOk) { $res.Note = ('架构不对：期望 0x{0:X2}' -f $ExpectedMachine[$abi]) }

  # --- 校验 2/3：DT_NEEDED（libc++ 是否真的静态链进来）与 JNI 符号 ---
  $neededOk = $false
  if ($haveReadelf) {
    Invoke-Capture -Exe $readelf -ExeArgs @('--dynamic-table', $dest)
    $d = $script:CapResult
    $needed = @($d.Out | Where-Object { $_ -match 'NEEDED' } | ForEach-Object { ($_ -split '\[', 2)[1] -replace '\]', '' })
    $res.Needed = ($needed -join ', ')
    $neededOk = -not ($needed -contains 'libc++_shared.so')
    if (-not $neededOk -and -not $res.Note) { $res.Note = 'DT_NEEDED 里出现了 libc++_shared.so（c++_static 没生效）' }

    Invoke-Capture -Exe $readelf -ExeArgs @('--dyn-syms', $dest)
    $s = $script:CapResult
    $res.Jni = @($s.Out | Where-Object { $_ -match 'Java_com_subconverter_NativeServer_' }).Count
  }
  else {
    # 没有 llvm-readelf 时的退路：直接在字节里找字符串（够用，但是启发式）
    $ascii = [Text.Encoding]::ASCII.GetString($bytes)
    $neededOk = -not $ascii.Contains('libc++_shared.so')
    $res.Needed = '(无 readelf，按字符串判断)'
    $cnt = 0
    foreach ($sym in $JniSymbols) { if ($ascii.Contains($sym)) { $cnt++ } }
    $res.Jni = $cnt
  }
  if (($res.Jni -lt $JniSymbols.Count) -and -not $res.Note) {
    $res.Note = ('JNI 符号只找到 {0}/{1}' -f $res.Jni, $JniSymbols.Count)
  }

  $res.Ok = ($machineOk -and $neededOk -and ($res.Jni -ge $JniSymbols.Count) -and $res.Note -eq '')
  if ($res.Ok) { $res.Note = 'ok' }

  if ($Install) {
    $jniDir = Join-Path $repoRoot ('app\src\main\jniLibs\' + $abi)
    New-Item -ItemType Directory -Path $jniDir -Force | Out-Null
    Copy-Item $dest (Join-Path $jniDir 'libsubconv.so') -Force
  }

  $results += $res
}

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '== 汇总' -ForegroundColor Cyan
Write-Host ('{0,-14} {1,-18} {2,-8} {3,-7} {4,-6} {5}' -f 'ABI', 'libsubconv.so', 'e_machine', 'JNI', '结果', 'DT_NEEDED')
foreach ($r in $results) {
  $size = ''
  if ($r.Size -gt 0) { $size = ('{0:N0} B' -f $r.Size) }
  $line = '{0,-14} {1,-18} {2,-8} {3,-7} {4,-6} {5}' -f $r.Abi, $size, $r.Machine, ($r.Jni.ToString() + '/' + $JniSymbols.Count), $(if ($r.Ok) { 'OK' } else { 'FAIL' }), $r.Needed
  if ($r.Ok) { Write-Host $line -ForegroundColor Green } else { Write-Host $line -ForegroundColor Red }
  if (-not $r.Ok -and $r.Note) { Write-Host ('   ^ {0}' -f $r.Note) -ForegroundColor Red }
}

if ($Install) {
  Write-Host ''
  Write-Host '已拷进 app\src\main\jniLibs\<abi>\libsubconv.so' -ForegroundColor Yellow
  Write-Host '注意：Gradle 侧的 externalNativeBuild 关掉之后，jniLibs 里这份才是进包的那份；' -ForegroundColor Yellow
  Write-Host '      两边同时产出同一路径会被资源合并挡下来。' -ForegroundColor Yellow
}

Remove-Item $script:Work -Recurse -Force -ErrorAction SilentlyContinue

$bad = @($results | Where-Object { -not $_.Ok })
if ($bad.Count -gt 0) {
  Write-Host ''
  Write-Host ("{0} 个 ABI 没过：{1}" -f $bad.Count, (($bad | ForEach-Object { $_.Abi }) -join ', ')) -ForegroundColor Red
  exit 1
}
Write-Host ''
Write-Host ("全部 {0} 个 ABI 都 OK。" -f $results.Count) -ForegroundColor Green

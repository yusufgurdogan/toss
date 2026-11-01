# Install toss on Windows. In PowerShell:
#
#   irm https://raw.githubusercontent.com/yusufgurdogan/toss/main/install.ps1 | iex
#
# Run it again to update. Settings (environment variables):
#   TOSS_VERSION      release to install, e.g. v0.1.0 (default: latest)
#   TOSS_INSTALL_DIR  where to put toss.exe
#                     (default: %LOCALAPPDATA%\Programs\toss)
#
# No administrator rights needed. The archive is checked against the
# release's SHA256SUMS before anything is installed, and the install folder
# is added to your user PATH.

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue' # makes downloads much faster on PowerShell 5
    $repo = 'yusufgurdogan/toss'

    if ($PSVersionTable.PSVersion.Major -lt 6) {
        # Windows PowerShell 5 may default to TLS 1.0.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }

    $arch = $null
    try { $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() } catch { }
    if (-not $arch) {
        $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    }
    switch -Regex ($arch) {
        '^(X64|AMD64)$' { $goarch = 'amd64'; break }
        '^ARM64$' { $goarch = 'arm64'; break }
        default { throw "toss install: no prebuilt toss for processor '$arch'" }
    }

    $version = if ($env:TOSS_VERSION) { $env:TOSS_VERSION } else { 'latest' }
    if ($env:TOSS_BASE_URL) {
        $base = $env:TOSS_BASE_URL.TrimEnd('/') # a mirror, or a local test server
    } elseif ($version -eq 'latest') {
        $base = "https://github.com/$repo/releases/latest/download"
    } else {
        $base = "https://github.com/$repo/releases/download/$version"
    }
    $dir = if ($env:TOSS_INSTALL_DIR) { $env:TOSS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\toss' }

    $zip = "toss_windows_$goarch.zip"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('toss-install-' + [Guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Host "Downloading toss ($version, windows/$goarch)..."
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$zip" -OutFile (Join-Path $tmp $zip)
        Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')

        $want = $null
        foreach ($line in Get-Content (Join-Path $tmp 'SHA256SUMS')) {
            $fields = $line.Trim() -split '\s+'
            if ($fields.Count -eq 2 -and $fields[1].TrimStart('*') -eq $zip) { $want = $fields[0] }
        }
        if (-not $want) { throw "toss install: $zip is not listed in SHA256SUMS" }
        $got = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $zip)).Hash
        if ($got -ne $want) { throw "toss install: checksum mismatch for $zip (got $got, want $want); not installing" }

        Expand-Archive -Path (Join-Path $tmp $zip) -DestinationPath (Join-Path $tmp 'x') -Force
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $exe = Join-Path $dir 'toss.exe'
        try {
            Copy-Item -Force -Path (Join-Path $tmp 'x\toss.exe') -Destination $exe
        } catch {
            throw "toss install: can't write $exe (is toss running?): $($_.Exception.Message)"
        }
    } finally {
        Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
    }

    # Add the folder to the user PATH, keeping existing entries exactly as
    # they are (including unexpanded ones like %USERPROFILE%).
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    try {
        $old = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $entries = @($old -split ';' | Where-Object { $_ -ne '' })
        $present = $entries | Where-Object { [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -ieq $dir.TrimEnd('\') }
        if (-not $present) {
            $key.SetValue('Path', (($entries + $dir) -join ';'), [Microsoft.Win32.RegistryValueKind]::ExpandString)
            # Tell Windows the environment changed, so new terminals see it.
            [Environment]::SetEnvironmentVariable('TOSS_INSTALL_REFRESH', '1', 'User')
            [Environment]::SetEnvironmentVariable('TOSS_INSTALL_REFRESH', $null, 'User')
            $addedToPath = $true
        }
    } finally {
        $key.Close()
    }
    if (($env:Path -split ';') -notcontains $dir) { $env:Path = "$env:Path;$dir" }

    Write-Host "Installed $(& $exe version) to $exe"
    if ($addedToPath) {
        Write-Host "Added $dir to your PATH. Other terminal windows need to be reopened to see it."
    }
    Write-Host "Run 'toss help' to get started."
}

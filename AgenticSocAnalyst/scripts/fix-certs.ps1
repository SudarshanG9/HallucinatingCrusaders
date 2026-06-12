$certsDir = "C:\Users\mmddf\Desktop\Agentic AI SOC Analyst\infrastructure\certs"
$fixed = 0

Get-ChildItem $certsDir | Where-Object { $_.PSIsContainer } | ForEach-Object {
    $folderName = $_.Name
    $folderPath = $_.FullName
    $innerFile  = Join-Path $folderPath $folderName

    if (Test-Path $innerFile -PathType Leaf) {
        $dest = Join-Path $certsDir $folderName
        Copy-Item $innerFile "$dest.tmp"
        Remove-Item $folderPath -Recurse -Force
        Move-Item "$dest.tmp" $dest
        Write-Host "[FIXED] $folderName"
        $fixed = $fixed + 1
    } else {
        $pem = Get-ChildItem $folderPath -Filter "*.pem" -File | Select-Object -First 1
        if ($pem) {
            $dest = Join-Path $certsDir $folderName
            Copy-Item $pem.FullName "$dest.tmp"
            Remove-Item $folderPath -Recurse -Force
            Move-Item "$dest.tmp" $dest
            Write-Host "[FIXED] $folderName (from $($pem.Name))"
            $fixed = $fixed + 1
        } else {
            Write-Host "[SKIP]  $folderName"
        }
    }
}

Write-Host ""
Write-Host "Fixed $fixed cert entries. Final state:"
Get-ChildItem $certsDir | Select-Object Name, PSIsContainer, Length | Format-Table -AutoSize

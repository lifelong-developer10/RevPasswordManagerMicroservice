$ErrorActionPreference = "Continue"

Write-Host "Cleaning up old logs..."
Remove-Item -Path ".\*\*\boot.log" -ErrorAction SilentlyContinue
Remove-Item -Path ".\*\*\boot.err" -ErrorAction SilentlyContinue

$services = @(
    "infrastructure\eureka-server",
    "infrastructure\config-server",
    "infrastructure\api-gateway",
    "microservices\user-service",
    "microservices\vault-service",
    "microservices\generator-service",
    "microservices\security-service",
    "microservices\notification-service"
)

foreach ($service in $services) {
    Write-Host "Starting $service..."
    $servicePath = Join-Path (Get-Location) $service
    
    $proc = Start-Process -FilePath "mvn.cmd" -ArgumentList "spring-boot:run" -WorkingDirectory $servicePath -PassThru -WindowStyle Hidden -RedirectStandardOutput "$servicePath\boot.log" -RedirectStandardError "$servicePath\boot.err"
    
    # Wait for Eureka and Config Server a bit longer
    if ($service -match "eureka-server") {
        Write-Host "Waiting 15s for Eureka Server..."
        Start-Sleep -Seconds 15
    } elseif ($service -match "config-server") {
        Write-Host "Waiting 10s for Config Server..."
        Start-Sleep -Seconds 10
    } else {
        Start-Sleep -Seconds 5
    }
}

Write-Host "All services startup initiated. Wait 30-60s for full registration."

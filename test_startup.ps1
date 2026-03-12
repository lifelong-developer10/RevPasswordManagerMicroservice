$ErrorActionPreference = "Continue"

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
    Set-Location "c:\Users\DELL\Downloads\RevPassword_Manager-Microservices\$service"
    Write-Host "Starting $service..."
    $proc = Start-Process -FilePath "mvn.cmd" -ArgumentList "spring-boot:run" -PassThru -WindowStyle Hidden -RedirectStandardOutput "boot.log" -RedirectStandardError "boot.err"
    
    Start-Sleep -Seconds 15
    
    if (-not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force
        Write-Host "$service started successfully."
    } else {
        Write-Host "$service failed to start! Check boot.log and boot.err."
    }
}

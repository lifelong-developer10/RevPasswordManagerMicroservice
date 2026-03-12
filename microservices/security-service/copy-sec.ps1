$monolith = "c:\Users\DELL\Downloads\RevPassword_Manager-Microservices\RevPassword_Manager\src\main\java\com\example\revpassword_manager"
$secSrc = "c:\Users\DELL\Downloads\RevPassword_Manager-Microservices\microservices\security-service\src\main\java\com\revature\security"

New-Item -ItemType Directory -Force -Path "$secSrc\controllers"
New-Item -ItemType Directory -Force -Path "$secSrc\services"
New-Item -ItemType Directory -Force -Path "$secSrc\dtos"

$files = @(
    @{ Src = "$monolith\Services\PasswordStrengthService.java"; Dest = "$secSrc\services\PasswordStrengthService.java" },
    @{ Src = "$monolith\DTOs\PasswordStrengthResponse.java"; Dest = "$secSrc\dtos\PasswordStrengthResponse.java" }
)

foreach ($f in $files) {
    if (Test-Path $f.Src) {
        Copy-Item -Path $f.Src -Destination $f.Dest
        $content = Get-Content $f.Dest
        $content = $content -replace "package com.example.revpassword_manager.(Controllers|Services|DTOs);",
                                     "package com.revature.security.`$1;" `
                            -replace "package com.revature.security.Controllers;", "package com.revature.security.controllers;" `
                            -replace "package com.revature.security.Services;", "package com.revature.security.services;" `
                            -replace "package com.revature.security.DTOs;", "package com.revature.security.dtos;" `
                            -replace "import com.example.revpassword_manager.(Controllers|Services|DTOs).", "import com.revature.security.`$1." `
                            -replace "import com.revature.security.Controllers.", "import com.revature.security.controllers." `
                            -replace "import com.revature.security.Services.", "import com.revature.security.services." `
                            -replace "import com.revature.security.DTOs.", "import com.revature.security.dtos." 
        Set-Content -Path $f.Dest -Value $content
        Write-Host "Migrated $($f.Dest)"
    } else {
        Write-Host "Missing $($f.Src)"
    }
}

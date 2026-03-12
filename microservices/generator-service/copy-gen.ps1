$monolith = "c:\Users\DELL\Downloads\RevPassword_Manager-Microservices\RevPassword_Manager\src\main\java\com\example\revpassword_manager"
$genSrc = "c:\Users\DELL\Downloads\RevPassword_Manager-Microservices\microservices\generator-service\src\main\java\com\revature\generator"

New-Item -ItemType Directory -Force -Path "$genSrc\controllers"
New-Item -ItemType Directory -Force -Path "$genSrc\services"
New-Item -ItemType Directory -Force -Path "$genSrc\dtos"

$files = @(
    @{ Src = "$monolith\Controllers\PasswordGeneratorController.java"; Dest = "$genSrc\controllers\PasswordGeneratorController.java" },
    @{ Src = "$monolith\Services\PasswordGeneratorService.java"; Dest = "$genSrc\services\PasswordGeneratorService.java" },
    @{ Src = "$monolith\DTOs\PasswordGenerateRequest.java"; Dest = "$genSrc\dtos\PasswordGenerateRequest.java" },
    @{ Src = "$monolith\DTOs\PasswordGenerateResponse.java"; Dest = "$genSrc\dtos\PasswordGenerateResponse.java" }
)

foreach ($f in $files) {
    if (Test-Path $f.Src) {
        Copy-Item -Path $f.Src -Destination $f.Dest
        $content = Get-Content $f.Dest
        $content = $content -replace "package com.example.revpassword_manager.(Controllers|Services|DTOs);",
                                     "package com.revature.generator.`$1;" `
                            -replace "package com.revature.generator.Controllers;", "package com.revature.generator.controllers;" `
                            -replace "package com.revature.generator.Services;", "package com.revature.generator.services;" `
                            -replace "package com.revature.generator.DTOs;", "package com.revature.generator.dtos;" `
                            -replace "import com.example.revpassword_manager.(Controllers|Services|DTOs).", "import com.revature.generator.`$1." `
                            -replace "import com.revature.generator.Controllers.", "import com.revature.generator.controllers." `
                            -replace "import com.revature.generator.Services.", "import com.revature.generator.services." `
                            -replace "import com.revature.generator.DTOs.", "import com.revature.generator.dtos." 
        Set-Content -Path $f.Dest -Value $content
        Write-Host "Migrated $($f.Dest)"
    } else {
        Write-Host "Missing $($f.Src)"
    }
}

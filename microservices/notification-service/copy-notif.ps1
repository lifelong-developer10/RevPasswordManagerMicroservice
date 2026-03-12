$monolith = "c:\Users\DELL\Downloads\RevPassword_Manager-Microservices\RevPassword_Manager\src\main\java\com\example\revpassword_manager"
$notifSrc = "c:\Users\DELL\Downloads\RevPassword_Manager-Microservices\microservices\notification-service\src\main\java\com\revature\notification"

New-Item -ItemType Directory -Force -Path "$notifSrc\controllers"
New-Item -ItemType Directory -Force -Path "$notifSrc\services"
New-Item -ItemType Directory -Force -Path "$notifSrc\models"
New-Item -ItemType Directory -Force -Path "$notifSrc\repository"
New-Item -ItemType Directory -Force -Path "$notifSrc\dtos"

$files = @(
    @{ Src = "$monolith\Controllers\OtpController.java"; Dest = "$notifSrc\controllers\OtpController.java" },
    @{ Src = "$monolith\Services\OtpService.java"; Dest = "$notifSrc\services\OtpService.java" },
    @{ Src = "$monolith\Models\OTPGenerater.java"; Dest = "$notifSrc\models\OTPGenerater.java" },
    @{ Src = "$monolith\Reposiotory\OtpRepository.java"; Dest = "$notifSrc\repository\OtpRepository.java" },
    @{ Src = "$monolith\DTOs\OtpRequest.java"; Dest = "$notifSrc\dtos\OtpRequest.java" },
    @{ Src = "$monolith\DTOs\OtpVerifyRequest.java"; Dest = "$notifSrc\dtos\OtpVerifyRequest.java" }
)

foreach ($f in $files) {
    if (Test-Path $f.Src) {
        Copy-Item -Path $f.Src -Destination $f.Dest
        $content = Get-Content $f.Dest
        $content = $content -replace "package com.example.revpassword_manager.(Controllers|Services|Models|Reposiotory|DTOs);",
                                     "package com.revature.notification.`$1;" `
                            -replace "package com.revature.notification.Controllers;", "package com.revature.notification.controllers;" `
                            -replace "package com.revature.notification.Services;", "package com.revature.notification.services;" `
                            -replace "package com.revature.notification.Models;", "package com.revature.notification.models;" `
                            -replace "package com.revature.notification.Reposiotory;", "package com.revature.notification.repository;" `
                            -replace "package com.revature.notification.DTOs;", "package com.revature.notification.dtos;" `
                            -replace "import com.example.revpassword_manager.(Controllers|Services|Models|Reposiotory|DTOs).", "import com.revature.notification.`$1." `
                            -replace "import com.revature.notification.Controllers.", "import com.revature.notification.controllers." `
                            -replace "import com.revature.notification.Services.", "import com.revature.notification.services." `
                            -replace "import com.revature.notification.Models.", "import com.revature.notification.models." `
                            -replace "import com.revature.notification.Reposiotory.", "import com.revature.notification.repository." `
                            -replace "import com.revature.notification.DTOs.", "import com.revature.notification.dtos." 
        Set-Content -Path $f.Dest -Value $content
        Write-Host "Migrated $($f.Dest)"
    } else {
        Write-Host "Missing $($f.Src)"
    }
}

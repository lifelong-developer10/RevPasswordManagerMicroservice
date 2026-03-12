$monolith = "c:\Users\DELL\Downloads\RevPassword_Manager-Microservices\RevPassword_Manager\src\main\java\com\example\revpassword_manager"
$vaultSrc = "c:\Users\DELL\Downloads\RevPassword_Manager-Microservices\microservices\vault-service\src\main\java\com\revature\vault"

# Create directories
New-Item -ItemType Directory -Force -Path "$vaultSrc\controllers"
New-Item -ItemType Directory -Force -Path "$vaultSrc\services"
New-Item -ItemType Directory -Force -Path "$vaultSrc\models"
New-Item -ItemType Directory -Force -Path "$vaultSrc\repository"
New-Item -ItemType Directory -Force -Path "$vaultSrc\dtos"

# Files to copy
$files = @(
    @{ Src = "$monolith\Controllers\PasswordEntryController.java"; Dest = "$vaultSrc\controllers\PasswordEntryController.java" },
    @{ Src = "$monolith\Services\PasswordEntryService.java"; Dest = "$vaultSrc\services\PasswordEntryService.java" },
    @{ Src = "$monolith\Models\AllPasswordEntry.java"; Dest = "$vaultSrc\models\AllPasswordEntry.java" },
    @{ Src = "$monolith\Reposiotory\PasswordEntryRepository.java"; Dest = "$vaultSrc\repository\PasswordEntryRepository.java" },
    @{ Src = "$monolith\DTOs\PasswordEntryResponse.java"; Dest = "$vaultSrc\dtos\PasswordEntryResponse.java" },
    @{ Src = "$monolith\DTOs\PasswordEntryRequest.java"; Dest = "$vaultSrc\dtos\PasswordEntryRequest.java" }
)

foreach ($f in $files) {
    if (Test-Path $f.Src) {
        Copy-Item -Path $f.Src -Destination $f.Dest
        # Refactor packages
        $content = Get-Content $f.Dest
        $content = $content -replace "package com.example.revpassword_manager.(Controllers|Services|Models|Reposiotory|DTOs);",
                                     "package com.revature.vault.`$1;" `
                            -replace "package com.revature.vault.Controllers;", "package com.revature.vault.controllers;" `
                            -replace "package com.revature.vault.Services;", "package com.revature.vault.services;" `
                            -replace "package com.revature.vault.Models;", "package com.revature.vault.models;" `
                            -replace "package com.revature.vault.Reposiotory;", "package com.revature.vault.repository;" `
                            -replace "package com.revature.vault.DTOs;", "package com.revature.vault.dtos;" `
                            -replace "import com.example.revpassword_manager.(Controllers|Services|Models|Reposiotory|DTOs).", "import com.revature.vault.`$1." `
                            -replace "import com.revature.vault.Controllers.", "import com.revature.vault.controllers." `
                            -replace "import com.revature.vault.Services.", "import com.revature.vault.services." `
                            -replace "import com.revature.vault.Models.", "import com.revature.vault.models." `
                            -replace "import com.revature.vault.Reposiotory.", "import com.revature.vault.repository." `
                            -replace "import com.revature.vault.DTOs.", "import com.revature.vault.dtos." 
        Set-Content -Path $f.Dest -Value $content
        Write-Host "Migrated $($f.Dest)"
    } else {
        Write-Host "Missing $($f.Src)"
    }
}

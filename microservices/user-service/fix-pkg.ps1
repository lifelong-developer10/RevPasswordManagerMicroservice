$files = Get-ChildItem -Path "src\main\java\com\revature\user" -Recurse -Filter "*.java"
foreach ($f in $files) {
    (Get-Content $f.FullName) -replace 'package com\.revature\.user\.Services;', 'package com.revature.user.services;' `
    -replace 'package com\.revature\.user\.Models;', 'package com.revature.user.models;' `
    -replace 'package com\.revature\.user\.Controllers;', 'package com.revature.user.controllers;' `
    -replace 'package com\.revature\.user\.Security;', 'package com.revature.user.security;' |
    Set-Content $f.FullName
}

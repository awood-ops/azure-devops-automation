@{
    ExcludeRules = @(
        # Interactive console tools — Write-Host is intentional for coloured output
        'PSAvoidUsingWriteHost',
        # Files authored on Linux/WSL without BOM — not a functional issue
        'PSUseBOMForUnicodeEncodedFile',
        # Pre-existing scripts grandfathered in — address incrementally
        'PSAvoidUsingEmptyCatchBlock',
        'PSReviewUnusedParameter',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSUseSingularNouns',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSShouldProcess'
    )
}

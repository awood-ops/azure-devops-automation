@{
    ExcludeRules = @(
        # Interactive console tools — Write-Host is intentional for coloured output
        'PSAvoidUsingWriteHost',
        # Files authored on Linux/WSL without BOM — not a functional issue
        'PSUseBOMForUnicodeEncodedFile'
    )
}

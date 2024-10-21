import base64

# Function to obfuscate PowerShell script using Base64 encoding
def obfuscate_script(script_path):
    # Read the PowerShell script
    with open(script_path, 'r') as file:
        script_content = file.read()

    # Encode the script content into bytes (UTF-16LE for PowerShell) and Base64 encode it
    script_bytes = script_content.encode('utf-16le')  # PowerShell expects UTF-16LE encoding
    encoded_script = base64.b64encode(script_bytes)

    # Convert the encoded script back to a string
    encoded_script_str = encoded_script.decode('utf-8')

    return encoded_script_str

# Path to your PowerShell script
script_path = 'exploit/payload.ps1'

# Obfuscate the PowerShell script
obfuscated_script = obfuscate_script(script_path)

# Create the final PowerShell command with the encoded script
final_script = f'powershell.exe -EncodedCommand {obfuscated_script}'

# Save the final obfuscated script to a new .ps1 file
with open('exploit/payload.ps1', 'w') as file:
    file.write(final_script)

print("Obfuscated PowerShell script saved to 'exploit/payload.ps1'")

param (
    [string]$opcion,
    [string]$rutaCarpetaArchivos = "CarpetaOriginal",
    [string]$rutaArchivoClaves = "llaves_finales.txt"
)

# Función para encriptar un archivo con claves AES
function EncriptarConAES {
    param (
        [string]$rutaArchivoOriginal,
        [string]$rutaArchivoEncriptado
    )

    $bytesArchivoOriginal = Get-Content -Path $rutaArchivoOriginal -Encoding Byte

    $aes = [System.Security.Cryptography.AesManaged]::new()
    $aes.GenerateKey()
    $aes.GenerateIV()

    # Guardar la clave AES y el IV en archivos (opcional)
    $aes.Key | Set-Content -Path "$rutaArchivoEncriptado.key" -Encoding Byte
    $aes.IV | Set-Content -Path "$rutaArchivoEncriptado.iv" -Encoding Byte

    $ms = [System.IO.MemoryStream]::new()
    $cs = $aes.CreateEncryptor()
    $csstream = [System.Security.Cryptography.CryptoStream]::new($ms, $cs, [System.Security.Cryptography.CryptoStreamMode]::Write)

    $csstream.Write($bytesArchivoOriginal, 0, $bytesArchivoOriginal.Length)
    $csstream.Close()

    $bytesEncriptados = $ms.ToArray()
    $bytesEncriptados | Set-Content -Path $rutaArchivoEncriptado -Encoding Byte
}

# Función para desencriptar un archivo con claves AES
function DesencriptarConAES {
    param (
        [string]$rutaArchivoEncriptado,
        [string]$rutaArchivoDesencriptado
    )

    $claveAES = Get-Content -Path "$rutaArchivoEncriptado.key" -Encoding Byte
    $ivAES = Get-Content -Path "$rutaArchivoEncriptado.iv" -Encoding Byte

    $aes = [System.Security.Cryptography.AesManaged]::new()
    $aes.Key = $claveAES
    $aes.IV = $ivAES

    $bytesEncriptados = Get-Content -Path $rutaArchivoEncriptado -Encoding Byte

    $ms = [System.IO.MemoryStream]::new($bytesEncriptados, 0, $bytesEncriptados.Length)
    $cs = $aes.CreateDecryptor()
    $csstream = [System.Security.Cryptography.CryptoStream]::new($ms, $cs, [System.Security.Cryptography.CryptoStreamMode]::Read)

    $bytesDesencriptados = New-Object byte[] $bytesEncriptados.Length
    $csstream.Read($bytesDesencriptados, 0, $bytesDesencriptados.Length)

    $csstream.Close()

    $bytesDesencriptados | Set-Content -Path $rutaArchivoDesencriptado -Encoding Byte
}

# Función para encriptar un archivo con claves RSA
function EncriptarConRSA {
    param (
        [string]$rutaArchivoOriginal,
        [string]$rutaArchivoClavePublica,
        [string]$rutaArchivoEncriptado
    )

    try {
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.FromXmlString((Get-Content -Path $rutaArchivoClavePublica))

        # Leer datos de archivo
        $bytesArchivoOriginal = Get-Content -Path $rutaArchivoOriginal -Encoding Byte

        # Encriptar los datos con RSA
        $bytesEncriptados = $rsa.Encrypt($bytesArchivoOriginal, $true)

        # Guardar datos encriptados en archivo
        $bytesEncriptados | Set-Content -Path $rutaArchivoEncriptado -Encoding Byte
    } catch {
        Write-Host "Error al encriptar con RSA: $_"
    }
}

# Función para desencriptar un archivo con claves RSA
function DesencriptarConRSA {
    param (
        [string]$rutaArchivoEncriptado,
        [string]$rutaArchivoClavePrivada,
        [string]$rutaArchivoDesencriptado
    )

    try {
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.FromXmlString((Get-Content -Path $rutaArchivoClavePrivada))

        # Leer datos de archivo encriptado
        $bytesEncriptados = Get-Content -Path $rutaArchivoEncriptado -Encoding Byte

        # Desencriptar los datos con RSA
        $bytesDesencriptados = $rsa.Decrypt($bytesEncriptados, $true)

        # Guardar datos desencriptados en archivo
        $bytesDesencriptados | Set-Content -Path $rutaArchivoDesencriptado -Encoding Byte
    } catch {
        Write-Host "Error al desencriptar con RSA: $_"
    }
}

# Función para generar claves RSA y guardarlas en archivos XML
function GenerarClavesRSA {
    param (
        [string]$rutaArchivoClavePublica,
        [string]$rutaArchivoClavePrivada
    )

    try {
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider

        # Guardar claves en archivos XML
        $clavePublica = $rsa.ToXmlString($false)
        $clavePrivada = $rsa.ToXmlString($true)

        $clavePublica | Out-File -FilePath $rutaArchivoClavePublica -Force
        $clavePrivada | Out-File -FilePath $rutaArchivoClavePrivada -Force
    } catch {
        Write-Host "Error al generar claves RSA: $_"
    }
}

# Función para encriptar un archivo con claves AES y generar un archivo de claves
function EncriptarYGenerarClaves {
    param (
        [string]$rutaCarpetaArchivos,
        [string]$rutaArchivoClaves,
        [string]$rutaArchivoClavePublicaRSA,
        [string]$rutaArchivoClavePrivadaRSA
    )

    # Crear la carpeta ENCRYPTADOS si no existe
    $carpetaEncriptados = Join-Path $rutaCarpetaArchivos "ENCRYPTADOS"
    if (-not (Test-Path $carpetaEncriptados -PathType Container)) {
        New-Item -ItemType Directory -Path $carpetaEncriptados | Out-Null
    }

    # Obtener la lista de archivos en la carpeta
    $archivos = Get-ChildItem $rutaCarpetaArchivos

    # Generar claves RSA si no existen
    if (-not (Test-Path $rutaArchivoClavePublicaRSA) -or -not (Test-Path $rutaArchivoClavePrivadaRSA)) {
        GenerarClavesRSA -rutaArchivoClavePublica $rutaArchivoClavePublicaRSA -rutaArchivoClavePrivada $rutaArchivoClavePrivadaRSA
        Write-Host "Claves RSA generadas y guardadas en archivos XML:"
        Write-Host "Clave Pública: $rutaArchivoClavePublicaRSA"
        Write-Host "Clave Privada: $rutaArchivoClavePrivadaRSA"
    }

    foreach ($archivo in $archivos) {
        if ($archivo.PSIsContainer -eq $false) {
            $rutaArchivoOriginal = $archivo.FullName
            $rutaArchivoEncriptado = Join-Path $carpetaEncriptados "$($archivo.BaseName)_encriptado.bin"

            # Encriptar el archivo
            EncriptarConAES -rutaArchivoOriginal $rutaArchivoOriginal -rutaArchivoEncriptado $rutaArchivoEncriptado

            # Guardar las claves en el archivo
            Add-Content -Path $rutaArchivoClaves -Value ("$($archivo.BaseName),$($rutaArchivoEncriptado),$rutaArchivoOriginal")

            # Eliminar el archivo original
            Remove-Item $rutaArchivoOriginal -Force
        }
    }

    # Encriptar las claves .key y .iv con RSA
    $claves = Get-Content -Path $rutaArchivoClaves
    foreach ($clave in $claves) {
        $datosClave = $clave -split ","
        $rutaArchivoEncriptado = $datosClave[1]

        # Encriptar .key con RSA
        EncriptarConRSA -rutaArchivoOriginal "$rutaArchivoEncriptado.key" -rutaArchivoClavePublica $rutaArchivoClavePublicaRSA -rutaArchivoEncriptado "$rutaArchivoEncriptado.key_encrypted"

        # Encriptar .iv con RSA
        EncriptarConRSA -rutaArchivoOriginal "$rutaArchivoEncriptado.iv" -rutaArchivoClavePublica $rutaArchivoClavePublicaRSA -rutaArchivoEncriptado "$rutaArchivoEncriptado.iv_encrypted"
    }
}

# Función para desencriptar archivos a partir de un archivo de claves
function DesencriptarDesdeClaves {
    param (
        [string]$rutaArchivoClaves,
        [string]$rutaArchivoClavePrivadaRSA
    )

    # Crear la carpeta DESENCRIPTADOS si no existe
    $carpetaDesencriptados = Join-Path $PSScriptRoot "DESENCRIPTADOS"
    if (-not (Test-Path $carpetaDesencriptados -PathType Container)) {
        New-Item -ItemType Directory -Path $carpetaDesencriptados | Out-Null
    }

    # Desencriptar las claves .key y .iv con RSA
    $claves = Get-Content -Path $rutaArchivoClaves
    foreach ($clave in $claves) {
        $datosClave = $clave -split ","
        $rutaArchivoEncriptado = $datosClave[1]

        # Desencriptar .key con RSA
        DesencriptarConRSA -rutaArchivoEncriptado "$rutaArchivoEncriptado.key_encrypted" -rutaArchivoClavePrivada $rutaArchivoClavePrivadaRSA -rutaArchivoDesencriptado "$rutaArchivoEncriptado.key"

        # Desencriptar .iv con RSA
        DesencriptarConRSA -rutaArchivoEncriptado "$rutaArchivoEncriptado.iv_encrypted" -rutaArchivoClavePrivada $rutaArchivoClavePrivadaRSA -rutaArchivoDesencriptado "$rutaArchivoEncriptado.iv"
    }

    # Leer las claves desde el archivo original y desencriptar los archivos
    foreach ($clave in $claves) {
        $datosClave = $clave -split ","
        $nombreArchivo = $datosClave[0]
        $rutaArchivoOriginal = $datosClave[2]
        $rutaArchivoEncriptado = $datosClave[1]
        $nombreArchivoDesencriptado = "$nombreArchivo" + "." + ($rutaArchivoOriginal -split '\.')[1]

        $rutaArchivoDesencriptado = Join-Path $carpetaDesencriptados $nombreArchivoDesencriptado

        # Desencriptar el archivo con AES
        DesencriptarConAES -rutaArchivoEncriptado $rutaArchivoEncriptado -rutaArchivoDesencriptado $rutaArchivoDesencriptado
    }
}

# Switch para ejecutar la opción seleccionada
switch ($opcion) {
    "encrypt" {
        EncriptarYGenerarClaves -rutaCarpetaArchivos $rutaCarpetaArchivos -rutaArchivoClaves $rutaArchivoClaves -rutaArchivoClavePublicaRSA "clave_publica.xml" -rutaArchivoClavePrivadaRSA "clave_privada.xml"
    }
    "decrypt" {
        DesencriptarDesdeClaves -rutaArchivoClaves $rutaArchivoClaves -rutaArchivoClavePrivadaRSA "clave_privada.xml"
    }
    default {
        Write-Host "Uso: .\encriptado_grupal -opcion <encrypt/decrypt> [-rutaCarpetaArchivos <ruta>] [-rutaArchivoClaves <ruta>]"
    }
}


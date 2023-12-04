# Definir el nombre de la computadora
$computerName = $env:COMPUTERNAME
$Admitidos = "Administrator,luis"
# Definir el archivo de registro para almacenar el último timestamp y estado de evento
$archivoRegistro = "ultimo_evento.txt"

# Obtener el último timestamp y estado de evento almacenado o asignar uno nuevo si el archivo no existe
if (Test-Path $archivoRegistro) {
    $contenidoRegistro = Get-Content -Path $archivoRegistro
    $ultimoTimestamp, $ultimoEstado = $contenidoRegistro -split ','
} else {
    $ultimoTimestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffffffzzz")
    $ultimoEstado = ""  # Cambiado: Inicializar como cadena vacía
    "$ultimoTimestamp,$ultimoEstado" | Out-File -FilePath $archivoRegistro -Force
    $ultimoEvento = $null  # Añadido: para almacenar el último evento
}

# Bucle infinito para monitorear continuamente
while ($true) {
    # Filtrar eventos de auditoría de archivos y carpetas (código de evento 4656) desde el último timestamp
    $filterXml = @"
    <QueryList>
        <Query Id="0" Path="Security">
            <Select Path="Security">
                *[System[(EventID=4656) and TimeCreated[@SystemTime>'$ultimoTimestamp']]]
                and
                *[EventData[Data[@Name='ObjectType'] and (Data='File')]]
            </Select>
        </Query>
    </QueryList>
"@

    # Obtener los eventos del registro y ordenarlos por la marca de tiempo
    $eventos = Get-WinEvent -ComputerName $computerName -FilterXml $filterXml | Sort-Object -Property TimeCreated -Descending

    # Verificar si hay eventos y mostrar información relevante solo si es un nuevo evento diferente al último
    if ($eventos.Count -gt 0) {
        $nuevoEvento = $eventos[0]

        # Convertir la información del evento en una cadena para comparación
        $nuevoEstado = "$($nuevoEvento.Properties[6].Value),$($nuevoEvento.Properties[1].Value),$($nuevoEvento.Properties[15].Value),$($nuevoEvento.TimeCreated)"

        # Comparar con el último estado y mostrar información solo si es diferente y no es la primera vez
        if (($nuevoEstado -ne $ultimoEstado) -and ($ultimoEstado -ne "")) {
            # Obtener información del nuevo evento
            $eventData = $nuevoEvento.Properties
            $archivoModificado = $eventData[6].Value
            $usuario = $eventData[1].Value
            $accion = $eventData[15].Value
            $fecha = $nuevoEvento.TimeCreated
            $mensaje = "Archivo: $archivoModificado | Usuario: $usuario | Programa: $accion | Fecha: $fecha"

            # Escribir el mensaje en el archivo de registro
            Add-Content -Path $archivoRegistro -Value $mensaje

            # Verificar si el usuario está en la lista de admitidos
            $usuarioAdmitido = $Admitidos -split ',' | ForEach-Object { $_.Trim() }
            if ($usuario -notin $usuarioAdmitido) {
                # Ejecutar el script encriptado_grupal.ps1 solo si el usuario no está en la lista de admitidos
                Write-Host "Usuario no admitido. Ejecutando encriptado_grupal.ps1..."
                $scriptPath = Join-Path $PSScriptRoot "encriptado_grupal.ps1"
                & $scriptPath -opcion encrypt -rutaCarpetaArchivos .\CarpetaOriginal\ -rutaArchivoClaves llaves_finales.txt
            }
            else{
                Write-Host "Usuario $usuario Adminitido"
            }
            # Actualizar el último evento y timestamp en el archivo de registro
            $ultimoEvento = $nuevoEvento 
            $ultimoEstado = $nuevoEstado
            $ultimoTimestamp = $nuevoEvento.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fffffffzzz")
            "$ultimoTimestamp,$ultimoEstado" | Out-File -FilePath $archivoRegistro -Force
          
        } elseif ($ultimoEstado -eq "") {
            # Si es la primera vez, actualizar el último estado sin imprimir
            $ultimoEstado = $nuevoEstado
            "$ultimoTimestamp,$ultimoEstado" | Out-File -FilePath $archivoRegistro -Force
        }
    }

    # Esperar un breve período antes de la siguiente iteración
    Start-Sleep -Seconds 1
}


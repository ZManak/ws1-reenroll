# Workspace One Reenroll Script
Este script de PowerShell está diseñado para limpiar claves de registro, archivos de registro y certificados relacionados con AirWatch y Microsoft MDM (Mobile Device Management) en una máquina con Windows. Asegura que todos los datos relevantes se eliminen para romper la relación MDM y limpiar el sistema. 

## Desglose por funciones 

### Uninstall-Hub 

* Eliminar Claves de Registro 

El script comienza eliminando claves de registro específicas relacionadas con AirWatch y Microsoft MDM. 

* Sincronizar OMA-DM 

Registra un mensaje indicando el inicio de la sincronización OMA-DM para romper la relación MDM. 

Recupera el GUID para la cuenta OMA-DM y comienza el proceso de Device Enroller. 

Espera 5 minutos para permitir que el proceso de desinscripción se complete. 

* Eliminar Claves de Registro Nuevamente 

Asegura que no queden claves de registro eliminándolas nuevamente. 
``` 
Remove-Item -Path HKLM:\SOFTWARE\Airwatch -Recurse -ErrorAction SilentlyContinue 
Remove-Item -Path HKLM:\SOFTWARE\AirwatchMDM -Recurse -ErrorAction SilentlyContinue 
Remove-Item -Path HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\* -Recurse -ErrorAction SilentlyContinue 
Remove-Item -Path HKLM:\SOFTWARE\Microsoft\Enrollments\* -Recurse -ErrorAction SilentlyContinue 
Remove-Item -Path HKLM:\SOFTWARE\Microsoft\Provisioning\omadm\Accounts\* -Recurse -ErrorAction SilentlyContinue 
```  
* Eliminar Archivos y Carpetas de Registro 

Registra un mensaje indicando el inicio de la eliminación de archivos y carpetas de registro. 

Elimina archivos y carpetas relacionados con AirWatch y AirWatchMDM. 

Espera 5 segundos entre operaciones para asegurar la finalización.  

* Eliminar Certificados de AirWatch 

Registra un mensaje indicando el inicio de la eliminación de certificados de AirWatch. 

Recupera y elimina certificados emitidos por "AirWatchCa". 
``` 
$Certs = get-childitem cert:"CurrentUser" -Recurse 
$AirwatchCert = $certs | Where-Object { $_.Issuer -eq "CN=AirWatchCa" } 
foreach ($Cert in $AirwatchCert) {  $cert | Remove-Item -Force } 
```  

### Enroll-Hub 

La función Enroll-Hub es responsable de inscribir el Workspace ONE Hub. Registra los parámetros de inscripción, incluyendo el servidor, el ID del grupo de organización y las credenciales de puesta en escena. La función construye una lista de argumentos para el instalador MSI, especificando varios parámetros como el servidor, el ID del grupo de organización, el nombre de usuario, la contraseña y la ruta del registro. Luego usa el cmdlet Start-Process para ejecutar el instalador MSI con los argumentos especificados y espera a que el proceso se complete. Después de iniciar la inscripción, la función pausa durante 5 minutos (start-sleep 300) para permitir que el proceso de inscripción se complete. 

### Get-Enrollment 

La función Get-Enrollment verifica si hay una inscripción válida de Workspace ONE en el sistema. Registra el inicio de la verificación de inscripción y recupera los GUIDs de la ruta del registro de inscripción MDM. La función inicializa una variable booleana $mdm en false y itera a través de los GUIDs recuperados. Para cada GUID, construye una ruta de registro y recupera el UPN (Nombre Principal de Usuario), el estado de inscripción y el ID del proveedor. Si el estado de inscripción es "1", el UPN está presente y el ID del proveedor coincide con "AirWatchMDM", establece $mdm en true y almacena el GUID. 

Si se encuentra una inscripción MDM válida ($mdm es true), la función recupera la información del servidor de la ruta del registro de configuración de la consola de AirWatch Beacon. Esta información del servidor se usa más adelante en el script para procesamiento o validación adicional. 

## Heurística 

El script de PowerShell proporcionado está diseñado para gestionar el proceso de inscripción del Workspace ONE Hub, asegurando que se cumplan las condiciones necesarias antes de proceder con la inscripción. El script comienza registrando la versión del script y la ruta del Agente AirWatch. Luego, verifica si el script se está ejecutando con permisos elevados (derechos de administrador). Si no es así, registra un mensaje indicando que se requieren permisos elevados, pausa y sale del script. 

A continuación, el script asegura que el directorio de registros exista verificando la ruta especificada en $Logpath. Si el directorio no existe, lo crea silenciosamente. El script luego verifica la arquitectura del proceso de PowerShell. Si se está ejecutando en un contexto de 32 bits, registra un mensaje y sale, ya que el script requiere un contexto de 64 bits. Si la arquitectura es de 64 bits, registra un mensaje de confirmación. 

El script luego verifica la conexión al servidor UEM de destino probando la conexión de red en el puerto 443. Si la conexión tiene éxito, registra un mensaje de confirmación; de lo contrario, registra un mensaje de fallo y sale del script. El script procede a verificar la existencia de un archivo vars.txt en la ruta especificada. Si no se encuentra el archivo, registra un mensaje de error y sale. Si se encuentra el archivo, registra un mensaje de confirmación y lee el contenido del archivo, creando nuevas variables basadas en los pares clave-valor definidos en el archivo. 

Si el script se está ejecutando en modo silencioso, desactiva las notificaciones. Luego, el script llama a la función Check-agent para verificar el estado del agente, seguido de llamar a la función Get-Enrollment para verificar el estado actual de la inscripción. Procede a desinstalar el Hub existente usando la función Uninstall-Hub y verifica el estado de la inscripción nuevamente. Si no se encuentra la inscripción, llama a la función Enroll-Hub para inscribir el Hub y verifica el estado de la inscripción una vez más. 

Finalmente, si el script se está ejecutando en modo silencioso, vuelve a habilitar las notificaciones, elimina el archivo vars.txt y registra un mensaje indicando que el archivo ha sido eliminado. Esto asegura que no quede información sensible después de que el script complete su ejecución. 

#### Notas 

* El script utiliza Write-Log para registrar mensajes con marcas de tiempo. 

* Start-Sleep se usa para introducir esperas y asegurar que los procesos tengan tiempo para completarse. 

* -ErrorAction SilentlyContinue se usa para suprimir errores y continuar la ejecución. 

* Necesarios permisos elevados, vars.txt y AirwatchAgent.msi en la carpeta de ejecución.

 

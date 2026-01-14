#!/bin/bash

# Pongo a disposición pública este script bajo el término de "software de dominio público".
# Puedes hacer lo que quieras con él porque es libre de verdad; no libre con condiciones como las licencias GNU y otras patrañas similares.
# Si se te llena la boca hablando de libertad entonces hazlo realmente libre.
# No tienes que aceptar ningún tipo de términos de uso o licencia para utilizarlo o modificarlo porque va sin CopyLeft.

# ----------
# Script de NiPeGun para parsear datos extraidos de la RAM de Windows en Debian
#
# Ejecución remota con parámetros:
#   curl -sL https://raw.githubusercontent.com/nipegun/dfir-scripts/refs/heads/main/DFIRWindows/Artefactos-RAM-Extraer-DeDump-Convolatility2.sh | bash -s [RutaAlArchivoConDump] [CarpetaDondeGuardar]
#
# Bajar y editar directamente el archivo en nano
#   curl -sL https://raw.githubusercontent.com/nipegun/dfir-scripts/refs/heads/main/DFIRWindows/Artefactos-RAM-Extraer-DeDump-Convolatility2.sh | nano -
#
# Más info aquí: https://volatility2.readthedocs.io/en/latest/        https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet
# ----------

# Definir constantes de color
  cColorAzul="\033[0;34m"
  cColorAzulClaro="\033[1;34m"
  cColorVerde="\033[1;32m"
  cColorRojo="\033[1;31m"
  # Para el color rojo también:
    #echo "$(tput setaf 1)Mensaje en color rojo. $(tput sgr 0)"
  cFinColor="\033[0m"

# Salir si la cantidad de parámetros pasados no es correcta
  cCantParamEsperados=2
  if [ $# -ne $cCantParamEsperados ]; then
    echo ""
    echo -e "${cColorRojo}  Mal uso del script. El uso correcto sería:${cFinColor}"
    echo ""
    echo "    $0 [RutaAlArchivoConDump] [CarpetaDondeGuardar]"
    echo ""
    echo "      Ejemplo:"
    echo ""
    echo "    $0 $HOME/Descargas/RAM.dump $HOME/Escritorio/ArtefactosRAM"
    echo ""
    exit 1
  fi

# Crear constantes para las carpetas
  cRutaAlArchivoDeDump="$1"
  cCarpetaDondeGuardar="$2"
  mkdir -p "$cCarpetaDondeGuardar"

# Comprobar si existe el repo de volatility2
  if [ ! -d $HOME/HackingTools/Forensics/volatility2/ ]; then
    echo ""
    echo "  El repo de volatility2 existe. Descargándolo..."
    echo ""
    mkdir -p $HOME/HackingTools/Forensics/ 2> /dev/null
    cd $HOME/HackingTools/Forensics/
    # Comprobar si el paquete git está instalado. Si no lo está, instalarlo.
      if [[ $(dpkg-query -s git 2>/dev/null | grep installed) == "" ]]; then
        echo ""
        echo -e "${cColorRojo}  El paquete git no está instalado. Iniciando su instalación...${cFinColor}"
        echo ""
        sudo apt-get -y update
        sudo apt-get -y install git
        echo ""
      fi
    git clone https://github.com/volatilityfoundation/volatility2.git
  fi

# Comprobar si existe el entorno virtual de python de volatility2
  if [ ! -d $HOME/HackingTools/Forensics/volatility2/venv/ ]; then
    echo ""
    echo "  El entorno virtual de python de volatility2 no existe. Creándolo..."
    echo ""
    cd $HOME/HackingTools/Forensics/volatility2/
    python3 -m venv venv
  fi

# Determinar el perfil a usar
  echo ""
  echo "  Intentando determinar el mejor perfil para usar..."
  echo ""
  if [ -n "$3" ]; then
    vPerfilAconsejado="$3"
  else
    source "$HOME/HackingTools/Forensics/volatility2/venv/bin/activate"
      vPerfilAconsejado=$("$HOME/HackingTools/Forensics/volatility2/vol.py" -f "$cRutaAlArchivoDeDump" kdbgscan | grep 'Profile suggestion' | cut -d':' -f2 | sed 's- --g' | sort -r | grep -v 2016 | head -n1)
    deactivate
  fi
vPerfilAconsejado='Win2016x64_14393'
#Win10x64_10586
#Win10x64_14393
#Win10x64_15063
#Win10x64_16299
#Win10x64_17134
#Win10x64_17763
#Win2016x64_14393

# Crear el menú
  # Comprobar si el paquete dialog está instalado. Si no lo está, instalarlo.
    if [[ $(dpkg-query -s dialog 2>/dev/null | grep installed) == "" ]]; then
      echo ""
      echo -e "${cColorRojo}  El paquete dialog no está instalado. Iniciando su instalación...${cFinColor}"
      echo ""
      apt-get -y update
      apt-get -y install dialog
      echo ""
    fi
  menu=(dialog --checklist "Marca los formatos de salida que quieras obtener:" 22 130 16)
    opciones=(
      1 "Simular el sistema de carpetas y archivos de dentro del dump" on
      2 "  Extraer archivos individuales de imagen"                    on
      3 "  Extraer archivos individuales de documentos"                on
      4 "  Extraer archivos individuales de scripts"                   on
      5 "  Extraer archivos individuales de logs y eventos"            on
      6 "Crear la carpeta para archivos tabulados"                     on
      7 "  INFOWINDOWS: w.envars, w.hashdump, w.info"                                                                                           on
      8 "  RED: w.netscan, w.netstat"                                                                                                           on
      9 "  REGISTRO: w.r.certificates w.r.getcellroutine w.r.hivelist w.r.hivescan w.r.printkey w.r.userassist"                                 on
     10 "  TAREAS: w.cmdline, w.cmdscan, w.consoles, w.joblinks, w.scheduled_tasks"                                                             on
     11 "  PROCESOS: w.getsids, w.handles, w.hollowprocesses, w.processghosting, w.pslist, w.psscan, w.pstree, w.psxview, w.strings, w.threads" on
     12 "  LÍNEA DE TIEMPO: w.mbrscan, timeliner"                                                                                               on
     13 "  HARDWARE: w.devicetree, w.ssdt"                                                                                                      on
     14 "  RESTO: ..."                                                                                                                          off
     15 "Parsear datos hacia archivos txt"                             off
     16 "Parsear datos hacia archivos csv"                             off
     17 "Parsear datos hacia archivos json"                            off
     18 "Buscar IPs privadas de clase A"                               off
     19 "Buscar IPs privadas de clase B"                               off
     20 "Buscar IPs privadas de clase C"                               off
     21 "Extraer el sistema de carpetas y archivos de dentro del dump" off
    )
  choices=$("${menu[@]}" "${opciones[@]}" 2>&1 >/dev/tty)
  #clear

  for choice in $choices
    do
      case $choice in

        1)

          echo ""
          echo "  Simular el sistema carpetas y archivos de dentro del dump..."
          echo ""

          # Crear carpetas
            mkdir -p "$cCarpetaDondeGuardar"/tab
            mkdir -p "$cCarpetaDondeGuardar"/Archivos/Simulados

          # Entrar en el entorno virtual de python
            source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate

          # Parsear datos

            # filescan (Scans for file objects present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin filescan..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" --profile="$vPerfilAconsejado" filescan > "$cCarpetaDondeGuardar"/tab/windows.filescan.tab
              #cat "$cCarpetaDondeGuardar"/tab/windows.filescan.tab | grep HarddiskVolume | awk '{print $1, $5}' | sed 's#\\Device\\HarddiskVolume1##g' | awk '$2 ~ /^\\[A-Za-z]/ {print $1, $2}' > /tmp/archivos.tab
              cat "$cCarpetaDondeGuardar"/tab/windows.filescan.tab | grep HarddiskVolume | awk '{print $1, $5}' | sed 's#\\Device\\HarddiskVolume1##g' > /tmp/archivos.tab
              # Reemplazar las barras para adaptarlas al sistema de carpetas de Linux
                sed -i 's|\\|/|g' /tmp/archivos.tab

          # Crear el array asociativo y meter dentro todos los offsets y los archivos
            unset aOffsetsArchivos
            declare -A aOffsetsArchivos
            while read -r vOffset vRuta; do
              aOffsetsArchivos["$vOffset"]="$vRuta"
            done < /tmp/archivos.tab

          # Mostrar el contenido del array
            #for key in "${!aOffsetsArchivos[@]}"; do
            #  echo "$key -> ${aOffsetsArchivos[$key]}"
            #done

          # Recorrer el array e ir creando archivos
            for key in "${!aOffsetsArchivos[@]}"; do
              mkdir -p "$cCarpetaDondeGuardar/Archivos/Simulados/$(dirname "${aOffsetsArchivos[$key]}")" && touch "$cCarpetaDondeGuardar/Archivos/Simulados/${aOffsetsArchivos[$key]}"
            done

          # Corregir algunos errores en carpetas
            # Borrar todas las carpetas y archivos que empiecen por un caracter oriental
              find "$cCarpetaDondeGuardar"/Archivos/Simulados/ -type d -name "$(printf '[\u4E00-\u9FFF]*')" -exec rm -rf {} +
              find "$cCarpetaDondeGuardar"/Archivos/Simulados/ -type f -name "$(printf '[\u4E00-\u9FFF]*')" -exec rm -rf {} +
            # Eliminar de la raíz todas las carpetas y archivos que no empiecen por $
              find "$cCarpetaDondeGuardar"/Archivos/Simulados/ -maxdepth 1 -type f ! -name '\$*' -exec rm -f {} +
            # Copiar el contenido de la carpeta Users de ?? sobre Users
              find "$cCarpetaDondeGuardar"/Archivos/Simulados/?? -type d -name 'Users' -exec cp -r -v {} "$cCarpetaDondeGuardar"/Archivos/Simulados/ \;

        ;;

        2)

          echo ""
          echo "  Extrayendo archivos individuales de imágenes..."
          echo ""
          # Guardar todas las líneas con las imágenes encontradas
            cat /tmp/archivos.tab | grep -a -i --color -E '\.(jpg|jpeg|png|bmp|webp)$' > "$cCarpetaDondeGuardar"/tab/windows.filescan-imagenes.tab
          # Crear el array asociativo y meter dentro todos los offsets y los archivos
            declare -A aOffsetsArchivosImagenes
            while IFS=$'\t' read -r key value; do
              aOffsetsArchivosImagenes["$key"]="$value"
            done < "$cCarpetaDondeGuardar"/tab/windows.filescan-imagenes.tab
          # Crear la carpeta donde guardar las imagenes
            mkdir -p "$cCarpetaDondeGuardar"/Archivos/Individuales/Imagenes/
          # Recorrer el array e ir guardando los offsets
            for key in "${!aOffsetsArchivosImagenes[@]}"; do
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" --profile="$vPerfilAconsejado" dumpfiles --dump-dir "$cCarpetaDondeGuardar"/Archivos/Individuales/Imagenes/ -Q $key 
            done
          # Eliminar archivos con hash duplicado
            declare -A aHashesImagenes
            find "$cCarpetaDondeGuardar"/Archivos/Individuales/Imagenes/ -type f | while read -r vArchivo; do
              # Calcular el hash del archivo (usa sha256sum o md5sum según prefieras)
                vHash=$(sha256sum "$vArchivo" | sed 's/ .*//')
              # Verificar si el hash ya existe en el array
                if [[ -v aHashesImagenes["$vHash"] ]]; then
                  # Si el hash ya existe, eliminar el archivo duplicado
                  echo "Eliminando duplicado: $vArchivo (hash: $vHash)"
                  rm -f "$vArchivo"
                else
                  # Si el hash no existe, guardar el archivo en el array
                  aHashesImagenes["$vHash"]="$vArchivo"
                fi
            done
          # Eliminar la extension .vacb a todos los archivos
            find "$cCarpetaDondeGuardar"/Archivos/Individuales/Imagenes/ -type f -name "*.vacb" | while IFS= read -r vArchivo; do
              # Obtener la nueva ruta sin la extensión .vacb
                vNuevoNombre="${vArchivo%.vacb}"
              # Renombrar el archivo
                mv "$vArchivo" "$vNuevoNombre"
                echo "Renombrado: $vArchivo -> $vNuevoNombre"
            done
          # Eliminar la extension .dat a todos los archivos
            find "$cCarpetaDondeGuardar"/Archivos/Individuales/Imagenes/ -type f -name "*.dat" | while IFS= read -r vArchivo; do
              # Verificar si el nombre del archivo contiene "DataSectionObject"
                if [[ "$vArchivo" == *"DataSectionObject"* ]]; then
                  # Obtener la nueva ruta sin la extensión .dat
                    vNuevoNombre="${vArchivo%.dat}"
                  # Renombrar el archivo
                    mv "$vArchivo" "$vNuevoNombre"
                fi
            done

        ;;

        3)

          echo ""
          echo "  Extrayendo archivos individuales de documentos..."
          echo ""
          # Guardar todas las líneas con las imágenes encontradas
            cat /tmp/archivos.tab | grep -a -i --color -E '\.(doc|docx|odt|xls|xlsx|ods|pdf)$' > "$cCarpetaDondeGuardar"/tab/windows.filescan-documentos.tab
          # Crear el array asociativo y meter dentro todos los offsets y los archivos
            declare -A aOffsetsArchivosDocumentos
            while IFS=$'\t' read -r key value; do
              aOffsetsArchivosDocumentos["$key"]="$value"
            done < "$cCarpetaDondeGuardar"/tab/windows.filescan-documentos.tab
          # Crear la carpeta donde guardar las imagenes
            mkdir -p "$cCarpetaDondeGuardar"/Archivos/Individuales/Documentos/
          # Recorrer el array e ir guardando los offsets
            for key in "${!aOffsetsArchivosDocumentos[@]}"; do
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" --profile="$vPerfilAconsejado" dumpfiles --dump-dir "$cCarpetaDondeGuardar"/Archivos/Individuales/Documentos/ -Q $key 
            done
          # Eliminar archivos con hash duplicado
            declare -A aHashesDocuementos
            find "$cCarpetaDondeGuardar"/Archivos/Individuales/Documentos/ -type f | while read -r vArchivo; do
              # Calcular el hash del archivo (usa sha256sum o md5sum según prefieras)
                vHash=$(sha256sum "$vArchivo" | sed 's/ .*//')
              # Verificar si el hash ya existe en el array
                if [[ -v aHashesDocumentos["$vHash"] ]]; then
                  # Si el hash ya existe, eliminar el archivo duplicado
                  echo "Eliminando duplicado: $vArchivo (hash: $vHash)"
                  rm -f "$vArchivo"
                else
                  # Si el hash no existe, guardar el archivo en el array
                  aHashesDocumentos["$vHash"]="$vArchivo"
                fi
            done
          # Eliminar la extension .vacb a todos los archivos
            find "$cCarpetaDondeGuardar"/Archivos/Individuales/Documentos/ -type f -name "*.vacb" | while IFS= read -r vArchivo; do
              # Obtener la nueva ruta sin la extensión .vacb
                vNuevoNombre="${vArchivo%.vacb}"
              # Renombrar el archivo
                mv "$vArchivo" "$vNuevoNombre"
                echo "Renombrado: $vArchivo -> $vNuevoNombre"
            done
          # Eliminar la extension .dat a todos los archivos
            find "$cCarpetaDondeGuardar"/Archivos/Individuales/Documentos/ -type f -name "*.dat" | while IFS= read -r vArchivo; do
              # Verificar si el nombre del archivo contiene "DataSectionObject"
                if [[ "$vArchivo" == *"DataSectionObject"* ]]; then
                  # Obtener la nueva ruta sin la extensión .dat
                    vNuevoNombre="${vArchivo%.dat}"
                  # Renombrar el archivo
                    mv "$vArchivo" "$vNuevoNombre"
                fi
            done

        ;;

        4)

          echo ""
          echo "  Extrayendo archivos individuales scripts..."
          echo ""
          # Guardar todas las líneas con las imágenes encontradas
            cat /tmp/archivos.tab | grep -a -i --color -E '\.(sh|bat|ps1|py)$' > "$cCarpetaDondeGuardar"/tab/windows.filescan-scripts.tab
          # Crear el array asociativo y meter dentro todos los offsets y los archivos
            declare -A aOffsetsArchivosScripts
            while IFS=$'\t' read -r key value; do
              aOffsetsArchivosScripts["$key"]="$value"
            done < "$cCarpetaDondeGuardar"/tab/windows.filescan-scripts.tab
          # Crear la carpeta donde guardar las imagenes
            mkdir -p "$cCarpetaDondeGuardar"/Archivos/Individuales/Scripts/
          # Recorrer el array e ir guardando los offsets
            for key in "${!aOffsetsArchivosScripts[@]}"; do
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" --profile="$vPerfilAconsejado" dumpfiles --dump-dir "$cCarpetaDondeGuardar"/Archivos/Individuales/Scripts/ -Q $key 
            done
          # Eliminar archivos con hash duplicado
            declare -A aHashesScripts
            find "$cCarpetaDondeGuardar"/Archivos/Individuales/Scripts/ -type f | while read -r vArchivo; do
              # Calcular el hash del archivo (usa sha256sum o md5sum según prefieras)
                vHash=$(sha256sum "$vArchivo" | sed 's/ .*//')
              # Verificar si el hash ya existe en el array
                if [[ -v aHashesScripts["$vHash"] ]]; then
                  # Si el hash ya existe, eliminar el archivo duplicado
                  echo "Eliminando duplicado: $vArchivo (hash: $vHash)"
                  rm -f "$vArchivo"
                else
                  # Si el hash no existe, guardar el archivo en el array
                  aHashesScripts["$vHash"]="$vArchivo"
                fi
            done
          # Eliminar la extension .vacb a todos los archivos
            find "$cCarpetaDondeGuardar"/Archivos/Individuales/Scripts/ -type f -name "*.vacb" | while IFS= read -r vArchivo; do
              # Obtener la nueva ruta sin la extensión .vacb
                vNuevoNombre="${vArchivo%.vacb}"
              # Renombrar el archivo
                mv "$vArchivo" "$vNuevoNombre"
                echo "Renombrado: $vArchivo -> $vNuevoNombre"
            done
          # Eliminar la extension .dat a todos los archivos
            find "$cCarpetaDondeGuardar"/Archivos/Individuales/Scripts/ -type f -name "*.dat" | while IFS= read -r vArchivo; do
              # Verificar si el nombre del archivo contiene "DataSectionObject"
                if [[ "$vArchivo" == *"DataSectionObject"* ]]; then
                  # Obtener la nueva ruta sin la extensión .dat
                    vNuevoNombre="${vArchivo%.dat}"
                  # Renombrar el archivo
                    mv "$vArchivo" "$vNuevoNombre"
                fi
            done

        ;;

        5)

          echo ""
          echo "  Extrayendo archivos individuales de logs y eventos..."
          echo ""
          # Guardar todas las líneas con las imágenes encontradas
            cat /tmp/archivos.tab | grep -a -i --color -E '\.(log|evtx)$' > "$cCarpetaDondeGuardar"/tab/windows.filescan-logsyeventos.tab
          # Crear el array asociativo y meter dentro todos los offsets y los archivos
            declare -A aOffsetsArchivosLogsYEventos
            while IFS=$'\t' read -r key value; do
              aOffsetsArchivosLogsYEventos["$key"]="$value"
            done < "$cCarpetaDondeGuardar"/tab/windows.filescan-logsyeventos.tab
          # Crear la carpeta donde guardar las imagenes
            mkdir -p "$cCarpetaDondeGuardar"/Archivos/Individuales/LogsYEventos/
          # Recorrer el array e ir guardando los offsets
            for key in "${!aOffsetsArchivosLogsYEventos[@]}"; do
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" --profile="$vPerfilAconsejado" dumpfiles --dump-dir "$cCarpetaDondeGuardar"/Archivos/Individuales/LogsYEventos/ -Q $key 
            done
          # Eliminar archivos con hash duplicado
            declare -A aHashesLogsYEventos
            find "$cCarpetaDondeGuardar"/Archivos/Individuales/LogsYEventos/ -type f | while read -r vArchivo; do
              # Calcular el hash del archivo (usa sha256sum o md5sum según prefieras)
                vHash=$(sha256sum "$vArchivo" | sed 's/ .*//')
              # Verificar si el hash ya existe en el array
                if [[ -v aHashesLogsYEventos["$vHash"] ]]; then
                  # Si el hash ya existe, eliminar el archivo duplicado
                  echo "Eliminando duplicado: $vArchivo (hash: $vHash)"
                  rm -f "$vArchivo"
                else
                  # Si el hash no existe, guardar el archivo en el array
                  aHashesLogsYEventos["$vHash"]="$vArchivo"
                fi
            done
          # Eliminar la extension .vacb a todos los archivos
            find "$cCarpetaDondeGuardar"/Archivos/Individuales/LogsYEventos/ -type f -name "*.vacb" | while IFS= read -r vArchivo; do
              # Obtener la nueva ruta sin la extensión .vacb
                vNuevoNombre="${vArchivo%.vacb}"
              # Renombrar el archivo
                mv "$vArchivo" "$vNuevoNombre"
                echo "Renombrado: $vArchivo -> $vNuevoNombre"
            done
          # Eliminar la extension .dat a todos los archivos
            find "$cCarpetaDondeGuardar"/Archivos/Individuales/LogsYEventos/ -type f -name "*.dat" | while IFS= read -r vArchivo; do
              # Verificar si el nombre del archivo contiene "DataSectionObject"
                if [[ "$vArchivo" == *"DataSectionObject"* ]]; then
                  # Obtener la nueva ruta sin la extensión .dat
                    vNuevoNombre="${vArchivo%.dat}"
                  # Renombrar el archivo
                    mv "$vArchivo" "$vNuevoNombre"
                fi
            done

        ;;

        6)

          echo ""
          echo "  Crear la carpeta para archivos tabulados..."
          echo ""

          # Crear carpeta
            mkdir -p "$cCarpetaDondeGuardar"/tab

        ;;

        7)

          echo ""
          echo "  Aplicando w.envars, w.hashdump, w.info..."
          echo ""

          # Entrar en el entorno virtual de python
            source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate

          # Parsear datos

            # windows.envars (Display process environment variables)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              #   --silent        - Suppress common and non-persistent variables
              echo ""
              echo "    Aplicando el plugin windows.envars..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.envars | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.envars.tab

            # windows.hashdump (Dumps user hashes from memory)
              echo ""
              echo "    Aplicando el plugin windows.hashdump..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.hashdump | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.hashdump.tab

            # windows.info (Show OS & kernel details of the memory sample being analyzed)
              echo ""
              echo "    Aplicando el plugin windows.info..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.info | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.info.tab

          # Salir del entorno virtual
            deactivate

        ;;

        8)

          echo ""
          echo "  Aplicando w.netscan, w.netstat..."
          echo ""

          # Entrar en el entorno virtual de python
            source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate

          # Parsear datos

            # windows.netscan (Scans for network objects present in a particular windows memory image)
              # Argumentos:
              #   --include-corrupt - Radically eases result validation. This will show partially overwritten data. WARNING: the results are likely to include garbage and/or corrupt data. Be cautious!
              echo ""
              echo "    Aplicando el plugin windows.netscan..."
              echo ""
              # Sin corruptos
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.netscan                   | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.netscan.tab
              # Con corruptos
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.netscan --include-corrupt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.netscan-corrupt.tab

            # windows.netstat (Traverses network tracking structures present in a particular windows memory image)
              # Argumentos:
              #   --include-corrupt - Radically eases result validation. This will show partially overwritten data. WARNING: the results are likely to include garbage and/or corrupt data. Be cautious!
              echo ""
              echo "    Aplicando el plugin windows.netstat..."
              echo ""
              # Sin corruptos
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.netstat                   | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.netstat.tab
              # Con corruptos
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.netstat --include-corrupt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.netstat-corrupt.tab

          # Salir del entorno virtual
            deactivate

        ;;

        9)

          echo ""
          echo "  Aplicando w.r.certificates, w.r.getcellroutine, w.r.hivelist, w.r.hivescan, w.r.printkey, w.r.userassist..."
          echo ""

          # Entrar en el entorno virtual de python
            source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate

          # Parsear datos

            # windows.registry.certificates (Lists the certificates in the registry's Certificate Store)
              # Argumentos:
              #   --dump - Extract listed certificates
              echo ""
              echo "    Aplicando el plugin windows.registry.certificates..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.registry.certificates | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.registry.certificates.tab

            # windows.registry.getcellroutine (Reports registry hives with a hooked GetCellRoutine handler)
              echo ""
              echo "    Aplicando el plugin windows.registry.getcellroutine..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.registry.getcellroutine | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.registry.getcellroutine.tab

            # windows.registry.hivelist (Lists the registry hives present in a particular memory image)
              # Argumentos:
              #   --filter FILTER - String to filter hive names returned
              #   --dump          - Extract listed registry hives
              echo ""
              echo "    Aplicando el plugin windows.registry.hivelist..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.registry.hivelist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.registry.hivelist.tab

            # windows.registry.hivescan (Scans for registry hives present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.registry.hivescan..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.registry.hivescan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.registry.hivescan.tab

            # windows.registry.printkey (Lists the registry keys under a hive or specific key value)
              # Argumentos:
              #   --offset OFFSET - Hive Offset
              #   --key KEY       - Key to start from
              #   --recurse       - Recurses through keys
              echo ""
              echo "    Aplicando el plugin windows.registry.printkey..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.registry.printkey | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.registry.printkey.tab
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.registry.printkey ‑‑key "Software\Microsoft\Windows\CurrentVersion" | grep -v "Volatility 3"

            # windows.registry.userassist (Print userassist registry keys and information)
              # Argumentos:
              #   --offset OFFSET - Hive Offset
              echo ""
              echo "    Aplicando el plugin windows.registry.userassist..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.registry.userassist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.registry.userassist.tab

          # Salir del entorno virtual
            deactivate

        ;;

        10)

          echo ""
          echo "  Aplicando w.cmdline, w.cmdscan, w.consoles, w.joblinks, w.scheduled_tasks..."
          echo ""

          # Entrar en el entorno virtual de python
            source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate

          # Parsear datos

            # windows.cmdline (Lists process command line arguments)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.cmdline..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.cmdline | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.cmdline.tab

            # windows.cmdscan (Looks for Windows Command History lists)
              # Argumentos:
              #   --no-registry                   - Don't search the registry for possible values of CommandHistorySize
              #   --max-history [MAX_HISTORY ...] - CommandHistorySize values to search for.
              echo ""
              echo "    Aplicando el plugin windows.cmdscan..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.cmdscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.cmdscan.tab

            # windows.consoles (Looks for Windows console buffers)
              # Argumentos:
              #   --no-registry                   - Don't search the registry for possible values of CommandHistorySize and HistoryBufferMax
              #   --max-history [MAX_HISTORY ...] - CommandHistorySize values to search for.
              #   --max-buffers [MAX_BUFFERS ...] - HistoryBufferMax values to search for.
              echo ""
              echo "    Aplicando el plugin windows.consoles..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.consoles | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.consoles.tab

            # windows.joblinks (Print process job link information)
             # Argumentos:
              #   --physical - Display physical offset instead of virtual
              echo ""
              echo "    Aplicando el plugin windows.joblinks..."
              echo ""
              # Offset virtual
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.joblinks            | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.joblinks-offsetvirtual.tab
              # Offset físico
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.joblinks --physical | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.joblinks-offsetfisico.tab

            # windows.scheduled_tasks (Decodes scheduled task information from the Windows registry, including information about triggers, actions, run times, and creation times)
              echo ""
              echo "    Aplicando el plugin windows.scheduled_tasks..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.scheduled_tasks | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.scheduled_tasks.tab

          # Salir del entorno virtual
            deactivate

        ;;

        11)

          echo ""
          echo "  Aplicando w.getsids, w.handles, w.hollowprocesses, w.processghosting, w.pslist, w.psscan, w.pstree, w.psxview, w.strings, w.threads..."
          echo ""

          # Entrar en el entorno virtual de python
            source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate

          # Parsear datos

            # windows.getsids (Print the SIDs owning each process)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.getsids..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.getsids | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.getsids.tab

            # windows.handles (Lists process open handles)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              #   --offset OFFSET - Process offset in the physical address space
              echo ""
              echo "    Aplicando el plugin windows.handles..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.handles | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.handles.tab
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.handles ‑‑pid "<PID>"

            # windows.hollowprocesses (Lists hollowed processes)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.hollowprocesses..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.hollowprocesses | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.hollowprocesses.tab

            # windows.processghosting (Lists processes whose DeletePending bit is set or whose FILE_OBJECT is set to 0)
              echo ""
              echo "    Aplicando el plugin windows.processghosting..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.processghosting | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.processghosting.tab

            # windows.pslist (Lists the processes present in a particular windows memory image)
              # Argumentos:
              #   --physical      - Display physical offsets instead of virtual
              #   --pid [PID ...] - Process ID to include (all other processes are excluded)
              #   --dump          - Extract listed processes
              echo ""
              echo "    Aplicando el plugin windows.pslist..."
              echo ""
              # Offset virtual
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.pslist            | grep -v "Volatility 3" | sort -n > "$cCarpetaDondeGuardar"/tab/windows.pslist-offsetvirtual-pid-ppid.tab
                sed -i '/^$/d' "$cCarpetaDondeGuardar"/tab/windows.pslist-offsetvirtual-pid-ppid.tab
                cut -f2 "$cCarpetaDondeGuardar"/tab/windows.pslist-offsetvirtual-pid-ppid.tab > /tmp/vArchivoTemporalConColumna2.txt
                cut --complement -f2 "$cCarpetaDondeGuardar"/tab/windows.pslist-offsetvirtual-pid-ppid.tab > /tmp/vArchivoTemporalConRestoDeColumnas.txt
                paste /tmp/vArchivoTemporalConColumna2.txt /tmp/vArchivoTemporalConRestoDeColumnas.txt > /tmp/vArchivoTemporal.txt
                cat /tmp/vArchivoTemporal.txt | sort -n > "$cCarpetaDondeGuardar"/tab/windows.pslist-offsetvirtual-ppid-pid.tab
                sed -i '/^$/d' "$cCarpetaDondeGuardar"/tab/windows.pslist-offsetvirtual-ppid-pid.tab
              # Offset físico
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.pslist --physical | grep -v "Volatility 3" | sort -n > "$cCarpetaDondeGuardar"/tab/windows.pslist-offsetfisico-pid-ppid.tab
                sed -i '/^$/d' "$cCarpetaDondeGuardar"/tab/windows.pslist-offsetfisico-pid-ppid.tab
                cut -f2 "$cCarpetaDondeGuardar"/tab/windows.pslist-offsetfisico-pid-ppid.tab > /tmp/vArchivoTemporalConColumna2.txt
                cut --complement -f2 "$cCarpetaDondeGuardar"/tab/windows.pslist-offsetfisico-pid-ppid.tab > /tmp/vArchivoTemporalConRestoDeColumnas.txt
                paste /tmp/vArchivoTemporalConColumna2.txt /tmp/vArchivoTemporalConRestoDeColumnas.txt > /tmp/vArchivoTemporal.txt
                cat /tmp/vArchivoTemporal.txt | sort -n > "$cCarpetaDondeGuardar"/tab/windows.pslist-offsetfisico-ppid-pid.tab
                sed -i '/^$/d' "$cCarpetaDondeGuardar"/tab/windows.pslist-offsetfisico-ppid-pid.tab

            # windows.psscan (Scans for processes present in a particular windows memory image)
              # Argumentos:
              #   --physical      - Display physical offsets instead of virtual
              #   --pid [PID ...] - Process ID to include (all other processes are excluded)
              #   --dump          - Extract listed processes
              echo ""
              echo "    Aplicando el plugin windows.psscan..."
              echo ""
              # Offset virtual
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.psscan            | grep -v "Volatility 3" | sort -n > "$cCarpetaDondeGuardar"/tab/windows.psscan-offsetvirtual-pid-ppid.tab
                sed -i '/^$/d' "$cCarpetaDondeGuardar"/tab/windows.psscan-offsetvirtual-pid-ppid.tab
                cut -f2 "$cCarpetaDondeGuardar"/tab/windows.psscan-offsetvirtual-pid-ppid.tab > /tmp/vArchivoTemporalConColumna2.txt
                cut --complement -f2 "$cCarpetaDondeGuardar"/tab/windows.psscan-offsetvirtual-pid-ppid.tab > /tmp/vArchivoTemporalConRestoDeColumnas.txt
                paste /tmp/vArchivoTemporalConColumna2.txt /tmp/vArchivoTemporalConRestoDeColumnas.txt > /tmp/vArchivoTemporal.txt
                cat /tmp/vArchivoTemporal.txt | sort -n > "$cCarpetaDondeGuardar"/tab/windows.psscan-offsetvirtual-ppid-pid.tab
                sed -i '/^$/d' "$cCarpetaDondeGuardar"/tab/windows.psscan-offsetvirtual-ppid-pid.tab
              # Offset físico
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.psscan --physical | grep -v "Volatility 3" | sort -n > "$cCarpetaDondeGuardar"/tab/windows.psscan-offsetfisico-pid-ppid.tab
                sed -i '/^$/d' "$cCarpetaDondeGuardar"/tab/windows.psscan-offsetfisico-pid-ppid.tab
                cut -f2 "$cCarpetaDondeGuardar"/tab/windows.psscan-offsetfisico-pid-ppid.tab > /tmp/vArchivoTemporalConColumna2.txt
                cut --complement -f2 "$cCarpetaDondeGuardar"/tab/windows.psscan-offsetfisico-pid-ppid.tab > /tmp/vArchivoTemporalConRestoDeColumnas.txt
                paste /tmp/vArchivoTemporalConColumna2.txt /tmp/vArchivoTemporalConRestoDeColumnas.txt > /tmp/vArchivoTemporal.txt
                cat /tmp/vArchivoTemporal.txt | sort -n > "$cCarpetaDondeGuardar"/tab/windows.psscan-offsetfisico-ppid-pid.tab
                sed -i '/^$/d' "$cCarpetaDondeGuardar"/tab/windows.psscan-offsetfisico-ppid-pid.tab

            # windows.pstree (Plugin for listing processes in a tree based on their parent process ID)
              # Argumentos:
              #   --physical      - Display physical offsets instead of virtual
              #   --pid [PID ...] - Process ID to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.pstree..."
              echo ""
              # Offset virtual
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.pstree            | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.pstree-offsetvirtual.tab
              # Offset físico
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.pstree --physical | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.pstree-offsetfisico.tab

            # windows.psxview (Lists all processes found via four of the methods described in "The Art of Memory Forensics," which may help identify processes that are trying to hide themselves. I recommend using -r pretty if you are looking at this plugin's output in a terminal)
              # Argumentos:
              # --physical-offsets - List processes with physical offsets instead of virtual offsets.
              echo ""
              echo "    Aplicando el plugin windows.psxview..."
              echo ""
              # Offsets virtuales
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.psxview                    | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.psxview-offsetsvirtuales.tab
              # Offsets físicos
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.psxview --physical-offsets | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.psxview-offsetsfisicos.tab

            # windows.strings (Reads output from the strings command and indicates which process(es) each string belongs to)
              # Argumentos:
              #   --pid [PID ...]             - Process ID to include (all other processes are excluded)
              #   --strings-file STRINGS_FILE - Strings file
              echo ""
              echo "    Aplicando el plugin windows.strings..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.strings | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.strings.tab

            # windows.threads (Lists process threads)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.threads..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.threads | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.threads.tab

          # Salir del entorno virtual
            deactivate

        ;;

        12)

          echo ""
          echo "  Aplicando w.mbrscan, timeliner..."
          echo ""

          # Entrar en el entorno virtual de python
            source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate

          # Parsear datos

            # windows.mbrscan (Scans for and parses potential Master Boot Records (MBRs))
              # Argumentos:
              #   --full - It analyzes and provides all the information in the partition entry and bootcode hexdump. (It returns a lot of information, so we recommend you render it in CSV.)
              echo ""
              echo "    Aplicando el plugin windows.mbrscan..."
              echo ""
              # Simple
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.mbrscan        | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.mbrscan.tab
              # Completo
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.mbrscan --full | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.mbrscan-full.tab

            # No windows

              # timeliner (Runs all relevant plugins that provide time related information and orders the results by time)
                # Argumentos:
                #   --record-config                     - Whether to record the state of all the plugins once complete
                #   --plugin-filter [PLUGIN-FILTER ...] - Only run plugins featuring this substring
                #   --create-bodyfile                   - Whether to create a body file whilst producing results
                echo ""
                echo "    Aplicando el plugin timeliner..."
                echo ""
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" timeliner | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/timeliner.tab

          # Salir del entorno virtual
            deactivate

        ;;

        13)

          echo ""
          echo "  Aplicando w.devicetree, w.ssdt..."
          echo ""

          # Entrar en el entorno virtual de python
            source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate

          # Parsear datos

            # windows.devicetree (Listing tree based on drivers and attached devices in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.devicetree..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.devicetree | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.devicetree.tab

            # windows.ssdt (Lists the system call table)
              echo ""
              echo "    Aplicando el plugin windows.ssdt..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.ssdt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.ssdt.tab

          # Salir del entorno virtual
            deactivate

        ;;

        14)

          echo ""
          echo "  Aplicando resto de plugins..."
          echo ""

          # Entrar en el entorno virtual de python
            source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate

          # Parsear datos

            # windows.amcache (Extract information on executed applications from the AmCache)
              echo ""
              echo "    Aplicando el plugin windows.amcache..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.amcache | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.amcache.tab

            # windows.bigpools (List big page pools)
              # Argumentos:
              #   --tags TAGS - Comma separated list of pool tags to filter pools returned
              #   --show-free - Show freed regions (otherwise only show allocations in use)
              echo ""
              echo "    Aplicando el plugin windows.bigpools..."
              echo ""
              # En uso
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.bigpools             | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.bigpools-enuso.tab
              # En uso y libres
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.bigpools --show-free | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.bigpools-enusoylibres.tab

            # windows.callbacks (Lists kernel callbacks and notification routines)
              echo ""
              echo "    Aplicando el plugin windows.callbacks..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.callbacks | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.callbacks.tab

            # windows.crashinfo (Lists the information from a Windows crash dump)
              echo ""
              echo "    Aplicando el plugin windows.crashinfo..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.crashinfo | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.crashinfo.tab

            # windows.debugregisters ()
              echo ""
              echo "    Aplicando el plugin windows.debugregisters..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.debugregisters | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.debugregisters.tab

            # windows.dlllist (Lists the loaded modules in a particular windows memory image)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              #   --offset OFFSET - Process offset in the physical address space
              #   --name NAME     - Specify a regular expression to match dll name(s)
              #   --base BASE     - Specify a base virtual address in process memory
              #   --ignore-case   - Specify case insensitivity for the regular expression name matching
              #   --dump          - Extract listed DLLs
              echo ""
              echo "    Aplicando el plugin windows.dlllist..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.dlllist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.dlllist.tab
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.dlllist ‑‑pid "<PID>"

            # windows.driverirp (List IRPs for drivers in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.driverirp..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.driverirp | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.driverirp.tab

            # windows.drivermodule (Determines if any loaded drivers were hidden by a rootkit)
              echo ""
              echo "    Aplicando el plugin windows.drivermodule..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.drivermodule | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.drivermodule.tab

            # windows.driverscan (Scans for drivers present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.driverscan..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.driverscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.driverscan.tab

            # windows.getservicesids (Lists process token sids)
              echo ""
              echo "    Aplicando el plugin windows.getservicesids..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.getservicesids | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.getservicesids.tab

            # windows.iat (Extract Import Address Table to list API (functions) used by a program contained in external libraries)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.iat..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.iat | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.iat.tab

            # windows.kpcrs (Print KPCR structure for each processor)
              echo ""
              echo "    Aplicando el plugin windows.kpcrs..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.kpcrs | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.kpcrs.tab

            # windows.ldrmodules (Lists the loaded modules in a particular windows memory image)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.ldrmodules..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.ldrmodules | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.ldrmodules.tab

            # windows.malfind (Lists process memory ranges that potentially contain injected code)
              echo ""
              echo "    Aplicando el plugin windows.malfind..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.malfind | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.malfind.tab

            # windows.memmap (Prints the memory map)
              # Argumentos:
              #   --pid PID - Process ID to include (all other processes are excluded)
              #   --dump    - Extract listed memory segments
              echo ""
              echo "    Aplicando el plugin windows.memmap..."
              echo ""
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.memmap | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.memmap.tab
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" -o "/path/to/dir" windows.memmap ‑‑dump ‑‑pid "<PID>"

            # windows.modscan (Scans for modules present in a particular windows memory image)
              # Argumentos:
              #   --dump      - Extract listed modules
              #   --base BASE - Extract a single module with BASE address
              #   --name NAME - module name/sub string
              echo ""
              echo "    Aplicando el plugin windows.modscan..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.modscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.modscan.tab

            # windows.modules (Lists the loaded kernel modules)
              # Argumentos:
              #   --dump      - Extract listed modules
              #   --base BASE - Extract a single module with BASE address
              #   --name NAME - module name/sub string
              echo ""
              echo "    Aplicando el plugin windows.modules..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.modules | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.modules.tab

            # windows.mutantscan (Scans for mutexes present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.mutantscan..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.mutantscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.mutantscan.tab

            # windows.orphan_kernel_threads (Lists process threads)
              echo ""
              echo "    Aplicando el plugin windows.orphan_kernel_threads..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.orphan_kernel_threads | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.orphan_kernel_threads.tab

            # windows.pe_symbols (Prints symbols in PE files in process and kernel memory)
              # Argumentos:
              #   --source {kernel,processes} - Where to resolve symbols.
              #   --module MODULE             - Module in which to resolve symbols. Use "ntoskrnl.exe" to resolve in the base kernel executable.
              #   --symbols [SYMBOLS ...]     - Symbol name to resolve
              #   --addresses [ADDRESSES ...] - Address of symbol to resolve
              echo ""
              echo "    Aplicando el plugin windows.pe_symbols..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.pe_symbols | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.pe_symbols.tab

            # windows.pedump (Allows extracting PE Files from a specific address in a specific address space)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              #   --base BASE     - Base address to reconstruct a PE file
              #   --kernel-module - Extract from kernel address space.
              echo ""
              echo "    Aplicando el plugin windows.pedump..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.pedump | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.pedump.tab

            # windows.poolscanner (A generic pool scanner plugin)
              echo ""
              echo "    Aplicando el plugin windows.poolscanner..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.poolscanner | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.poolscanner.tab

            # windows.privileges (Lists process token privileges)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.privileges..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.privileges | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.privileges.tab

            # windows.sessions (lists Processes with Session information extracted from Environmental Variables)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.sessions..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.sessions | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.sessions.tab

            # windows.shimcachemem (Reads Shimcache entries from the ahcache.sys AVL tree)
              echo ""
              echo "    Aplicando el plugin windows.shimcachemem..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.shimcachemem | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.shimcachemem.tab

            # windows.skeleton_key_check (Looks for signs of Skeleton Key malware)
              echo ""
              echo "    Aplicando el plugin windows.skeleton_key_check..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.skeleton_key_check | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.skeleton_key_check.tab

            # windows.statistics (Lists statistics about the memory space)
              echo ""
              echo "    Aplicando el plugin windows.statistics..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.statistics | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.statistics.tab

            # windows.suspicious_threads (Lists suspicious userland process threads)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.suspicious_threads..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.suspicious_threads | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.suspicious_threads.tab

            # windows.svcdiff (Compares services found through list walking versus scanning to find rootkits)
              echo ""
              echo "    Aplicando el plugin windows.svcdiff..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.svcdiff | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.svcdiff.tab

            # windows.svclist (Lists services contained with the services.exe doubly linked list of services)
              echo ""
              echo "    Aplicando el plugin windows.svclist..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.svclist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.svclist.tab

            # windows.svcscan (Scans for windows services)
              echo ""
              echo "    Aplicando el plugin windows.svcscan..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.svcscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.svcscan.tab

            # windows.symlinkscan (Scans for links present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.symlinkscan..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.symlinkscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.symlinkscan.tab

            # windows.thrdscan (Scans for windows threads)
              echo ""
              echo "    Aplicando el plugin windows.thrdscan..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.thrdscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.thrdscan.tab

            # windows.timers (Print kernel timers and associated module DPCs)
              echo ""
              echo "    Aplicando el plugin windows.timers..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.timers | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.timers.tab

            # windows.truecrypt (TrueCrypt Cached Passphrase Finder)
              # Argumentos:
              #   --min-length MIN-LENGTH - Minimum length of passphrases to identify
              echo ""
              echo "    Aplicando el plugin windows.truecrypt..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.truecrypt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.truecrypt.tab

            # windows.unhooked_system_calls (Looks for signs of Skeleton Key malware)
              echo ""
              echo "    Aplicando el plugin windows.unhooked_system_calls..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.unhooked_system_calls | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.unhooked_system_calls.tab

            # windows.unloadedmodules (Lists the unloaded kernel modules)
              echo ""
              echo "    Aplicando el plugin windows.unloadedmodules..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.unloadedmodules | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.unloadedmodules.tab

            # windows.vadinfo (Lists process memory ranges)
              # Argumentos:
              #   --address ADDRESS - Process virtual memory address to include (all other address ranges are excluded).
              #   --pid [PID ...]   - Filter on specific process IDs
              #   --dump            - Extract listed memory ranges
              #   --maxsize MAXSIZE - Maximum size for dumped VAD sections (all the bigger sections will be ignored)
              echo ""
              echo "    Aplicando el plugin windows.vadinfo..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.vadinfo | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.vadinfo.tab

            # windows.vadregexscan (Scans all virtual memory areas for tasks using RegEx)
              # Argumentos:
              #   --pid [PID ...]   - Filter on specific process IDs
              #   --pattern PATTERN - RegEx pattern
              #   --maxsize MAXSIZE - Maximum size in bytes for displayed context
              echo ""
              echo "    Aplicando el plugin windows.vadregexscan..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.vadregexscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.vadregexscan.tab

            # windows.vadwalk (Walk the VAD tree)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.vadwalk..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.vadwalk | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.vadwalk.tab

            # windows.verinfo (Lists version information from PE files)
              # Argumenots:
              #   --extensive - Search physical layer for version information
              echo ""
              echo "    Aplicando el plugin windows.verinfo..."
              echo ""
              # Normal
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.verinfo             | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.verinfo-normal.tab
              # Extensivo
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.verinfo --extensive | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.verinfo-extensivo.tab

            # windows.virtmap (Lists virtual mapped sections)
              echo ""
              echo "    Aplicando el plugin windows.virtmap..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.virtmap | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.virtmap.tab

            # windows.vadyarascan (Scans all the Virtual Address Descriptor memory maps using yara)
              # Argumentos:
              #   --insensitive                           - Makes the search case insensitive
              #   --wide                                  - Match wide (unicode) strings
              #   --yara-string YARA_STRING               - Yara rules (as a string)
              #   --yara-file YARA_FILE                   - Yara rules (as a file)
              #   --yara-compiled-file YARA_COMPILED_FILE - Yara compiled rules (as a file)
              #   --max-size MAX_SIZE                     - Set the maximum size (default is 1GB)
              #   --pid [PID ...]                         - Process IDs to include (all other processes are excluded)
              #
              # Notas: Este módulo nos permite buscar cadenas dentro de un proceso, de esta forma:
              # $HOME/HackingTools/Forensics/volatility2/vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
              echo ""
              echo "    Aplicando el plugin windows.vadyarascan..."
              echo ""
              $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.vadyarascan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.vadyarascan.tab

            # No windows

              # isinfo (Determines information about the currently available ISF files, or a specific one)
                # Argumentos:
                #   --filter [FILTER ...] - String that must be present in the file URI to display the ISF
                #   --isf ISF             - Specific ISF file to process
                #   --validate            - Validate against schema if possible
                #   --live                - Traverse all files, rather than use the cache
                echo ""
                echo "    Aplicando el plugin isinfo..."
                echo ""
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" isfinfo | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/isfinfo.tab

              # layerwriter (Runs the automagics and writes out the primary layer produced by the stacker)
                # Argumentos:
                #   --block-size BLOCK_SIZE - Size of blocks to copy over
                #   --list                  - List available layers
                #   --layers [LAYERS ...]   - Names of layers to write (defaults to the highest non-mapped layer)
                echo ""
                echo "    Aplicando el plugin layerwriter..."
                echo ""
                mkdir -p "$cCarpetaDondeGuardar"/tab/MemoryLayer/
                cd "$cCarpetaDondeGuardar"/tab/MemoryLayer/
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" layerwriter
                cd $HOME/HackingTools/Forensics/volatility2

              # regexscan.RegExScan (Scans kernel memory using RegEx patterns)
                # Argumentos:
                #   --pattern PATTERN - RegEx pattern
                #   --maxsize MAXSIZE - Maximum size in bytes for displayed context
                echo ""
                echo "    Aplicando el plugin regexscan.RegExScan..."
                echo ""
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" regexscan.RegExScan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/regexscan.RegExScan.tab

          # Salir del entorno virtual
            deactivate

        ;;

       15)

          echo ""
          echo "  Parseando hacia archivos txt..."
          echo ""

          # Entrar en el entorno virtual de python
            source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate

          # Parsear datos

            # Crear carpeta
              mkdir -p "$cCarpetaDondeGuardar"/txt

            # windows.amcache (Extract information on executed applications from the AmCache)
              echo ""
              echo "    Aplicando el plugin windows.amcache..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.amcache | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.amcache.txt

            # windows.bigpools (List big page pools)
              # Argumentos:
              #   --tags TAGS - Comma separated list of pool tags to filter pools returned
              #   --show-free - Show freed regions (otherwise only show allocations in use)
              echo ""
              echo "    Aplicando el plugin windows.bigpools..."
              echo ""
              # En uso
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.bigpools             | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.bigpools-enuso.txt
              # En uso y libres
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.bigpools --show-free | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.bigpools-enusoylibres.txt

            # windows.callbacks (Lists kernel callbacks and notification routines)
              echo ""
              echo "    Aplicando el plugin windows.callbacks..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.callbacks | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.callbacks.txt

            # windows.cmdline (Lists process command line arguments)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.cmdline..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.cmdline | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.cmdline.txt

            # windows.cmdscan (Looks for Windows Command History lists)
              # Argumentos:
              #   --no-registry                   - Don't search the registry for possible values of CommandHistorySize
              #   --max-history [MAX_HISTORY ...] - CommandHistorySize values to search for.
              echo ""
              echo "    Aplicando el plugin windows.cmdscan..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.cmdscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.cmdscan.txt

            # windows.consoles (Looks for Windows console buffers)
              # Argumentos:
              #   --no-registry                   - Don't search the registry for possible values of CommandHistorySize and HistoryBufferMax
              #   --max-history [MAX_HISTORY ...] - CommandHistorySize values to search for.
              #   --max-buffers [MAX_BUFFERS ...] - HistoryBufferMax values to search for.
              echo ""
              echo "    Aplicando el plugin windows.consoles..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.consoles | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.consoles.txt

            # windows.crashinfo (Lists the information from a Windows crash dump)
              echo ""
              echo "    Aplicando el plugin windows.crashinfo..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.crashinfo | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.crashinfo.txt

            # windows.debugregisters ()
              echo ""
              echo "    Aplicando el plugin windows.debugregisters..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.debugregisters | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.debugregisters.txt

            # windows.devicetree (Listing tree based on drivers and attached devices in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.devicetree..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.devicetree | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.devicetree.txt

            # windows.dlllist (Lists the loaded modules in a particular windows memory image)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              #   --offset OFFSET - Process offset in the physical address space
              #   --name NAME     - Specify a regular expression to match dll name(s)
              #   --base BASE     - Specify a base virtual address in process memory
              #   --ignore-case   - Specify case insensitivity for the regular expression name matching
              #   --dump          - Extract listed DLLs
              echo ""
              echo "    Aplicando el plugin windows.dlllist..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.dlllist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.dlllist.txt
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.dlllist ‑‑pid "<PID>"

            # windows.driverirp (List IRPs for drivers in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.driverirp..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.driverirp | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.driverirp.txt

            # windows.drivermodule (Determines if any loaded drivers were hidden by a rootkit)
              echo ""
              echo "    Aplicando el plugin windows.drivermodule..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.drivermodule | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.drivermodule.txt

            # windows.driverscan (Scans for drivers present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.driverscan..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.driverscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.driverscan.txt

            # windows.envars (Display process environment variables)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              #   --silent        - Suppress common and non-persistent variables
              echo ""
              echo "    Aplicando el plugin windows.envars..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.envars | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.envars.txt

            # windows.filescan (Scans for file objects present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.filescan..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.filescan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.filescan.txt

            # windows.getservicesids (Lists process token sids)
              echo ""
              echo "    Aplicando el plugin windows.getservicesids..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.getservicesids | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.getservicesids.txt

            # windows.getsids (Print the SIDs owning each process)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.getsids..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.getsids | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.getsids.txt

            # windows.handles (Lists process open handles)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              #   --offset OFFSET - Process offset in the physical address space
              echo ""
              echo "    Aplicando el plugin windows.handles..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.handles | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.handles.txt
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.handles ‑‑pid "<PID>"

            # windows.hashdump (Dumps user hashes from memory)
              echo ""
              echo "    Aplicando el plugin windows.hashdump..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.hashdump | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.hashdump.txt

            # windows.hollowprocesses (Lists hollowed processes)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.hollowprocesses..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.hollowprocesses | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.hollowprocesses.txt

            # windows.iat (Extract Import Address Table to list API (functions) used by a program contained in external libraries)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.iat..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.iat | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.iat.txt

            # windows.info (Show OS & kernel details of the memory sample being analyzed)
              echo ""
              echo "    Aplicando el plugin windows.info..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.info | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.info.txt

            # windows.joblinks (Print process job link information)
             # Argumentos:
              #   --physical - Display physical offset instead of virtual
              echo ""
              echo "    Aplicando el plugin windows.joblinks..."
              echo ""
              # Offset virtual
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.joblinks            | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.joblinks-offsetvirtual.txt
              # Offset físico
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.joblinks --physical | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.joblinks-offsetfisico.txt


            # windows.kpcrs (Print KPCR structure for each processor)
              echo ""
              echo "    Aplicando el plugin windows.kpcrs..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.kpcrs | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.kpcrs.txt

            # windows.ldrmodules (Lists the loaded modules in a particular windows memory image)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.ldrmodules..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.ldrmodules | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.ldrmodules.txt

            # windows.malfind (Lists process memory ranges that potentially contain injected code)
              echo ""
              echo "    Aplicando el plugin windows.malfind..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.malfind | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.malfind.txt

            # windows.mbrscan (Scans for and parses potential Master Boot Records (MBRs))
              # Argumentos:
              #   --full - It analyzes and provides all the information in the partition entry and bootcode hexdump. (It returns a lot of information, so we recommend you render it in CSV.)
              echo ""
              echo "    Aplicando el plugin windows.mbrscan..."
              echo ""
              # Simple
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.mbrscan        | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.mbrscan.txt
              # Completo
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.mbrscan --full | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.mbrscan-full.txt

            # windows.memmap (Prints the memory map)
              # Argumentos:
              #   --pid PID - Process ID to include (all other processes are excluded)
              #   --dump    - Extract listed memory segments
              echo ""
              echo "    Aplicando el plugin windows.memmap..."
              echo ""
              #vol -r pretty -f "$cRutaAlArchivoDeDump" windows.memmap | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.memmap.txt
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" -o "/path/to/dir" windows.memmap ‑‑dump ‑‑pid "<PID>"

            # windows.modscan (Scans for modules present in a particular windows memory image)
              # Argumentos:
              #   --dump      - Extract listed modules
              #   --base BASE - Extract a single module with BASE address
              #   --name NAME - module name/sub string
              echo ""
              echo "    Aplicando el plugin windows.modscan..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.modscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.modscan.txt

            # windows.modules (Lists the loaded kernel modules)
              # Argumentos:
              #   --dump      - Extract listed modules
              #   --base BASE - Extract a single module with BASE address
              #   --name NAME - module name/sub string
              echo ""
              echo "    Aplicando el plugin windows.modules..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.modules | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.modules.txt

            # windows.mutantscan (Scans for mutexes present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.mutantscan..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.mutantscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.mutantscan.txt

            # windows.netscan (Scans for network objects present in a particular windows memory image)
              # Argumentos:
              #   --include-corrupt - Radically eases result validation. This will show partially overwritten data. WARNING: the results are likely to include garbage and/or corrupt data. Be cautious!
              echo ""
              echo "    Aplicando el plugin windows.netscan..."
              echo ""
              # Sin corruptos
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.netscan                   | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.netscan.txt
              # Con corruptos
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.netscan --include-corrupt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.netscan-corrupt.txt

            # windows.netstat (Traverses network tracking structures present in a particular windows memory image)
              # Argumentos:
              #   --include-corrupt - Radically eases result validation. This will show partially overwritten data. WARNING: the results are likely to include garbage and/or corrupt data. Be cautious!
              echo ""
              echo "    Aplicando el plugin windows.netstat..."
              echo ""
              # Sin corruptos
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.netstat                   | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.netstat.txt
              # Con corruptos
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.netstat --include-corrupt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.netstat-corrupt.txt

            # windows.orphan_kernel_threads (Lists process threads)
              echo ""
              echo "    Aplicando el plugin windows.orphan_kernel_threads..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.orphan_kernel_threads | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.orphan_kernel_threads.txt

            # windows.pe_symbols (Prints symbols in PE files in process and kernel memory)
              # Argumentos:
              #   --source {kernel,processes} - Where to resolve symbols.
              #   --module MODULE             - Module in which to resolve symbols. Use "ntoskrnl.exe" to resolve in the base kernel executable.
              #   --symbols [SYMBOLS ...]     - Symbol name to resolve
              #   --addresses [ADDRESSES ...] - Address of symbol to resolve
              echo ""
              echo "    Aplicando el plugin windows.pe_symbols..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.pe_symbols | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.pe_symbols.txt

            # windows.pedump (Allows extracting PE Files from a specific address in a specific address space)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              #   --base BASE     - Base address to reconstruct a PE file
              #   --kernel-module - Extract from kernel address space.
              echo ""
              echo "    Aplicando el plugin windows.pedump..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.pedump | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.pedump.txt

            # windows.poolscanner (A generic pool scanner plugin)
              echo ""
              echo "    Aplicando el plugin windows.poolscanner..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.poolscanner | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.poolscanner.txt

            # windows.privileges (Lists process token privileges)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.privileges..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.privileges | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.privileges.txt

            # windows.processghosting (Lists processes whose DeletePending bit is set or whose FILE_OBJECT is set to 0)
              echo ""
              echo "    Aplicando el plugin windows.processghosting..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.processghosting | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.processghosting.txt

            # windows.pslist (Lists the processes present in a particular windows memory image)
              # Argumentos:
              #   --physical      - Display physical offsets instead of virtual
              #   --pid [PID ...] - Process ID to include (all other processes are excluded)
              #   --dump          - Extract listed processes
              echo ""
              echo "    Aplicando el plugin windows.pslist..."
              echo ""
              # Offset virtual
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.pslist            | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.pslist-offsetvirtual.txt
              # Offset físico
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.pslist --physical | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.pslist-offsetfisico.txt

            # windows.psscan (Scans for processes present in a particular windows memory image)
              # Argumentos:
              #   --physical      - Display physical offsets instead of virtual
              #   --pid [PID ...] - Process ID to include (all other processes are excluded)
              #   --dump          - Extract listed processes
              echo ""
              echo "    Aplicando el plugin windows.psscan..."
              echo ""
              # Offset virtual
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.psscan            | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.psscan-offsetvirtual.txt
              # Offset físico
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.psscan --physical | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.psscan-offsetfisico.txt

            # windows.pstree (Plugin for listing processes in a tree based on their parent process ID)
              # Argumentos:
              #   --physical      - Display physical offsets instead of virtual
              #   --pid [PID ...] - Process ID to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.pstree..."
              echo ""
              # Offset virtual
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.pstree            | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.pstree-offsetvirtual.txt
              # Offset físico
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.pstree --physical | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.pstree-offsetfisico.txt

            # windows.psxview (Lists all processes found via four of the methods described in "The Art of Memory Forensics," which may help identify processes that are trying to hide themselves. I recommend using -r pretty if you are looking at this plugin's output in a terminal)
              # Argumentos:
              # --physical-offsets - List processes with physical offsets instead of virtual offsets.
              echo ""
              echo "    Aplicando el plugin windows.psxview..."
              echo ""
              # Offsets virtuales
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.psxview                    | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.psxview-offsetsvirtuales.txt
              # Offsets físicos
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.psxview --physical-offsets | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.psxview-offsetsfisicos.txt

            # windows.registry.certificates (Lists the certificates in the registry's Certificate Store)
              # Argumentos:
              #   --dump - Extract listed certificates
              echo ""
              echo "    Aplicando el plugin windows.registry.certificates..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.registry.certificates | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.registry.certificates.txt

            # windows.registry.getcellroutine (Reports registry hives with a hooked GetCellRoutine handler)
              echo ""
              echo "    Aplicando el plugin windows.registry.getcellroutine..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.registry.getcellroutine | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.registry.getcellroutine.txt

            # windows.registry.hivelist (Lists the registry hives present in a particular memory image)
              # Argumentos:
              #   --filter FILTER - String to filter hive names returned
              #   --dump          - Extract listed registry hives
              echo ""
              echo "    Aplicando el plugin windows.registry.hivelist..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.registry.hivelist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.registry.hivelist.txt

            # windows.registry.hivescan (Scans for registry hives present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.registry.hivescan..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.registry.hivescan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.registry.hivescan.txt

            # windows.registry.printkey (Lists the registry keys under a hive or specific key value)
              # Argumentos:
              #   --offset OFFSET - Hive Offset
              #   --key KEY       - Key to start from
              #   --recurse       - Recurses through keys
              echo ""
              echo "    Aplicando el plugin windows.registry.printkey..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.registry.printkey | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.registry.printkey.txt
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.registry.printkey ‑‑key "Software\Microsoft\Windows\CurrentVersion" | grep -v "Volatility 3"

            # windows.registry.userassist (Print userassist registry keys and information)
              # Argumentos:
              #   --offset OFFSET - Hive Offset
              echo ""
              echo "    Aplicando el plugin windows.registry.userassist..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.registry.userassist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.registry.userassist.txt

            # windows.scheduled_tasks (Decodes scheduled task information from the Windows registry, including information about triggers, actions, run times, and creation times)
              echo ""
              echo "    Aplicando el plugin windows.scheduled_tasks..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.scheduled_tasks | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.scheduled_tasks.txt

            # windows.sessions (lists Processes with Session information extracted from Environmental Variables)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.sessions..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.sessions | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.sessions.txt

            # windows.shimcachemem (Reads Shimcache entries from the ahcache.sys AVL tree)
              echo ""
              echo "    Aplicando el plugin windows.shimcachemem..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.shimcachemem | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.shimcachemem.txt

            # windows.skeleton_key_check (Looks for signs of Skeleton Key malware)
              echo ""
              echo "    Aplicando el plugin windows.skeleton_key_check..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.skeleton_key_check | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.skeleton_key_check.txt

            # windows.ssdt (Lists the system call table)
              echo ""
              echo "    Aplicando el plugin windows.ssdt..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.ssdt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.ssdt.txt

            # windows.statistics (Lists statistics about the memory space)
              echo ""
              echo "    Aplicando el plugin windows.statistics..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.statistics | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.statistics.txt

            # windows.strings (Reads output from the strings command and indicates which process(es) each string belongs to)
              # Argumentos:
              #   --pid [PID ...]             - Process ID to include (all other processes are excluded)
              #   --strings-file STRINGS_FILE - Strings file
              echo ""
              echo "    Aplicando el plugin windows.strings..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.strings | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.strings.txt

            # windows.suspicious_threads (Lists suspicious userland process threads)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.suspicious_threads..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.suspicious_threads | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.suspicious_threads.txt

            # windows.svcdiff (Compares services found through list walking versus scanning to find rootkits)
              echo ""
              echo "    Aplicando el plugin windows.svcdiff..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.svcdiff | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.svcdiff.txt

            # windows.svclist (Lists services contained with the services.exe doubly linked list of services)
              echo ""
              echo "    Aplicando el plugin windows.svclist..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.svclist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.svclist.txt

            # windows.svcscan (Scans for windows services)
              echo ""
              echo "    Aplicando el plugin windows.svcscan..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.svcscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.svcscan.txt

            # windows.symlinkscan (Scans for links present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.symlinkscan..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.symlinkscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.symlinkscan.txt

            # windows.thrdscan (Scans for windows threads)
              echo ""
              echo "    Aplicando el plugin windows.thrdscan..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.thrdscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.thrdscan.txt

            # windows.threads (Lists process threads)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.threads..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.threads | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.threads.txt

            # windows.timers (Print kernel timers and associated module DPCs)
              echo ""
              echo "    Aplicando el plugin windows.timers..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.timers | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.timers.txt

            # windows.truecrypt (TrueCrypt Cached Passphrase Finder)
              # Argumentos:
              #   --min-length MIN-LENGTH - Minimum length of passphrases to identify
              echo ""
              echo "    Aplicando el plugin windows.truecrypt..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.truecrypt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.truecrypt.txt

            # windows.unhooked_system_calls (Looks for signs of Skeleton Key malware)
              echo ""
              echo "    Aplicando el plugin windows.unhooked_system_calls..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.unhooked_system_calls | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.unhooked_system_calls.txt

            # windows.unloadedmodules (Lists the unloaded kernel modules)
              echo ""
              echo "    Aplicando el plugin windows.unloadedmodules..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.unloadedmodules | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.unloadedmodules.txt

            # windows.vadinfo (Lists process memory ranges)
              # Argumentos:
              #   --address ADDRESS - Process virtual memory address to include (all other address ranges are excluded).
              #   --pid [PID ...]   - Filter on specific process IDs
              #   --dump            - Extract listed memory ranges
              #   --maxsize MAXSIZE - Maximum size for dumped VAD sections (all the bigger sections will be ignored)
              echo ""
              echo "    Aplicando el plugin windows.vadinfo..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.vadinfo | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.vadinfo.txt

            # windows.vadregexscan (Scans all virtual memory areas for tasks using RegEx)
              # Argumentos:
              #   --pid [PID ...]   - Filter on specific process IDs
              #   --pattern PATTERN - RegEx pattern
              #   --maxsize MAXSIZE - Maximum size in bytes for displayed context
              echo ""
              echo "    Aplicando el plugin windows.vadregexscan..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.vadregexscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.vadregexscan.txt

            # windows.vadwalk (Walk the VAD tree)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.vadwalk..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.vadwalk | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.vadwalk.txt

            # windows.verinfo (Lists version information from PE files)
              # Argumenots:
              #   --extensive - Search physical layer for version information
              echo ""
              echo "    Aplicando el plugin windows.verinfo..."
              echo ""
              # Normal
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.verinfo             | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.verinfo-normal.txt
              # Extensivo
                vol -r pretty -f "$cRutaAlArchivoDeDump" windows.verinfo --extensive | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.verinfo-extensivo.txt

            # windows.virtmap (Lists virtual mapped sections)
              echo ""
              echo "    Aplicando el plugin windows.virtmap..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.virtmap | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/windows.virtmap.txt

            # windows.vadyarascan (Scans all the Virtual Address Descriptor memory maps using yara)
              # Argumentos:
              #   --insensitive                           - Makes the search case insensitive
              #   --wide                                  - Match wide (unicode) strings
              #   --yara-string YARA_STRING               - Yara rules (as a string)
              #   --yara-file YARA_FILE                   - Yara rules (as a file)
              #   --yara-compiled-file YARA_COMPILED_FILE - Yara compiled rules (as a file)
              #   --max-size MAX_SIZE                     - Set the maximum size (default is 1GB)
              #   --pid [PID ...]                         - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.vadyarascan..."
              echo ""
              vol -r pretty -f "$cRutaAlArchivoDeDump" windows.vadyarascan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.vadyarascan.txt

            # No windows

              # isinfo (Determines information about the currently available ISF files, or a specific one)
                # Argumentos:
                #   --filter [FILTER ...] - String that must be present in the file URI to display the ISF
                #   --isf ISF             - Specific ISF file to process
                #   --validate            - Validate against schema if possible
                #   --live                - Traverse all files, rather than use the cache
                echo ""
                echo "    Aplicando el plugin isinfo..."
                echo ""
                vol -r pretty -f "$cRutaAlArchivoDeDump" isfinfo | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/isfinfo.txt

              # layerwriter (Runs the automagics and writes out the primary layer produced by the stacker)
                # Argumentos:
                #   --block-size BLOCK_SIZE - Size of blocks to copy over
                #   --list                  - List available layers
                #   --layers [LAYERS ...]   - Names of layers to write (defaults to the highest non-mapped layer)
                echo ""
                echo "    Aplicando el plugin layerwriter..."
                echo ""
                mkdir -p "$cCarpetaDondeGuardar"/txt/MemoryLayer/
                cd "$cCarpetaDondeGuardar"/txt/MemoryLayer/
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" layerwriter
                cd $HOME/HackingTools/Forensics/volatility2

              # regexscan.RegExScan (Scans kernel memory using RegEx patterns)
                # Argumentos:
                #   --pattern PATTERN - RegEx pattern
                #   --maxsize MAXSIZE - Maximum size in bytes for displayed context
                echo ""
                echo "    Aplicando el plugin regexscan.RegExScan..."
                echo ""
                vol -r pretty -f "$cRutaAlArchivoDeDump" regexscan.RegExScan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/regexscan.RegExScan.txt

              # timeliner (Runs all relevant plugins that provide time related information and orders the results by time)
                # Argumentos:
                #   --record-config                     - Whether to record the state of all the plugins once complete
                #   --plugin-filter [PLUGIN-FILTER ...] - Only run plugins featuring this substring
                #   --create-bodyfile                   - Whether to create a body file whilst producing results
                echo ""
                echo "    Aplicando el plugin timeliner..."
                echo ""
                vol -r pretty -f "$cRutaAlArchivoDeDump" timeliner | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/txt/timeliner.txt

            # Desactivar el entorno virtual
              deactivate

        ;;

       16)

          echo ""
          echo "  Parseando hacia archivos csv..."
          echo ""

          # Entrar en el entorno virtual de python
            source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate

          # Parsear datos

            # Crear carpeta
              mkdir -p "$cCarpetaDondeGuardar"/csv

            # windows.amcache (Extract information on executed applications from the AmCache)
              echo ""
              echo "    Aplicando el plugin windows.amcache..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.amcache | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.amcache.csv

            # windows.bigpools (List big page pools)
              # Argumentos:
              #   --tags TAGS - Comma separated list of pool tags to filter pools returned
              #   --show-free - Show freed regions (otherwise only show allocations in use)
              echo ""
              echo "    Aplicando el plugin windows.bigpools..."
              echo ""
              # En uso
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.bigpools             | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.bigpools-enuso.csv
              # En uso y libres
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.bigpools --show-free | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.bigpools-enusoylibres.csv

            # windows.callbacks (Lists kernel callbacks and notification routines)
              echo ""
              echo "    Aplicando el plugin windows.callbacks..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.callbacks | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.callbacks.csv

            # windows.cmdline (Lists process command line arguments)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.cmdline..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.cmdline | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.cmdline.csv

            # windows.cmdscan (Looks for Windows Command History lists)
              # Argumentos:
              #   --no-registry                   - Don't search the registry for possible values of CommandHistorySize
              #   --max-history [MAX_HISTORY ...] - CommandHistorySize values to search for.
              echo ""
              echo "    Aplicando el plugin windows.cmdscan..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.cmdscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.cmdscan.csv

            # windows.consoles (Looks for Windows console buffers)
              # Argumentos:
              #   --no-registry                   - Don't search the registry for possible values of CommandHistorySize and HistoryBufferMax
              #   --max-history [MAX_HISTORY ...] - CommandHistorySize values to search for.
              #   --max-buffers [MAX_BUFFERS ...] - HistoryBufferMax values to search for.
              echo ""
              echo "    Aplicando el plugin windows.consoles..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.consoles | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.consoles.csv

            # windows.crashinfo (Lists the information from a Windows crash dump)
              echo ""
              echo "    Aplicando el plugin windows.crashinfo..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.crashinfo | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.crashinfo.csv

            # windows.debugregisters ()
              echo ""
              echo "    Aplicando el plugin windows.debugregisters..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.debugregisters | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.debugregisters.csv

            # windows.devicetree (Listing tree based on drivers and attached devices in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.devicetree..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.devicetree | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.devicetree.csv

            # windows.dlllist (Lists the loaded modules in a particular windows memory image)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              #   --offset OFFSET - Process offset in the physical address space
              #   --name NAME     - Specify a regular expression to match dll name(s)
              #   --base BASE     - Specify a base virtual address in process memory
              #   --ignore-case   - Specify case insensitivity for the regular expression name matching
              #   --dump          - Extract listed DLLs
              echo ""
              echo "    Aplicando el plugin windows.dlllist..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.dlllist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.dlllist.csv
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.dlllist ‑‑pid "<PID>"

            # windows.driverirp (List IRPs for drivers in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.driverirp..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.driverirp | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.driverirp.csv

            # windows.drivermodule (Determines if any loaded drivers were hidden by a rootkit)
              echo ""
              echo "    Aplicando el plugin windows.drivermodule..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.drivermodule | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.drivermodule.csv

            # windows.driverscan (Scans for drivers present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.driverscan..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.driverscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.driverscan.csv

            # windows.envars (Display process environment variables)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              #   --silent        - Suppress common and non-persistent variables
              echo ""
              echo "    Aplicando el plugin windows.envars..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.envars | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.envars.csv

            # windows.filescan (Scans for file objects present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.filescan..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.filescan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.filescan.csv

            # windows.getservicesids (Lists process token sids)
              echo ""
              echo "    Aplicando el plugin windows.getservicesids..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.getservicesids | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.getservicesids.csv

            # windows.getsids (Print the SIDs owning each process)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.getsids..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.getsids | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.getsids.csv

            # windows.handles (Lists process open handles)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              #   --offset OFFSET - Process offset in the physical address space
              echo ""
              echo "    Aplicando el plugin windows.handles..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.handles | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.handles.csv
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.handles ‑‑pid "<PID>"

            # windows.hashdump (Dumps user hashes from memory)
              echo ""
              echo "    Aplicando el plugin windows.hashdump..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.hashdump | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.hashdump.csv

            # windows.hollowprocesses (Lists hollowed processes)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.hollowprocesses..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.hollowprocesses | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.hollowprocesses.csv

            # windows.iat (Extract Import Address Table to list API (functions) used by a program contained in external libraries)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.iat..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.iat | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.iat.csv

            # windows.info (Show OS & kernel details of the memory sample being analyzed)
              echo ""
              echo "    Aplicando el plugin windows.info..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.info | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.info.csv

            # windows.joblinks (Print process job link information)
             # Argumentos:
              #   --physical - Display physical offset instead of virtual
              echo ""
              echo "    Aplicando el plugin windows.joblinks..."
              echo ""
              # Offset virtual
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.joblinks            | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.joblinks-offsetvirtual.csv
              # Offset físico
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.joblinks --physical | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.joblinks-offsetfisico.csv

            # windows.kpcrs (Print KPCR structure for each processor)
              echo ""
              echo "    Aplicando el plugin windows.kpcrs..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.kpcrs | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.kpcrs.csv

            # windows.ldrmodules (Lists the loaded modules in a particular windows memory image)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.ldrmodules..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.ldrmodules | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.ldrmodules.csv

            # windows.malfind (Lists process memory ranges that potentially contain injected code)
              echo ""
              echo "    Aplicando el plugin windows.malfind..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.malfind | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.malfind.csv

            # windows.mbrscan (Scans for and parses potential Master Boot Records (MBRs))
              # Argumentos:
              #   --full - It analyzes and provides all the information in the partition entry and bootcode hexdump. (It returns a lot of information, so we recommend you render it in CSV.)
              echo ""
              echo "    Aplicando el plugin windows.mbrscan..."
              echo ""
              # Simple
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.mbrscan        | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.mbrscan.csv
              # Completo
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.mbrscan --full | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.mbrscan-full.csv

            # windows.memmap (Prints the memory map)
              # Argumentos:
              #   --pid PID - Process ID to include (all other processes are excluded)
              #   --dump    - Extract listed memory segments
              echo ""
              echo "    Aplicando el plugin windows.memmap..."
              echo ""
              #vol -r csv -f "$cRutaAlArchivoDeDump" windows.memmap | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.memmap.csv
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" -o "/path/to/dir" windows.memmap ‑‑dump ‑‑pid "<PID>"

            # windows.modscan (Scans for modules present in a particular windows memory image)
              # Argumentos:
              #   --dump      - Extract listed modules
              #   --base BASE - Extract a single module with BASE address
              #   --name NAME - module name/sub string
              echo ""
              echo "    Aplicando el plugin windows.modscan..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.modscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.modscan.csv

            # windows.modules (Lists the loaded kernel modules)
              # Argumentos:
              #   --dump      - Extract listed modules
              #   --base BASE - Extract a single module with BASE address
              #   --name NAME - module name/sub string
              echo ""
              echo "    Aplicando el plugin windows.modules..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.modules | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.modules.csv

            # windows.mutantscan (Scans for mutexes present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.mutantscan..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.mutantscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.mutantscan.csv

            # windows.netscan (Scans for network objects present in a particular windows memory image)
              # Argumentos:
              #   --include-corrupt - Radically eases result validation. This will show partially overwritten data. WARNING: the results are likely to include garbage and/or corrupt data. Be cautious!
              echo ""
              echo "    Aplicando el plugin windows.netscan..."
              echo ""
              # Sin corruptos
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.netscan                   | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.netscan.csv
              # Con corruptos
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.netscan --include-corrupt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.netscan-corrupt.csv

            # windows.netstat (Traverses network tracking structures present in a particular windows memory image)
              # Argumentos:
              #   --include-corrupt - Radically eases result validation. This will show partially overwritten data. WARNING: the results are likely to include garbage and/or corrupt data. Be cautious!
              echo ""
              echo "    Aplicando el plugin windows.netstat..."
              echo ""
              # Sin corruptos
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.netstat                   | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.netstat.csv
              # Con corruptos
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.netstat --include-corrupt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.netstat-corrupt.csv

            # windows.orphan_kernel_threads (Lists process threads)
              echo ""
              echo "    Aplicando el plugin windows.orphan_kernel_threads..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.orphan_kernel_threads | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.orphan_kernel_threads.csv

            # windows.pe_symbols (Prints symbols in PE files in process and kernel memory)
              # Argumentos:
              #   --source {kernel,processes} - Where to resolve symbols.
              #   --module MODULE             - Module in which to resolve symbols. Use "ntoskrnl.exe" to resolve in the base kernel executable.
              #   --symbols [SYMBOLS ...]     - Symbol name to resolve
              #   --addresses [ADDRESSES ...] - Address of symbol to resolve
              echo ""
              echo "    Aplicando el plugin windows.pe_symbols..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.pe_symbols | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.pe_symbols.csv

            # windows.pedump (Allows extracting PE Files from a specific address in a specific address space)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              #   --base BASE     - Base address to reconstruct a PE file
              #   --kernel-module - Extract from kernel address space.
              echo ""
              echo "    Aplicando el plugin windows.pedump..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.pedump | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.pedump.csv

            # windows.poolscanner (A generic pool scanner plugin)
              echo ""
              echo "    Aplicando el plugin windows.poolscanner..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.poolscanner | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.poolscanner.csv

            # windows.privileges (Lists process token privileges)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.privileges..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.privileges | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.privileges.csv

            # windows.processghosting (Lists processes whose DeletePending bit is set or whose FILE_OBJECT is set to 0)
              echo ""
              echo "    Aplicando el plugin windows.processghosting..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.processghosting | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.processghosting.csv

            # windows.pslist (Lists the processes present in a particular windows memory image)
              # Argumentos:
              #   --physical      - Display physical offsets instead of virtual
              #   --pid [PID ...] - Process ID to include (all other processes are excluded)
              #   --dump          - Extract listed processes
              echo ""
              echo "    Aplicando el plugin windows.pslist..."
              echo ""
              # Offset virtual
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.pslist            | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.pslist-offsetvirtual.csv
              # Offset físico
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.pslist --physical | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.pslist-offsetfisico.csv

            # windows.psscan (Scans for processes present in a particular windows memory image)
              # Argumentos:
              #   --physical      - Display physical offsets instead of virtual
              #   --pid [PID ...] - Process ID to include (all other processes are excluded)
              #   --dump          - Extract listed processes
              echo ""
              echo "    Aplicando el plugin windows.psscan..."
              echo ""
              # Offset virtual
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.psscan            | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.psscan-offsetvirtual.csv
              # Offset físico
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.psscan --physical | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.psscan-offsetfisico.csv

            # windows.pstree (Plugin for listing processes in a tree based on their parent process ID)
              # Argumentos:
              #   --physical      - Display physical offsets instead of virtual
              #   --pid [PID ...] - Process ID to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.pstree..."
              echo ""
              # Offset virtual
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.pstree            | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.pstree-offsetvirtual.csv
              # Offset físico
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.pstree --physical | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.pstree-offsetfisico.csv

            # windows.psxview (Lists all processes found via four of the methods described in "The Art of Memory Forensics," which may help identify processes that are trying to hide themselves. I recommend using -r pretty if you are looking at this plugin's output in a terminal)
              # Argumentos:
              # --physical-offsets - List processes with physical offsets instead of virtual offsets.
              echo ""
              echo "    Aplicando el plugin windows.psxview..."
              echo ""
              # Offsets virtuales
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.psxview                    | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.psxview-offsetsvirtuales.csv
              # Offsets físicos
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.psxview --physical-offsets | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.psxview-offsetsfisicos.csv

            # windows.registry.certificates (Lists the certificates in the registry's Certificate Store)
              # Argumentos:
              #   --dump - Extract listed certificates
              echo ""
              echo "    Aplicando el plugin windows.registry.certificates..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.registry.certificates | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.registry.certificates.csv

            # windows.registry.getcellroutine (Reports registry hives with a hooked GetCellRoutine handler)
              echo ""
              echo "    Aplicando el plugin windows.registry.getcellroutine..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.registry.getcellroutine | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.registry.getcellroutine.csv

            # windows.registry.hivelist (Lists the registry hives present in a particular memory image)
              # Argumentos:
              #   --filter FILTER - String to filter hive names returned
              #   --dump          - Extract listed registry hives
              echo ""
              echo "    Aplicando el plugin windows.registry.hivelist..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.registry.hivelist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.registry.hivelist.csv

            # windows.registry.hivescan (Scans for registry hives present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.registry.hivescan..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.registry.hivescan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.registry.hivescan.csv

            # windows.registry.printkey (Lists the registry keys under a hive or specific key value)
              # Argumentos:
              #   --offset OFFSET - Hive Offset
              #   --key KEY       - Key to start from
              #   --recurse       - Recurses through keys
              echo ""
              echo "    Aplicando el plugin windows.registry.printkey..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.registry.printkey | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.registry.printkey.csv
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.registry.printkey ‑‑key "Software\Microsoft\Windows\CurrentVersion" | grep -v "Volatility 3"

            # windows.registry.userassist (Print userassist registry keys and information)
              # Argumentos:
              #   --offset OFFSET - Hive Offset
              echo ""
              echo "    Aplicando el plugin windows.registry.userassist..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.registry.userassist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.registry.userassist.csv

            # windows.scheduled_tasks (Decodes scheduled task information from the Windows registry, including information about triggers, actions, run times, and creation times)
              echo ""
              echo "    Aplicando el plugin windows.scheduled_tasks..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.scheduled_tasks | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.scheduled_tasks.csv

            # windows.sessions (lists Processes with Session information extracted from Environmental Variables)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.sessions..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.sessions | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.sessions.csv

            # windows.shimcachemem (Reads Shimcache entries from the ahcache.sys AVL tree)
              echo ""
              echo "    Aplicando el plugin windows.shimcachemem..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.shimcachemem | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.shimcachemem.csv

            # windows.skeleton_key_check (Looks for signs of Skeleton Key malware)
              echo ""
              echo "    Aplicando el plugin windows.skeleton_key_check..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.skeleton_key_check | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.skeleton_key_check.csv

            # windows.ssdt (Lists the system call table)
              echo ""
              echo "    Aplicando el plugin windows.ssdt..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.ssdt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.ssdt.csv

            # windows.statistics (Lists statistics about the memory space)
              echo ""
              echo "    Aplicando el plugin windows.statistics..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.statistics | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.statistics.csv

            # windows.strings (Reads output from the strings command and indicates which process(es) each string belongs to)
              # Argumentos:
              #   --pid [PID ...]             - Process ID to include (all other processes are excluded)
              #   --strings-file STRINGS_FILE - Strings file
              echo ""
              echo "    Aplicando el plugin windows.strings..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.strings | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.strings.csv

            # windows.suspicious_threads (Lists suspicious userland process threads)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.suspicious_threads..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.suspicious_threads | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.suspicious_threads.csv

            # windows.svcdiff (Compares services found through list walking versus scanning to find rootkits)
              echo ""
              echo "    Aplicando el plugin windows.svcdiff..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.svcdiff | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.svcdiff.csv

            # windows.svclist (Lists services contained with the services.exe doubly linked list of services)
              echo ""
              echo "    Aplicando el plugin windows.svclist..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.svclist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.svclist.csv

            # windows.svcscan (Scans for windows services)
              echo ""
              echo "    Aplicando el plugin windows.svcscan..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.svcscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.svcscan.csv

            # windows.symlinkscan (Scans for links present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.symlinkscan..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.symlinkscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.symlinkscan.csv

            # windows.thrdscan (Scans for windows threads)
              echo ""
              echo "    Aplicando el plugin windows.thrdscan..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.thrdscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.thrdscan.csv

            # windows.threads (Lists process threads)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.threads..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.threads | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.threads.csv

            # windows.timers (Print kernel timers and associated module DPCs)
              echo ""
              echo "    Aplicando el plugin windows.timers..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.timers | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.timers.csv

            # windows.truecrypt (TrueCrypt Cached Passphrase Finder)
              # Argumentos:
              #   --min-length MIN-LENGTH - Minimum length of passphrases to identify
              echo ""
              echo "    Aplicando el plugin windows.truecrypt..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.truecrypt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.truecrypt.csv

            # windows.unhooked_system_calls (Looks for signs of Skeleton Key malware)
              echo ""
              echo "    Aplicando el plugin windows.unhooked_system_calls..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.unhooked_system_calls | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.unhooked_system_calls.csv

            # windows.unloadedmodules (Lists the unloaded kernel modules)
              echo ""
              echo "    Aplicando el plugin windows.unloadedmodules..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.unloadedmodules | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.unloadedmodules.csv

            # windows.vadinfo (Lists process memory ranges)
              # Argumentos:
              #   --address ADDRESS - Process virtual memory address to include (all other address ranges are excluded).
              #   --pid [PID ...]   - Filter on specific process IDs
              #   --dump            - Extract listed memory ranges
              #   --maxsize MAXSIZE - Maximum size for dumped VAD sections (all the bigger sections will be ignored)
              echo ""
              echo "    Aplicando el plugin windows.vadinfo..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.vadinfo | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.vadinfo.csv

            # windows.vadregexscan (Scans all virtual memory areas for tasks using RegEx)
              # Argumentos:
              #   --pid [PID ...]   - Filter on specific process IDs
              #   --pattern PATTERN - RegEx pattern
              #   --maxsize MAXSIZE - Maximum size in bytes for displayed context
              echo ""
              echo "    Aplicando el plugin windows.vadregexscan..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.vadregexscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.vadregexscan.csv

            # windows.vadwalk (Walk the VAD tree)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.vadwalk..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.vadwalk | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.vadwalk.csv

            # windows.verinfo (Lists version information from PE files)
              # Argumenots:
              #   --extensive - Search physical layer for version information
              echo ""
              echo "    Aplicando el plugin windows.verinfo..."
              echo ""
              # Normal
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.verinfo             | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.verinfo-normal.csv
              # Extensivo
                vol -r csv -f "$cRutaAlArchivoDeDump" windows.verinfo --extensive | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.verinfo-extensivo.csv

            # windows.virtmap (Lists virtual mapped sections)
              echo ""
              echo "    Aplicando el plugin windows.virtmap..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.virtmap | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/windows.virtmap.csv

            # windows.vadyarascan (Scans all the Virtual Address Descriptor memory maps using yara)
              # Argumentos:
              #   --insensitive                           - Makes the search case insensitive
              #   --wide                                  - Match wide (unicode) strings
              #   --yara-string YARA_STRING               - Yara rules (as a string)
              #   --yara-file YARA_FILE                   - Yara rules (as a file)
              #   --yara-compiled-file YARA_COMPILED_FILE - Yara compiled rules (as a file)
              #   --max-size MAX_SIZE                     - Set the maximum size (default is 1GB)
              #   --pid [PID ...]                         - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.vadyarascan..."
              echo ""
              vol -r csv -f "$cRutaAlArchivoDeDump" windows.vadyarascan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.vadyarascan.csv

            # No windows

              # isinfo (Determines information about the currently available ISF files, or a specific one)
                # Argumentos:
                #   --filter [FILTER ...] - String that must be present in the file URI to display the ISF
                #   --isf ISF             - Specific ISF file to process
                #   --validate            - Validate against schema if possible
                #   --live                - Traverse all files, rather than use the cache
                echo ""
                echo "    Aplicando el plugin isinfo..."
                echo ""
                vol -r csv -f "$cRutaAlArchivoDeDump" isfinfo | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/isfinfo.csv

              # layerwriter (Runs the automagics and writes out the primary layer produced by the stacker)
                # Argumentos:
                #   --block-size BLOCK_SIZE - Size of blocks to copy over
                #   --list                  - List available layers
                #   --layers [LAYERS ...]   - Names of layers to write (defaults to the highest non-mapped layer)
                echo ""
                echo "    Aplicando el plugin layerwriter..."
                echo ""
                mkdir -p "$cCarpetaDondeGuardar"/csv/MemoryLayer/
                cd "$cCarpetaDondeGuardar"/csv/MemoryLayer/
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" layerwriter
                cd $HOME/HackingTools/Forensics/volatility2

              # regexscan.RegExScan (Scans kernel memory using RegEx patterns)
                # Argumentos:
                #   --pattern PATTERN - RegEx pattern
                #   --maxsize MAXSIZE - Maximum size in bytes for displayed context
                echo ""
                echo "    Aplicando el plugin regexscan.RegExScan..."
                echo ""
                vol -r csv -f "$cRutaAlArchivoDeDump" regexscan.RegExScan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/regexscan.RegExScan.csv

              # timeliner (Runs all relevant plugins that provide time related information and orders the results by time)
                # Argumentos:
                #   --record-config                     - Whether to record the state of all the plugins once complete
                #   --plugin-filter [PLUGIN-FILTER ...] - Only run plugins featuring this substring
                #   --create-bodyfile                   - Whether to create a body file whilst producing results
                echo ""
                echo "    Aplicando el plugin timeliner..."
                echo ""
                vol -r csv -f "$cRutaAlArchivoDeDump" timeliner | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/csv/timeliner.csv

            # Desactivar el entorno virtual
              deactivate

        ;;

       17)

          echo ""
          echo "  Parseando hacia archivos json..."
          echo ""

          # Entrar en el entorno virtual de python
            source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate

          # Parsear datos

            # Crear carpeta
              mkdir -p "$cCarpetaDondeGuardar"/json

            # windows.amcache (Extract information on executed applications from the AmCache)
              echo ""
              echo "    Aplicando el plugin windows.amcache..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.amcache | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.amcache.json

            # windows.bigpools (List big page pools)
              # Argumentos:
              #   --tags TAGS - Comma separated list of pool tags to filter pools returned
              #   --show-free - Show freed regions (otherwise only show allocations in use)
              echo ""
              echo "    Aplicando el plugin windows.bigpools..."
              echo ""
              # En uso
                vol -r json -f "$cRutaAlArchivoDeDump" windows.bigpools             | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.bigpools-enuso.json
              # En uso y libres
                vol -r json -f "$cRutaAlArchivoDeDump" windows.bigpools --show-free | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.bigpools-enusoylibres.json

            # windows.callbacks (Lists kernel callbacks and notification routines)
              echo ""
              echo "    Aplicando el plugin windows.callbacks..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.callbacks | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.callbacks.json

            # windows.cmdline (Lists process command line arguments)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.cmdline..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.cmdline | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.cmdline.json

            # windows.cmdscan (Looks for Windows Command History lists)
              # Argumentos:
              #   --no-registry                   - Don't search the registry for possible values of CommandHistorySize
              #   --max-history [MAX_HISTORY ...] - CommandHistorySize values to search for.
              echo ""
              echo "    Aplicando el plugin windows.cmdscan..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.cmdscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.cmdscan.json

            # windows.consoles (Looks for Windows console buffers)
              # Argumentos:
              #   --no-registry                   - Don't search the registry for possible values of CommandHistorySize and HistoryBufferMax
              #   --max-history [MAX_HISTORY ...] - CommandHistorySize values to search for.
              #   --max-buffers [MAX_BUFFERS ...] - HistoryBufferMax values to search for.
              echo ""
              echo "    Aplicando el plugin windows.consoles..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.consoles | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.consoles.json

            # windows.crashinfo (Lists the information from a Windows crash dump)
              echo ""
              echo "    Aplicando el plugin windows.crashinfo..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.crashinfo | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.crashinfo.json

            # windows.debugregisters ()
              echo ""
              echo "    Aplicando el plugin windows.debugregisters..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.debugregisters | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.debugregisters.json

            # windows.devicetree (Listing tree based on drivers and attached devices in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.devicetree..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.devicetree | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.devicetree.json

            # windows.dlllist (Lists the loaded modules in a particular windows memory image)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              #   --offset OFFSET - Process offset in the physical address space
              #   --name NAME     - Specify a regular expression to match dll name(s)
              #   --base BASE     - Specify a base virtual address in process memory
              #   --ignore-case   - Specify case insensitivity for the regular expression name matching
              #   --dump          - Extract listed DLLs
              echo ""
              echo "    Aplicando el plugin windows.dlllist..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.dlllist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.dlllist.json
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.dlllist ‑‑pid "<PID>"

            # windows.driverirp (List IRPs for drivers in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.driverirp..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.driverirp | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.driverirp.json

            # windows.drivermodule (Determines if any loaded drivers were hidden by a rootkit)
              echo ""
              echo "    Aplicando el plugin windows.drivermodule..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.drivermodule | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.drivermodule.json

            # windows.driverscan (Scans for drivers present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.driverscan..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.driverscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.driverscan.json

            # windows.envars (Display process environment variables)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              #   --silent        - Suppress common and non-persistent variables
              echo ""
              echo "    Aplicando el plugin windows.envars..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.envars | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.envars.json

            # windows.filescan (Scans for file objects present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.filescan..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.filescan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.filescan.json

            # windows.getservicesids (Lists process token sids)
              echo ""
              echo "    Aplicando el plugin windows.getservicesids..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.getservicesids | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.getservicesids.json

            # windows.getsids (Print the SIDs owning each process)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.getsids..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.getsids | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.getsids.json

            # windows.handles (Lists process open handles)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              #   --offset OFFSET - Process offset in the physical address space
              echo ""
              echo "    Aplicando el plugin windows.handles..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.handles | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.handles.json
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.handles ‑‑pid "<PID>"

            # windows.hashdump (Dumps user hashes from memory)
              echo ""
              echo "    Aplicando el plugin windows.hashdump..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.hashdump | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.hashdump.json

            # windows.hollowprocesses (Lists hollowed processes)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.hollowprocesses..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.hollowprocesses | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.hollowprocesses.json

            # windows.iat (Extract Import Address Table to list API (functions) used by a program contained in external libraries)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.iat..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.iat | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.iat.json

            # windows.info (Show OS & kernel details of the memory sample being analyzed)
              echo ""
              echo "    Aplicando el plugin windows.info..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.info | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.info.json

            # windows.joblinks (Print process job link information)
             # Argumentos:
              #   --physical - Display physical offset instead of virtual
              echo ""
              echo "    Aplicando el plugin windows.joblinks..."
              echo ""
              # Offset virtual
                vol -r json -f "$cRutaAlArchivoDeDump" windows.joblinks            | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.joblinks-offsetvirtual.json
              # Offset físico
                vol -r json -f "$cRutaAlArchivoDeDump" windows.joblinks --physical | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.joblinks-offsetfisico.json

            # windows.kpcrs (Print KPCR structure for each processor)
              echo ""
              echo "    Aplicando el plugin windows.kpcrs..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.kpcrs | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.kpcrs.json

            # windows.ldrmodules (Lists the loaded modules in a particular windows memory image)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.ldrmodules..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.ldrmodules | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.ldrmodules.json

            # windows.malfind (Lists process memory ranges that potentially contain injected code)
              echo ""
              echo "    Aplicando el plugin windows.malfind..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.malfind | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.malfind.json

            # windows.mbrscan (Scans for and parses potential Master Boot Records (MBRs))
              # Argumentos:
              #   --full - It analyzes and provides all the information in the partition entry and bootcode hexdump. (It returns a lot of information, so we recommend you render it in CSV.)
              echo ""
              echo "    Aplicando el plugin windows.mbrscan..."
              echo ""
              # Simple
                vol -r json -f "$cRutaAlArchivoDeDump" windows.mbrscan        | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.mbrscan.json
              # Completo
                vol -r json -f "$cRutaAlArchivoDeDump" windows.mbrscan --full | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.mbrscan-full.json

            # windows.memmap (Prints the memory map)
              # Argumentos:
              #   --pid PID - Process ID to include (all other processes are excluded)
              #   --dump    - Extract listed memory segments
              echo ""
              echo "    Aplicando el plugin windows.memmap..."
              echo ""
              #vol -r json -f "$cRutaAlArchivoDeDump" windows.memmap | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.memmap.json
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" -o "/path/to/dir" windows.memmap ‑‑dump ‑‑pid "<PID>"

            # windows.modscan (Scans for modules present in a particular windows memory image)
              # Argumentos:
              #   --dump      - Extract listed modules
              #   --base BASE - Extract a single module with BASE address
              #   --name NAME - module name/sub string
              echo ""
              echo "    Aplicando el plugin windows.modscan..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.modscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.modscan.json

            # windows.modules (Lists the loaded kernel modules)
              # Argumentos:
              #   --dump      - Extract listed modules
              #   --base BASE - Extract a single module with BASE address
              #   --name NAME - module name/sub string
              echo ""
              echo "    Aplicando el plugin windows.modules..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.modules | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.modules.json

            # windows.mutantscan (Scans for mutexes present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.mutantscan..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.mutantscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.mutantscan.json

            # windows.netscan (Scans for network objects present in a particular windows memory image)
              # Argumentos:
              #   --include-corrupt - Radically eases result validation. This will show partially overwritten data. WARNING: the results are likely to include garbage and/or corrupt data. Be cautious!
              echo ""
              echo "    Aplicando el plugin windows.netscan..."
              echo ""
              # Sin corruptos
                vol -r json -f "$cRutaAlArchivoDeDump" windows.netscan                   | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.netscan.json
              # Con corruptos
                vol -r json -f "$cRutaAlArchivoDeDump" windows.netscan --include-corrupt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.netscan-corrupt.json

            # windows.netstat (Traverses network tracking structures present in a particular windows memory image)
              # Argumentos:
              #   --include-corrupt - Radically eases result validation. This will show partially overwritten data. WARNING: the results are likely to include garbage and/or corrupt data. Be cautious!
              echo ""
              echo "    Aplicando el plugin windows.netstat..."
              echo ""
              # Sin corruptos
                vol -r json -f "$cRutaAlArchivoDeDump" windows.netstat                   | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.netstat.json
              # Con corruptos
                vol -r json -f "$cRutaAlArchivoDeDump" windows.netstat --include-corrupt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.netstat-corrupt.json

            # windows.orphan_kernel_threads (Lists process threads)
              echo ""
              echo "    Aplicando el plugin windows.orphan_kernel_threads..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.orphan_kernel_threads | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.orphan_kernel_threads.json

            # windows.pe_symbols (Prints symbols in PE files in process and kernel memory)
              # Argumentos:
              #   --source {kernel,processes} - Where to resolve symbols.
              #   --module MODULE             - Module in which to resolve symbols. Use "ntoskrnl.exe" to resolve in the base kernel executable.
              #   --symbols [SYMBOLS ...]     - Symbol name to resolve
              #   --addresses [ADDRESSES ...] - Address of symbol to resolve
              echo ""
              echo "    Aplicando el plugin windows.pe_symbols..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.pe_symbols | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.pe_symbols.json

            # windows.pedump (Allows extracting PE Files from a specific address in a specific address space)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              #   --base BASE     - Base address to reconstruct a PE file
              #   --kernel-module - Extract from kernel address space.
              echo ""
              echo "    Aplicando el plugin windows.pedump..."
              echo ""

              vol -r json -f "$cRutaAlArchivoDeDump" windows.pedump | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.pedump.json

            # windows.poolscanner (A generic pool scanner plugin)
              echo ""
              echo "    Aplicando el plugin windows.poolscanner..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.poolscanner | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.poolscanner.json

            # windows.privileges (Lists process token privileges)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.privileges..."
              echo ""

              vol -r json -f "$cRutaAlArchivoDeDump" windows.privileges | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.privileges.json

            # windows.processghosting (Lists processes whose DeletePending bit is set or whose FILE_OBJECT is set to 0)
              echo ""
              echo "    Aplicando el plugin windows.processghosting..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.processghosting | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.processghosting.json

            # windows.pslist (Lists the processes present in a particular windows memory image)
              # Argumentos:
              #   --physical      - Display physical offsets instead of virtual
              #   --pid [PID ...] - Process ID to include (all other processes are excluded)
              #   --dump          - Extract listed processes
              echo ""
              echo "    Aplicando el plugin windows.pslist..."
              echo ""
              # Offset virtual
                vol -r json -f "$cRutaAlArchivoDeDump" windows.pslist            | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.pslist-offsetvirtual.json
              # Offset físico
                vol -r json -f "$cRutaAlArchivoDeDump" windows.pslist --physical | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.pslist-offsetfisico.json

            # windows.psscan (Scans for processes present in a particular windows memory image)
              # Argumentos:
              #   --physical      - Display physical offsets instead of virtual
              #   --pid [PID ...] - Process ID to include (all other processes are excluded)
              #   --dump          - Extract listed processes
              echo ""
              echo "    Aplicando el plugin windows.psscan..."
              echo ""
              # Offset virtual
                vol -r json -f "$cRutaAlArchivoDeDump" windows.psscan            | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.psscan-offsetvirtual.json
              # Offset físico
                vol -r json -f "$cRutaAlArchivoDeDump" windows.psscan --physical | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.psscan-offsetfisico.json

            # windows.pstree (Plugin for listing processes in a tree based on their parent process ID)
              # Argumentos:
              #   --physical      - Display physical offsets instead of virtual
              #   --pid [PID ...] - Process ID to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.pstree..."
              echo ""
              # Offset virtual
                vol -r json -f "$cRutaAlArchivoDeDump" windows.pstree            | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.pstree-offsetvirtual.json
              # Offset físico
                vol -r json -f "$cRutaAlArchivoDeDump" windows.pstree --physical | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.pstree-offsetfisico.json

            # windows.psxview (Lists all processes found via four of the methods described in "The Art of Memory Forensics," which may help identify processes that are trying to hide themselves. I recommend using -r pretty if you are looking at this plugin's output in a terminal)
              # Argumentos:
              # --physical-offsets - List processes with physical offsets instead of virtual offsets.
              echo ""
              echo "    Aplicando el plugin windows.psxview..."
              echo ""
              # Offsets virtuales
                vol -r json -f "$cRutaAlArchivoDeDump" windows.psxview                    | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.psxview-offsetsvirtuales.json
              # Offsets físicos
                vol -r json -f "$cRutaAlArchivoDeDump" windows.psxview --physical-offsets | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.psxview-offsetsfisicos.json

            # windows.registry.certificates (Lists the certificates in the registry's Certificate Store)
              # Argumentos:
              #   --dump - Extract listed certificates
              echo ""
              echo "    Aplicando el plugin windows.registry.certificates..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.registry.certificates | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.registry.certificates.json

            # windows.registry.getcellroutine (Reports registry hives with a hooked GetCellRoutine handler)
              echo ""
              echo "    Aplicando el plugin windows.registry.getcellroutine..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.registry.getcellroutine | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.registry.getcellroutine.json

            # windows.registry.hivelist (Lists the registry hives present in a particular memory image)
              # Argumentos:
              #   --filter FILTER - String to filter hive names returned
              #   --dump          - Extract listed registry hives
              echo ""
              echo "    Aplicando el plugin windows.registry.hivelist..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.registry.hivelist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.registry.hivelist.json

            # windows.registry.hivescan (Scans for registry hives present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.registry.hivescan..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.registry.hivescan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.registry.hivescan.json

            # windows.registry.printkey (Lists the registry keys under a hive or specific key value)
              # Argumentos:
              #   --offset OFFSET - Hive Offset
              #   --key KEY       - Key to start from
              #   --recurse       - Recurses through keys
              echo ""
              echo "    Aplicando el plugin windows.registry.printkey..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.registry.printkey | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.registry.printkey.json
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.registry.printkey ‑‑key "Software\Microsoft\Windows\CurrentVersion" | grep -v "Volatility 3"

            # windows.registry.userassist (Print userassist registry keys and information)
              # Argumentos:
              #   --offset OFFSET - Hive Offset
              echo ""
              echo "    Aplicando el plugin windows.registry.userassist..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.registry.userassist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.registry.userassist.json

            # windows.scheduled_tasks (Decodes scheduled task information from the Windows registry, including information about triggers, actions, run times, and creation times)
              echo ""
              echo "    Aplicando el plugin windows.scheduled_tasks..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.scheduled_tasks | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.scheduled_tasks.json

            # windows.sessions (lists Processes with Session information extracted from Environmental Variables)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.sessions..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.sessions | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.sessions.json

            # windows.shimcachemem (Reads Shimcache entries from the ahcache.sys AVL tree)
              echo ""
              echo "    Aplicando el plugin windows.shimcachemem..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.shimcachemem | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.shimcachemem.json

            # windows.skeleton_key_check (Looks for signs of Skeleton Key malware)
              echo ""
              echo "    Aplicando el plugin windows.skeleton_key_check..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.skeleton_key_check | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.skeleton_key_check.json

            # windows.ssdt (Lists the system call table)
              echo ""
              echo "    Aplicando el plugin windows.ssdt..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.ssdt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.ssdt.json

            # windows.statistics (Lists statistics about the memory space)
              echo ""
              echo "    Aplicando el plugin windows.statistics..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.statistics | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.statistics.json

            # windows.strings (Reads output from the strings command and indicates which process(es) each string belongs to)
              # Argumentos:
              #   --pid [PID ...]             - Process ID to include (all other processes are excluded)
              #   --strings-file STRINGS_FILE - Strings file
              echo ""
              echo "    Aplicando el plugin windows.strings..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.strings | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.strings.json

            # windows.suspicious_threads (Lists suspicious userland process threads)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.suspicious_threads..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.suspicious_threads | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.suspicious_threads.json

            # windows.svcdiff (Compares services found through list walking versus scanning to find rootkits)
              echo ""
              echo "    Aplicando el plugin windows.svcdiff..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.svcdiff | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.svcdiff.json

            # windows.svclist (Lists services contained with the services.exe doubly linked list of services)
              echo ""
              echo "    Aplicando el plugin windows.svclist..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.svclist | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.svclist.json

            # windows.svcscan (Scans for windows services)
              echo ""
              echo "    Aplicando el plugin windows.svcscan..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.svcscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.svcscan.json

            # windows.symlinkscan (Scans for links present in a particular windows memory image)
              echo ""
              echo "    Aplicando el plugin windows.symlinkscan..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.symlinkscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.symlinkscan.json

            # windows.thrdscan (Scans for windows threads)
              echo ""
              echo "    Aplicando el plugin windows.thrdscan..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.thrdscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.thrdscan.json

            # windows.threads (Lists process threads)
              # Argumentos:
              #   --pid [PID ...] - Filter on specific process IDs
              echo ""
              echo "    Aplicando el plugin windows.threads..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.threads | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.threads.json

            # windows.timers (Print kernel timers and associated module DPCs)
              echo ""
              echo "    Aplicando el plugin windows.timers..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.timers | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.timers.json

            # windows.truecrypt (TrueCrypt Cached Passphrase Finder)
              # Argumentos:
              #   --min-length MIN-LENGTH - Minimum length of passphrases to identify
              echo ""
              echo "    Aplicando el plugin windows.truecrypt..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.truecrypt | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.truecrypt.json

            # windows.unhooked_system_calls (Looks for signs of Skeleton Key malware)
              echo ""
              echo "    Aplicando el plugin windows.unhooked_system_calls..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.unhooked_system_calls | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.unhooked_system_calls.json

            # windows.unloadedmodules (Lists the unloaded kernel modules)
              echo ""
              echo "    Aplicando el plugin windows.unloadedmodules..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.unloadedmodules | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.unloadedmodules.json

            # windows.vadinfo (Lists process memory ranges)
              # Argumentos:
              #   --address ADDRESS - Process virtual memory address to include (all other address ranges are excluded).
              #   --pid [PID ...]   - Filter on specific process IDs
              #   --dump            - Extract listed memory ranges
              #   --maxsize MAXSIZE - Maximum size for dumped VAD sections (all the bigger sections will be ignored)
              echo ""
              echo "    Aplicando el plugin windows.vadinfo..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.vadinfo | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.vadinfo.json

            # windows.vadregexscan (Scans all virtual memory areas for tasks using RegEx)
              # Argumentos:
              #   --pid [PID ...]   - Filter on specific process IDs
              #   --pattern PATTERN - RegEx pattern
              #   --maxsize MAXSIZE - Maximum size in bytes for displayed context
              echo ""
              echo "    Aplicando el plugin windows.vadregexscan..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.vadregexscan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.vadregexscan.json

            # windows.vadwalk (Walk the VAD tree)
              # Argumentos:
              #   --pid [PID ...] - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.vadwalk..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.vadwalk | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.vadwalk.json

            # windows.verinfo (Lists version information from PE files)
              # Argumenots:
              #   --extensive - Search physical layer for version information
              echo ""
              echo "    Aplicando el plugin windows.verinfo..."
              echo ""
              # Normal
                vol -r json -f "$cRutaAlArchivoDeDump" windows.verinfo             | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.verinfo-normal.json
              # Extensivo
                vol -r json -f "$cRutaAlArchivoDeDump" windows.verinfo --extensive | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.verinfo-extensivo.json

            # windows.virtmap (Lists virtual mapped sections)
              echo ""
              echo "    Aplicando el plugin windows.virtmap..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.virtmap | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/windows.virtmap.json

            # windows.vadyarascan (Scans all the Virtual Address Descriptor memory maps using yara)
              # Argumentos:
              #   --insensitive                           - Makes the search case insensitive
              #   --wide                                  - Match wide (unicode) strings
              #   --yara-string YARA_STRING               - Yara rules (as a string)
              #   --yara-file YARA_FILE                   - Yara rules (as a file)
              #   --yara-compiled-file YARA_COMPILED_FILE - Yara compiled rules (as a file)
              #   --max-size MAX_SIZE                     - Set the maximum size (default is 1GB)
              #   --pid [PID ...]                         - Process IDs to include (all other processes are excluded)
              echo ""
              echo "    Aplicando el plugin windows.vadyarascan..."
              echo ""
              vol -r json -f "$cRutaAlArchivoDeDump" windows.vadyarascan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/tab/windows.vadyarascan.json

            # No windows

              # isinfo (Determines information about the currently available ISF files, or a specific one)
                # Argumentos:
                #   --filter [FILTER ...] - String that must be present in the file URI to display the ISF
                #   --isf ISF             - Specific ISF file to process
                #   --validate            - Validate against schema if possible
                #   --live                - Traverse all files, rather than use the cache
                echo ""
                echo "    Aplicando el plugin isinfo..."
                echo ""
                vol -r json -f "$cRutaAlArchivoDeDump" isfinfo | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/isfinfo.json

              # layerwriter (Runs the automagics and writes out the primary layer produced by the stacker)
                # Argumentos:
                #   --block-size BLOCK_SIZE - Size of blocks to copy over
                #   --list                  - List available layers
                #   --layers [LAYERS ...]   - Names of layers to write (defaults to the highest non-mapped layer)
                echo ""
                echo "    Aplicando el plugin layerwriter..."
                echo ""
                mkdir -p "$cCarpetaDondeGuardar"/json/MemoryLayer/
                cd "$cCarpetaDondeGuardar"/json/MemoryLayer/
                $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" layerwriter
                cd $HOME/HackingTools/Forensics/volatility2

              # regexscan.RegExScan (Scans kernel memory using RegEx patterns)
                # Argumentos:
                #   --pattern PATTERN - RegEx pattern
                #   --maxsize MAXSIZE - Maximum size in bytes for displayed context
                echo ""
                echo "    Aplicando el plugin regexscan.RegExScan..."
                echo ""
                vol -r json -f "$cRutaAlArchivoDeDump" regexscan.RegExScan | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/regexscan.RegExScan.json

              # timeliner (Runs all relevant plugins that provide time related information and orders the results by time)
                # Argumentos:
                #   --record-config                     - Whether to record the state of all the plugins once complete
                #   --plugin-filter [PLUGIN-FILTER ...] - Only run plugins featuring this substring
                #   --create-bodyfile                   - Whether to create a body file whilst producing results
                echo ""
                echo "    Aplicando el plugin timeliner..."
                echo ""
                vol -r json -f "$cRutaAlArchivoDeDump" timeliner | grep -v "Volatility 3" > "$cCarpetaDondeGuardar"/json/timeliner.json

            # Desactivar el entorno virtual
              deactivate

        ;;

       18)

          echo ""
          echo "  Buscando IPs privadas de clase A..."
          echo ""
          strings "$cRutaAlArchivoDeDump" | grep -Eo '10\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])' | sort -n | uniq

        ;;

       19)

          echo ""
          echo "  Buscando IPs privadas de clase B..."
          echo ""
          strings "$cRutaAlArchivoDeDump" | grep -Eo '172\.(1[6-9]|2[0-9]|3[0-1])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])' | sort -n | uniq

        ;;

       20)

          echo ""
          echo "  Buscando IPs privadas de clase C..."
          echo ""
          strings "$cRutaAlArchivoDeDump" | grep -Eo '192\.168\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])' | sort -n | uniq

        ;;

       21)

          echo ""
          echo "  Extrayendo el sistema carpetas y archivos de dentro del dump..."
          echo ""

          # Crear carpetas
            mkdir -p "$cCarpetaDondeGuardar"/tab
            mkdir -p "$cCarpetaDondeGuardar"/Archivos/Reales

          # Entrar en el entorno virtual de python
            source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate

          # Aplicar el plugin filescan
            echo ""
            echo "    Aplicando el plugin filescan..."
            echo ""
            $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" --profile="$vPerfilAconsejado" filescan > "$cCarpetaDondeGuardar"/tab/windows.filescan.tab
            #cat "$cCarpetaDondeGuardar"/tab/windows.filescan.tab | grep HarddiskVolume | awk '{print $1, $5}' | sed 's#\\Device\\HarddiskVolume1##g' | awk '$2 ~ /^\\[A-Za-z]/ {print $1, $2}' > /tmp/archivos.tab
            cat "$cCarpetaDondeGuardar"/tab/windows.filescan.tab | grep HarddiskVolume | awk '{print $1, $5}' | sed 's#\\Device\\HarddiskVolume1##g' > /tmp/archivos.tab
            # Reemplazar las barras para adaptarlas al sistema de carpetas de Linux
              sed -i 's|\\|/|g' /tmp/archivos.tab

          # Crear el array asociativo y meter dentro todos los offsets y los archivos
            unset aOffsetsArchivos
            declare -A aOffsetsArchivos
            while read -r vOffset vRuta; do
              aOffsetsArchivos["$vOffset"]="$vRuta"
            done < /tmp/archivos.tab

          # Mostrar el contenido del array
            #for key in "${!aOffsetsArchivos[@]}"; do
              #echo "$key -> ${aOffsetsArchivos[$key]}"
            #done

          # Recorrer el array e ir creando archivos
            for key in "${!aOffsetsArchivos[@]}"; do
              mkdir -p "$cCarpetaDondeGuardar"/Archivos/Reales/"$(dirname "${aOffsetsArchivos[$key]}")" \
              && cd "$cCarpetaDondeGuardar"/Archivos/Reales/"$(dirname "${aOffsetsArchivos[$key]}")" \
              && $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" --profile="$vPerfilAconsejado" dumpfiles -Q $key -D "$cCarpetaDondeGuardar"/Archivos/Reales/"$(dirname "${aOffsetsArchivos[$key]}")" 
            done

          # Eliminar la extension .dat a todos los archivos
            find "$cCarpetaDondeGuardar"/Archivos/Reales/ -type f -name "*.dat" | while IFS= read -r vArchivo; do
              # Verificar si el nombre del archivo contiene "DataSectionObject"
                if [[ "$vArchivo" == *"DataSectionObject"* ]]; then
                  # Obtener la nueva ruta sin la extensión .dat
                    vNuevoNombre="${vArchivo%.dat}"
                  # Renombrar el archivo
                    mv "$vArchivo" "$vNuevoNombre"
                fi
            done

          # Eliminar del nombre del archivo todo antes del . de DataSectionObject
            find "$cCarpetaDondeGuardar"/Archivos/Reales/ -type f | while IFS= read -r vArchivo; do
              # Extraer el nombre del archivo
                vNombreArchivo=$(basename "$vArchivo")
              # Verificar si el nombre contiene "DataSectionObject."
                if [[ "$vNombreArchivo" == *"DataSectionObject."* ]]; then
                  # Eliminar todo lo anterior a "DataSectionObject." (incluido)
                    vNuevoNombre="${vNombreArchivo#*DataSectionObject.}"
                  # Obtener la ruta completa del nuevo nombre
                    vDirectorio=$(dirname "$vArchivo")
                    vRutaNueva="$vDirectorio/$vNuevoNombre"
                  # Renombrar el archivo
                    mv "$vArchivo" "$vRutaNueva"
                fi
            done

          # Eliminar la extension .img a todos los archivos
            find "$cCarpetaDondeGuardar"/Archivos/Reales/ -type f -name "*.img" | while IFS= read -r vArchivo; do
              # Verificar si el nombre del archivo contiene "ImageSectionObject"
                if [[ "$vArchivo" == *"ImageSectionObject"* ]]; then
                  # Obtener la nueva ruta sin la extensión .dat
                    vNuevoNombre="${vArchivo%.img}"
                  # Renombrar el archivo
                    mv "$vArchivo" "$vNuevoNombre"
                fi
            done

          # Eliminar del nombre del archivo todo antes del . de ImageSectionObject
            find "$cCarpetaDondeGuardar"/Archivos/Reales/ -type f | while IFS= read -r vArchivo; do
              # Extraer el nombre del archivo
                vNombreArchivo=$(basename "$vArchivo")
              # Verificar si el nombre contiene "ImageSectionObject."
                if [[ "$vNombreArchivo" == *"ImageSectionObject."* ]]; then
                  # Eliminar todo lo anterior a "ImageSectionObject." (incluido)
                    vNuevoNombre="${vNombreArchivo#*ImageSectionObject.}"
                  # Obtener la ruta completa del nuevo nombre
                    vDirectorio=$(dirname "$vArchivo")
                    vRutaNueva="$vDirectorio/$vNuevoNombre"
                  # Renombrar el archivo
                    mv "$vArchivo" "$vRutaNueva"
                fi
            done


            # windows. (Dumps cached file contents from Windows memory samples)
              # Argumentos:
              #  --pid PID           - Process ID to include (all other processes are excluded)
              #  --virtaddr VIRTADDR - Dump a single _FILE_OBJECT at this virtual address
              #  --physaddr PHYSADDR - Dump a single _FILE_OBJECT at this physical address
              #  --filter FILTER     - Dump files matching regular expression FILTER
              #  --ignore-case       - Ignore case in filter match
      #        echo ""
     #         echo "    Aplicando el plugin windows.dumpfiles..."
          #    echo ""
         #     mkdir -p "$cCarpetaDondeGuardar"/Archivos/
        #      cd "$cCarpetaDondeGuardar"/Archivos/
       #       for vExtens in "${aExtensionesAExtraer[@]}"; do
      #          echo -e "\n      Extrayendo todos los archivos $vExtens...\n"
     #           $HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" windows.dumpfiles --filter \.$vExtens\$
     #         done
    #          cd $HOME/HackingTools/Forensics/volatility2
   #           dd if=file.None.0xfffffa8000d06e10.dat of=img.png bs=1 skip=0
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" -o "/path/to/dir" windows.dumpfiles ‑‑pid "<PID>" 
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" -o "/path/to/dir" windows.dumpfiles
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" -o "/path/to/dir" windows.dumpfiles ‑‑virtaddr "<offset>"
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" -o "/path/to/dir" windows.dumpfiles ‑‑physaddr "<offset>"   
              #$HOME/HackingTools/Forensics/volatility2/vol.py -f "$cRutaAlArchivoDeDump" -o "$cCarpetaDondeGuardar"/Archivos windows.dumpfiles --virtaddr 0xe70f57293860

        ;;

      esac

    done

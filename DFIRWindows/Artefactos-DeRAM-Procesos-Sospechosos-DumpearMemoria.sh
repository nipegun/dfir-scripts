#!/bin/bash

# Script de nipegun para analizar procesos sospechosos con Volatility2
#
# Ejecución remota:
#   curl -sL https://raw.githubusercontent.com/nipegun/dfir-scripts/refs/heads/main/DFIRWindows/Artefactos-DeRAM-Procesos-Sospechosos-DumpearMemoria.sh | bash
#

# Definir constantes
  cRutaAVolatility2="$HOME/HackingTools/Forensics/volatility2/vol.py"
  cRutaAlArchivoDeDump='/home/nipegun/Escritorio/CTFs/IntentandoResolver/ir_insider_2024.raw'
  cPerfilAconsejado='Win2016x64_14393'
  cCarpetaDondeGuardar="$HOME/Escritorio/CTFs/IntentandoResolver/"
  cCarpetaTMP="$HOME/Escritorio/CTFs/IntentandoResolver/Extracciones"

# Crear carpetas
  mkdir -p "$cCarpetaTMP"

# Extraer malfind
  source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate > /dev/null
    "$cRutaAVolatility2" -f "$cRutaAlArchivoDeDump" --profile="$cPerfilAconsejado" malfind > "$cCarpetaTMP"/malfind.txt
  deactivate

# Guardar en un array los números de procesos en malfind
  cat "$cCarpetaTMP"/malfind.txt | grep -i pid | awk '{print $4,$6}' > "$cCarpetaTMP"/malfind-array.txt
  unset aProcesosMaliciosos
  declare -A aProcesosMaliciosos
  while read -r vNumProc vDirecMem; do
    if [[ -n "${aProcesosMaliciosos[$vNumProc]}" ]]; then
      aProcesosMaliciosos[$vNumProc]="${aProcesosMaliciosos[$vNumProc]} $vDirecMem"
    else
      aProcesosMaliciosos[$vNumProc]="$vDirecMem"
    fi
  done < "$cCarpetaTMP"/malfind-array.txt

# Ejecutar un memdump por cada proceso
  for vNumProc in "${!aProcesosMaliciosos[@]}"; do
    mkdir -p "$cCarpetaTMP"/Procesos/"$vNumProc"/memdump/
    source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate > /dev/null
      "$cRutaAVolatility2" -f "$cRutaAlArchivoDeDump" --profile="$cPerfilAconsejado" memdump -p "$vNumProc" -D "$cCarpetaTMP"/Procesos/"$vNumProc"/memdump/
    deactivate
  done

    echo "$vNumProc -> ${aProcesosMaliciosos[$vNumProc]}"

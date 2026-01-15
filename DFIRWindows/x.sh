#!/bin/bash

# Script de nipegun para analizar procesos sospechosos con Volatility2

# Definir constantes
  cRutaAVolatility2="$HOME/HackingTools/Forensics/volatility2/vol.py"
  cRutaAlArchivoDeDump='/home/nipegun/Escritorio/CTFs/IntentandoResolver/ir_insider_2024.raw'
  cPerfilAconsejado='Win2016x64_14393'
  cCarpetaDondeGuardar="$HOME/Escritorio/CTFs/IntentandoResolver/"
  cCarpetaTMP='/tmp/RAMAnalysis'

# Crear carpetas
  mkdir -p "$cCarpetaTMP"

# Extraer malfind
  source $HOME/HackingTools/Forensics/volatility2/venv/bin/activate > /dev/null
    "$cRutaAVolatility2" -f "$cRutaAlArchivoDeDump" --profile="$cPerfilAconsejado" malfind > "$cCarpetaTMP"/malfind.txt
  deactivate

# Guardar en un array los números de procesos en malfind
  cat "$cCarpetaTMP"/malfind.txt | grep -i pid | awk '{print $4,$2,$6}' > "$cCarpetaTMP"/malfind-array.txt
  declare -A aProcesos
  while read -r vPid vProceso vDireccion; do
    vClave="${vPid}:${vProceso}"
    if [[ -n "${aProcesos[$vClave]}" ]]; then
      aProcesos["$vClave"]+=" ${vDireccion}"
    else
      aProcesos["$vClave"]="$vDireccion"
    fi
  done < "$cCarpetaTMP"/malfind-array.txt

# Mostrar el contenido del array
  for vClave in "${!aProcesos[@]}"; do
    echo "$vClave -> ${aProcesos[$vClave]}"
  done


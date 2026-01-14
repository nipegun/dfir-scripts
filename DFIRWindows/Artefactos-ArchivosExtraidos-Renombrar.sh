#!/bin/bash

# Pongo a disposición pública este script bajo el término de "software de dominio público".
# Puedes hacer lo que quieras con él porque es libre de verdad; no libre con condiciones como las licencias GNU y otras patrañas similares.
# Si se te llena la boca hablando de libertad entonces hazlo realmente libre.
# No tienes que aceptar ningún tipo de términos de uso o licencia para utilizarlo o modificarlo porque va sin CopyLeft.

# ----------
# Script de NiPeGun para reubicar los archivos extraidos por volatility en subcarpetas dat, img y vacb
#
# Ejecución remota:
#   curl -sL https://raw.githubusercontent.com/nipegun/dfir-scripts/refs/heads/main/DFIRWindows/Artefactos-ArchivosExtraidos-Renombrar.sh | bash -s [CarpetaBase]
#
# Bajar y editar directamente el archivo en nano
#   curl -sL https://raw.githubusercontent.com/nipegun/dfir-scripts/refs/heads/main/DFIRWindows/Artefactos-ArchivosExtraidos-Renombrar.sh | nano -
# ----------

# Comprobar que se haya pasado parámetro
  if [ -z "$1" ]; then
    echo "Uso: $0 <directorio_base>"
    exit 1
  fi

# Definir la constante con la carpeta base
  cCarpetaBase="$1"

# Renombrar en img/
  if [ -d "$cCarpetaBase/img" ]; then
    find "$cCarpetaBase/img" -type f -name '*.img' | while read -r vArchivo; do
      mv -v "$vArchivo" "${vArchivo%.img}"
    done
  fi

# Renombrar en dat/
  if [ -d "$cCarpetaBase/dat" ]; then
    find "$cCarpetaBase/dat" -type f -name '*.dat' | while read -r vArchivo; do
      mv -v "$vArchivo" "${vArchivo%.dat}"
    done
  fi

# Renombrar en vacb/
  if [ -d "$cCarpetaBase/vacb" ]; then
    find "$cCarpetaBase/vacb" -type f -name '*.vacb' | while read -r vArchivo; do
      mv -v "$vArchivo" "${vArchivo%.vacb}"
    done
  fi

echo "Renombrado completado."



#!/bin/bash

# Pongo a disposición pública este script bajo el término de "software de dominio público".
# Puedes hacer lo que quieras con él porque es libre de verdad; no libre con condiciones como las licencias GNU y otras patrañas similares.
# Si se te llena la boca hablando de libertad entonces hazlo realmente libre.
# No tienes que aceptar ningún tipo de términos de uso o licencia para utilizarlo o modificarlo porque va sin CopyLeft.

# ----------
# Script de NiPeGun para reubicar los archivos extraidos por volatility en subcarpetas dat, img y vacb
#
# Ejecución remota:
#   curl -sL https://raw.githubusercontent.com/nipegun/dfir-scripts/refs/heads/main/DFIRWindows/Artefactos-ArchivosExtraidos-Reubicar.sh | bash -s [CarpetaConArcchivosExtraidos]
#
# Bajar y editar directamente el archivo en nano
#   curl -sL https://raw.githubusercontent.com/nipegun/dfir-scripts/refs/heads/main/DFIRWindows/Artefactos-ArchivosExtraidos-Reubicar.sh | nano -
# ----------

# Comprobar que se haya pasado la carpeta
  if [ -z "$1" ]; then
    echo "Uso: $0 [CarpetaConArcchivosExtraidos]"
    exit 1
  fi

# Definir la constante con la ruta de la carpeta
cCarpetaConArcchivosExtraidos="$1"

# Crear subcarpetas
  mkdir -p "$cCarpetaConArcchivosExtraidos/dat"
  mkdir -p "$cCarpetaConArcchivosExtraidos/img"
  mkdir -p "$cCarpetaConArcchivosExtraidos/vacb"
  mkdir -p "$cCarpetaConArcchivosExtraidos/_otros"

# Mover archivos según extensión
  find "$cCarpetaConArcchivosExtraidos" -maxdepth 1 -type f -name '*.dat'  -exec mv -v {} "$cCarpetaConArcchivosExtraidos/dat/"  \;
  find "$cCarpetaConArcchivosExtraidos" -maxdepth 1 -type f -name '*.img'  -exec mv -v {} "$cCarpetaConArcchivosExtraidos/img/"  \;
  find "$cCarpetaConArcchivosExtraidos" -maxdepth 1 -type f -name '*.vacb' -exec mv -v {} "$cCarpetaConArcchivosExtraidos/vacb/" \;

# Cualquier otro archivo
  find "$cCarpetaConArcchivosExtraidos" -maxdepth 1 -type f ! -name '*.dat' ! -name '*.img' ! -name '*.vacb' -exec mv -v {} "$cCarpetaConArcchivosExtraidos/_otros/" \;

echo "Reubicación completada completada."

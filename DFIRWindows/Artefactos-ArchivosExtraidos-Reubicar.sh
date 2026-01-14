#!/bin/bash

# Pongo a disposición pública este script bajo el término de "software de dominio público".
# Puedes hacer lo que quieras con él porque es libre de verdad; no libre con condiciones como las licencias GNU y otras patrañas similares.
# Si se te llena la boca hablando de libertad entonces hazlo realmente libre.
# No tienes que aceptar ningún tipo de términos de uso o licencia para utilizarlo o modificarlo porque va sin CopyLeft.

# ----------
# Script de NiPeGun para reubicar los archivos extraidos por volatility en subcarpetas dat, img y vacb
#
# Ejecución remota:
#   curl -sL https://raw.githubusercontent.com/nipegun/df-scripts/refs/heads/main/DFIRWindows/Artefactos-MFT-Parsear.sh | bash -s [CarpetaDondeCrearLasSubCarpetas]
#
# Bajar y editar directamente el archivo en nano
#   curl -sL https://raw.githubusercontent.com/nipegun/df-scripts/refs/heads/main/DFIRWindows/Artefactos-MFT-Parsear.sh | nano -
# ----------

# Comprobar parámetro
if [ -z "$1" ]; then
  echo "Uso: $0 [CarpetaDondeCrearLasSubCarpetas]"
  exit 1
fi

cCarpetaDondeCrearLasSubCarpetas="$1"

# Crear subcarpetas
mkdir -p "$cCarpetaDondeCrearLasSubCarpetas/dat"
mkdir -p "$cCarpetaDondeCrearLasSubCarpetas/img"
mkdir -p "$cCarpetaDondeCrearLasSubCarpetas/vacb"
mkdir -p "$cCarpetaDondeCrearLasSubCarpetas/otros"

# Mover archivos según extensión
find "$cCarpetaDondeCrearLasSubCarpetas" -maxdepth 1 -type f -name '*.dat'  -exec mv -v {} "$cCarpetaDondeCrearLasSubCarpetas/dat/"  \;
find "$cCarpetaDondeCrearLasSubCarpetas" -maxdepth 1 -type f -name '*.img'  -exec mv -v {} "$cCarpetaDondeCrearLasSubCarpetas/img/"  \;
find "$cCarpetaDondeCrearLasSubCarpetas" -maxdepth 1 -type f -name '*.vacb' -exec mv -v {} "$cCarpetaDondeCrearLasSubCarpetas/vacb/" \;

# Cualquier otro archivo
find "$cCarpetaDondeCrearLasSubCarpetas" -maxdepth 1 -type f ! -name '*.dat' ! -name '*.img' ! -name '*.vacb' -exec mv -v {} "$cCarpetaDondeCrearLasSubCarpetas/otros/" \;

echo "Reubicación completada completada."

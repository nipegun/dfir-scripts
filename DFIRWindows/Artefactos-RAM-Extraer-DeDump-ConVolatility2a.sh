#!/bin/bash

# Pongo a disposición pública este script bajo el término de "software de dominio público".
# Puedes hacer lo que quieras con él porque es libre de verdad; no libre con condiciones como las licencias GNU y otras patrañas similares.
# Si se te llena la boca hablando de libertad entonces hazlo realmente libre.
# No tienes que aceptar ningún tipo de términos de uso o licencia para utilizarlo o modificarlo porque va sin CopyLeft.

# ----------
# Script de NiPeGun para parsear datos extraidos de la RAM de Windows en Debian
#
# Ejecución remota con parámetros:
#   curl -sL https://raw.githubusercontent.com/nipegun/df-scripts/refs/heads/main/DFIRWindows/Artefactos-RAM-Extraer-DeDump-ConVolatility2.sh | bash -s [RutaAlArchivoConDump]
#
# Bajar y editar directamente el archivo en nano
#   curl -sL https://raw.githubusercontent.com/nipegun/df-scripts/refs/heads/main/DFIRWindows/Artefactos-RAM-Extraer-DeDump-ConVolatility2.sh | nano -
#
# Más info aquí: https://github.com/volatilityfoundation/volatility/wiki/Command-Reference
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
    echo -e "    Ejemplo:"
    echo ""
    echo "    $0 /Casos/a2024m11d24/Dump/RAM.dump /Casos/a2024m11d24/Artefactos"
    echo ""
    exit 1
  fi

# Crear constantes para las carpetas
  cRutaAlArchivoDeDump="$1"
  cCarpetaDondeGuardar="$2"
  mkdir -p "$cCarpetaDondeGuardar"

# Calcular los posibles perfiles a aplicar al dump
  echo ""
  echo "  Calculando que perfiles se le pueden aplicar al dump..."
  echo ""
  vPerfilesSugeridos=$(vol.py -f "$cRutaAlArchivoDeDump" imageinfo | grep uggested | cut -d':' -f2 | sed 's-,--g' | sed "s- -\n-" | sed 's- -|-g' | sed 's-|- | -g')
  echo ""
  echo "    Se le pueden aplicar los siguientes perfiles:"
  echo "      $vPerfilesSugeridos"

# Guardar todos los perfiles en un archivo
  mkdir -p ~/volatility2/
  vol.py --info | grep "A Profile" | cut -d' ' -f1 > ~/volatility2/Volatility2-TodosLosPerfiles.txt
# Guardar los perfiles sugeridos en un archivo
  vol.py -f "$cRutaAlArchivoDeDump" imageinfo | grep uggested | cut -d':' -f2 | sed 's-,--g' | sed "s- -\n-" | sed 's- -|-g' | sed 's/|/\n/g' | sed 's-  --g' | sed 's- --g' | sed '/^$/d' > ~/volatility2/Volatility2-PerfilesSugeridos.txt
  sed -i '/^$/d' ~/volatility2/Volatility2-PerfilesSugeridos.txt
# Guardar todos los plugins en un archivo
  vol.py -h | sed "s-\t-|-g" | grep "^||" | sed 's-|--g' | cut -d' ' -f1 > ~/volatility2/Volatility2-Plugins.txt

# Obtener la versión correcta del sistema operativo
  while IFS= read -r vPerfil; do
    echo ""
    echo "  Intentando obtener la versión correcta del SO desde el registro usando el perfil $vPerfil..."
    echo ""
    vol.py -f "$cRutaAlArchivoDeDump" --profile="$vPerfil" printkey -K "Microsoft\\Windows NT\\CurrentVersion" | grep -a BuildLab
  done < ~/volatility2/Volatility2-PerfilesSugeridos.txt

# Parsear con todos los perfiles sugeridos
  while IFS= read -r vPerfil; do
    echo ""
    echo "  Parseando con el perfil $vPerfil..."
    echo ""
    # Aplicar todos los plugins
      while IFS= read -r vPlugin; do
        echo "    Aplicando el plugin $vPlugin..."
        vol.py -f "$cRutaAlArchivoDeDump" --profile="$vPerfil" "$vPlugin" > "$cCarpetaDondeGuardar"/"$vPerfil"-"$vPlugin".txt 2>/dev/null
      done < ~/volatility2/Volatility2-Plugins.txt
  done < ~/volatility2/Volatility2-PerfilesSugeridos.txt




#!/bin/bash

# Verifica se è stato fornito un argomento
if [ -z "$1" ]; then
  echo "Errore: è necessario fornire il nome del file come argomento."
  echo "Uso: $0 nome_del_file.md"
  exit 1
fi

# Assegna l'argomento a una variabile
FILE_NAME=$1

# Aggiungi tutti i file cambiati
git add .

# Commit con il messaggio che include il nome del file
git commit -m "$FILE_NAME aggiunto"

# Effettua il pull con rebase
git pull --rebase origin main

# Effettua il push
git push origin main

echo "Operazioni git completate con successo."

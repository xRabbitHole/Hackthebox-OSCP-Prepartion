#!/bin/bash

# Verifica se sono stati forniti argomenti
if [ $# -eq 0 ]; then
  echo "Errore: è necessario fornire almeno un nome di file come argomento."
  echo "Uso: $0 file1.md file2.md ..."
  exit 1
fi

# Crea una stringa con i nomi dei file separati da virgola per il messaggio di commit
FILES=""
for FILE in "$@"; do
  FILES="$FILES $FILE"
done

# Aggiungi tutti i file cambiati
git add .

# Commit con il messaggio che include i nomi dei file
git commit -m "Aggiunti file: $FILES"

# Effettua il pull con rebase
git pull --rebase origin main

# Effettua il push
git push origin main

echo "Operazioni git completate con successo."


# Extension Chrome PhishGuard Upload

Cette extension ajoute un bouton flottant sur les pages de webmail.

## Fonctionnement
1. Télécharge le mail au format `.eml` depuis ton webmail.
2. Clique sur **Analyser un .eml**.
3. Dépose le fichier dans le panneau.
4. L'extension l'envoie au backend `POST /analyze/file`.
5. Le backend analyse le mail et supprime le fichier temporaire à la fin.

## Installation
1. Ouvre `chrome://extensions`.
2. Active **Developer mode**.
3. Clique sur **Load unpacked**.
4. Sélectionne le dossier `extension/`.
5. Ouvre les options de l'extension et vérifie l'URL API : `http://127.0.0.1:8000`.

## Remarque
Le backend gère déjà la suppression du fichier temporaire côté serveur après analyse.

# Extension Chrome PhishGuard

Cette extension ajoute un petit panneau d'envoi sur certaines messageries web compatibles.
Elle n'analyse pas directement les emails dans le navigateur : elle envoie un fichier `.eml` ou `.msg` vers le backend local de PhishGuard.

## Principe d'utilisation

1. exporter un email depuis sa messagerie au format `.eml` ou `.msg` ;
2. ouvrir la messagerie web compatible ;
3. ouvrir le panneau PhishGuard ;
4. déposer le fichier ou le sélectionner ;
5. laisser l'extension l'envoyer au backend local ;
6. lire le verdict, le score et les raisons affichées.

## Fichiers acceptés

L'interface accepte actuellement :
- `.eml`
- `.msg`

## Ce que montre le panneau

- le verdict final ;
- le score ;
- le niveau de confiance ;
- plusieurs sous-scores ;
- les raisons principales.

## Hôtes pris en charge

L'extension est volontairement limitée à certains hôtes définis dans `manifest.json`, par exemple :
- Gmail ;
- Outlook Web ;
- Yahoo Mail ;
- Proton Mail.

Si l'on souhaite ajouter d'autres hôtes, il faut adapter `manifest.json` et tester explicitement le comportement.

## Installation

1. ouvrir `chrome://extensions` ;
2. activer le mode développeur ;
3. cliquer sur **Charger l'extension non empaquetée** ;
4. sélectionner le dossier `extension/` ;
5. lancer le backend local PhishGuard.

## Backend local

Exemple de lancement :

```bash
python -m uvicorn sources.api:app --reload
```

## Confidentialité et circulation des données

- l'extension envoie le fichier sélectionné au backend local ;
- elle n'envoie pas directement le mail à un service SaaS ;
- le backend peut, selon sa configuration, interroger certaines sources externes de réputation ;
- les fichiers temporaires utilisés pour l'analyse sont gérés côté backend.

## Limites

L'extension dépend de :
- la compatibilité du site web de messagerie ;
- le bon fonctionnement du backend local ;
- les permissions précisées dans `manifest.json`.


## Identité visuelle

Le dossier `icons/` contient les icônes de l'extension générées à partir du logo du projet.

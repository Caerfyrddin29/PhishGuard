# Nature du code, sources et usage de l'IA

## Degré de création originale

Le projet PhishGuard a été conçu, structuré, développé et documenté dans le cadre du travail de l'équipe composée de Myrddin Bellion et Ilyan Kassous.
L'architecture générale, l'organisation du code, la logique de traitement, les règles heuristiques et la documentation finale relèvent d'un travail de conception et d'intégration réalisé pour ce projet.

## Sources utilisées

Nous avons utilisé des bibliothèques Python externes pour des briques techniques standard. Les principales dépendances figurant dans `requirements.txt` et leur rôle sont les suivantes :
- `fastapi` : création de l'API locale ;
- `uvicorn` : lancement du serveur ASGI en local ;
- `pydantic` : validation et structuration des données ;
- `python-multipart` : gestion des fichiers envoyés à l'API ;
- `extract-msg` : lecture de fichiers email au format `.msg` ;
- `beautifulsoup4` : extraction et nettoyage de contenu HTML ;
- `python-whois` : récupération d'informations WHOIS pour certaines vérifications sur les domaines ;
- `joblib` : chargement du modèle de machine learning ;
- `scikit-learn` : utilisation du classifieur entraîné ;
- `pytest` : exécution des tests automatiques du projet.

Nous avons également consulté de la documentation technique pour comprendre :
- le format des emails et de leurs en-têtes ;
- le fonctionnement de FastAPI et d'Uvicorn ;
- la structure d'une extension Chrome ;
- les indicateurs courants d'un email de phishing.

Exemples de documentations consultées :
- documentation officielle de Python ;
- documentation officielle de FastAPI ;
- documentation officielle de Uvicorn ;
- documentation de `extract-msg` ;
- documentation de `python-whois` ;
- documentation développeur des extensions Chrome.

## Réutilisation éventuelle

Le projet n'est pas une copie d'une application existante. Il peut s'appuyer sur des bibliothèques standards, des conventions de développement et des exemples techniques courts consultés dans leur documentation officielle, mais la structuration du projet, l'intégration des modules et l'assemblage final ont été réalisés pour ce travail.

## Usage de l'intelligence artificielle

L'intelligence artificielle a été utilisée de manière limitée, réfléchie et relue.

Elle a surtout servi à :
- reformuler certains passages de documentation ;
- suggérer des améliorations de clarté dans certains textes ;
- aider à relire la conformité du dossier technique vis-à-vis du règlement.

L'IA n'a pas remplacé le travail de compréhension, de validation, de test ni les décisions techniques prises sur le projet.
Toutes les propositions conservées ont été relues, comprises, modifiées si nécessaire et validées par l'équipe.
L'IA n'aen aucun cas été utilisée pour écrire, générer ou modifier du code dans la structure du projet.

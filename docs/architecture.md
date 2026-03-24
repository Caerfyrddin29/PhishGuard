# Architecture de PhishGuard

## Vue d'ensemble

PhishGuard suit un pipeline d'analyse d'emails :
1. réception du fichier ;
2. extraction des informations utiles ;
3. passage dans plusieurs analyseurs spécialisés ;
4. combinaison des résultats ;
5. production d'un score, d'un verdict et d'explications.

## Fichiers principaux

### `main.py`
Point d'entrée principal du projet pour la ligne de commande.

### `api.py`
Définit l'API FastAPI, les modèles d'entrée et les endpoints de l'application.

### `cli.py`
Contient la logique de lancement en ligne de commande pour analyser directement un fichier email.

### `phishguard/parser.py`
Extrait les informations principales d'un email :
- sujet ;
- expéditeur ;
- en-têtes ;
- corps texte ;
- corps HTML ;
- liens ;
- pièces jointes.

### `phishguard/analyzers/`
Répertoire regroupant les modules d'analyse.

Exemples :
- `text_analyzer.py` : signaux textuels ;
- `header_analyzer.py` : cohérence des en-têtes ;
- `url_analyzer.py` : inspection des URLs ;
- `attachment_analyzer.py` : présence de pièces jointes à risque ;
- `domain_analyzer.py` : logique liée aux domaines ;
- `reputation_analyzer.py` : réputation de certaines ressources externes ;
- `hybrid.py` : combinaison finale des résultats.

### `extension/`
Contient l'extension navigateur destinée à envoyer un fichier exporté vers le backend local.

### `tests/`
Contient les scripts de tests automatiques du projet.

## Choix de conception

Nous avons choisi une organisation modulaire pour :
- séparer les responsabilités ;
- faciliter les tests ;
- rendre le code plus lisible ;
- permettre des améliorations progressives.

## Résultat attendu

Le projet renvoie un résultat structuré comprenant :
- les informations extraites ;
- un score ;
- un verdict ;
- un niveau de confiance ;
- des raisons détaillées.

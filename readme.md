# PhishGuard

PhishGuard est un projet de détection de mails de phishing.
Il permet d'analyser des emails exportés au format `.eml` ou `.msg` afin d'estimer s'ils sont légitimes, suspects ou clairement malveillants.

Le projet a été pensé comme un **outil local d'analyse et d'aide à la décision**. Il ne remplace pas une passerelle de messagerie professionnelle, mais il permet de comprendre rapidement pourquoi un email paraît risqué grâce à un verdict, un score et des raisons détaillées.

## À quoi sert le projet ?

Le phishing consiste à envoyer de faux emails qui imitent un service connu pour pousser une personne à cliquer sur un lien, ouvrir une pièce jointe ou transmettre des informations sensibles.

PhishGuard cherche à repérer ce type de message en combinant plusieurs analyses :
- étude du texte ;
- étude des en-têtes techniques ;
- étude des liens présents dans le message ;
- étude de certains indices de réputation ;
- prise en compte de signaux rassurants comme l'authentification ou la cohérence entre l'expéditeur et les liens.

## Fonctionnalités principales

- analyse de fichiers `.eml` et `.msg` ;
- API locale développée avec FastAPI ;
- documentation web interactive de l'API ;
- analyse par modules spécialisés ;
- verdict final parmi `legit`, `suspicious` et `phishing` ;
- affichage des raisons principales de la décision ;
- extension Chrome permettant d'envoyer un email exporté vers le backend local.

## Structure du dépôt

```text
.
├── sources/
│   ├── __init__.py
│   ├── main.py
│   ├── api.py
│   ├── cli.py
│   ├── phishguard/
│   └── extension/
├── test/
├── docs/
├── exemples/
├── presentation.md
├── readme.md
├── licence.txt
├── requirements.txt
└── pyproject.toml
```

Le code source du projet est regroupé dans le répertoire `sources/`, conformément à la nomenclature du règlement.
Le programme principal du projet Python est `sources/main.py`.

## Pré-requis

- Python **3.10 minimum** ;
- Python **3.11 ou plus récent recommandé** ;
- `pip` ;
- une connexion Internet peut améliorer certaines vérifications externes.

## Installation

### Sous Linux ou macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Sous Windows (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Lancement du projet

### Point d'entrée principal

Le point d'entrée principal demandé pour un projet Python est `sources/main.py`.

Afficher l'aide :

```bash
python -m sources.main --help
```

Analyser un fichier email :

```bash
python -m sources.main chemin/vers/message.eml
```

Version JSON :

```bash
python -m sources.main chemin/vers/message.eml --json
```

### Lancer l'API

```bash
python -m uvicorn sources.api:app --reload
```

Une fois l'API démarrée, ouvrir :
- `http://127.0.0.1:8000/docs` pour l'interface Swagger ;
- `http://127.0.0.1:8000/redoc` pour la documentation ReDoc.

## Endpoints principaux de l'API

| Méthode | Endpoint | Rôle |
|---|---|---|
| `GET` | `/health` | vérifie que l'API fonctionne |
| `POST` | `/analyze/file` | analyse un fichier `.eml` ou `.msg` |
| `POST` | `/analyze/raw-eml` | analyse un email brut envoyé en JSON |
| `POST` | `/analyze/base64-eml` | analyse un email encodé en base64 |
| `POST` | `/analyze/components` | analyse des composants d'email fournis séparément |
| `POST` | `/debug/parse` | retourne l'extraction sans verdict final |

## Utilisation rapide via l'interface web

1. lancer l'API ;
2. ouvrir `http://127.0.0.1:8000/docs` ;
3. choisir l'endpoint `/analyze/file` ;
4. cliquer sur **Try it out** ;
5. sélectionner un fichier `.eml` ou `.msg` ;
6. cliquer sur **Execute** ;
7. lire le verdict, le score et les raisons.

## Ce que renvoie l'analyse

La réponse contient généralement :
- les informations extraites du mail ;
- un score ;
- un verdict ;
- un niveau de confiance ;
- des sous-scores par module ;
- une liste de raisons détaillées.

Exemple de champs importants :
- `score` ;
- `verdict` ;
- `confidence` ;
- `reasons`.

## Comment fonctionne l'analyse

Le projet suit un pipeline simple :
1. lecture du fichier ;
2. extraction du sujet, des en-têtes, du corps, des URLs et des pièces jointes ;
3. passage dans plusieurs modules d'analyse ;
4. combinaison des résultats ;
5. production d'un verdict final.

Les principaux modules sont :
- `text_analyzer.py` : analyse du contenu textuel ;
- `header_analyzer.py` : analyse des en-têtes techniques ;
- `url_analyzer.py` : analyse des liens ;
- `domain_analyzer.py` : logique liée aux domaines ;
- `reputation_analyzer.py` : réputation de certaines URLs ou infrastructures ;
- `hybrid.py` : combinaison finale des résultats.

## Tests

Pour lancer les tests :

```bash
pytest -q
```

Si un plugin tiers installé dans l'environnement perturbe `pytest`, utiliser :

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -q
```

## Fichiers complémentaires

- `presentation.md` : présentation du projet pour le dossier technique ;
- `licence.txt` : licences du code et de la documentation ;
- `docs/architecture.md` : organisation du projet ;
- `docs/ia_et_sources.md` : nature du code, sources et usage de l'IA ;
- `exemples/` : éléments d'exemple et d'aide à la démonstration.

## Limites connues

- le projet reste heuristique ;
- un email légitime très chargé en liens peut parfois paraître suspect ;
- certaines vérifications externes dépendent du réseau ;
- l'absence d'un signal négatif ne garantit jamais qu'un message soit sûr.

## Licence

Le code source du projet est placé sous licence **GPL v3+**.
Les documents et textes du dossier sont placés sous licence **CC BY-SA**.

# PhishGuard - présentation du projet

## 1. Présentation globale du projet

PhishGuard est un projet de détection de mails de phishing. Le phishing est une forme de fraude qui consiste à envoyer des emails trompeurs afin d'inciter une personne à cliquer sur un lien, ouvrir une pièce jointe ou communiquer des informations sensibles.

Nous avons choisi ce sujet parce qu'il est actuel, concret et utile. Il nous permet de travailler à la fois la programmation, l'analyse logique, la structuration d'un projet et des notions de cybersécurité.

L'objectif du projet est d'analyser automatiquement un email afin de le classer comme légitime, suspect ou potentiellement malveillant. Nous avons aussi voulu que le résultat soit explicable, avec des raisons détaillées et pas seulement un score.

## 2. Organisation du travail

L'équipe est composée de :
- [À compléter : noms et prénoms des membres de l'équipe]

Répartition du travail :
- étude du problème et définition des objectifs ;
- parsing des emails et structuration générale du projet ;
- développement des différents modules d'analyse ;
- développement de l'API et de la documentation ;
- tests, calibration et préparation de la démonstration.

Temps passé sur le projet :
- recherche sur le phishing et définition du périmètre ;
- développement progressif du moteur ;
- tests sur plusieurs types d'emails ;
- amélioration de la précision ;
- rédaction de la documentation et préparation du dossier technique.

## 3. Étapes du projet

### Naissance de l'idée
Nous voulions réaliser un projet en cybersécurité, dans un domaine qui touche directement les utilisateurs. Le phishing nous a semblé particulièrement intéressant parce qu'il combine des aspects techniques et des mécanismes de manipulation.

### Première version
Nous avons d'abord conçu une version simple capable de lire un email et d'extraire ses éléments les plus importants : sujet, expéditeur, corps du message et liens.

### Amélioration progressive
Ensuite, nous avons séparé le projet en plusieurs modules spécialisés : analyse du texte, des en-têtes, des liens, des domaines et de la réputation. Nous avons également ajouté une API en FastAPI pour rendre le projet plus propre, plus réutilisable et plus facile à démontrer.

### Travail sur la calibration
Une étape importante a été la réduction des faux positifs. En effet, certains emails légitimes, comme des newsletters ou des reçus, ressemblent parfois à des messages suspects. Nous avons donc ajusté les règles pour mieux distinguer les cas réellement dangereux des emails simplement très riches en liens ou très marketing.

## 4. Validation du fonctionnement

Au moment du dépôt, le projet est fonctionnel.

Nous avons vérifié son fonctionnement grâce à :
- des tests automatiques ;
- des essais sur plusieurs fichiers email ;
- la vérification du lancement local du projet ;
- la vérification des endpoints de l'API ;
- la relecture de la documentation et du guide d'utilisation.

Nous avons testé le projet sur plusieurs catégories de messages :
- emails de phishing ;
- emails légitimes ;
- newsletters ;
- emails promotionnels ;
- messages contenant de nombreux liens.

## 5. Difficultés rencontrées et solutions apportées

Nous avons rencontré plusieurs difficultés :
- la grande variété des formats d'emails ;
- la complexité des en-têtes techniques ;
- le risque de faux positifs ;
- la nécessité de garder le projet compréhensible.

Pour y répondre, nous avons :
- amélioré le parser ;
- séparé les traitements en modules spécialisés ;
- rendu le verdict final plus explicable ;
- ajouté une documentation claire ;
- mis en place des tests et une démonstration reproductible.

## 6. Ouverture

Le projet peut encore être amélioré de plusieurs façons :
- enrichir le jeu de tests ;
- améliorer encore la calibration ;
- renforcer l'analyse de réputation ;
- développer une interface utilisateur plus poussée ;
- étendre les cas d'usage.

Ce projet nous a permis de développer des compétences en Python, en architecture logicielle, en API, en documentation, en tests et en cybersécurité.

## 7. Démarche d'inclusion

Nous avons essayé de répartir les tâches de manière équilibrée et de faire participer chaque membre à une partie technique réelle du projet. Nous avons aussi cherché à produire une documentation claire, afin que le projet soit compréhensible et réutilisable par d'autres élèves.

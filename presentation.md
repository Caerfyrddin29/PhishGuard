# PhishGuard - présentation du projet

## 1. Présentation globale du projet

PhishGuard est un projet de détection de mails de phishing. Le phishing est une forme de fraude qui consiste à envoyer des emails trompeurs afin d’inciter une personne à cliquer sur un lien, à ouvrir une pièce jointe ou à communiquer des informations sensibles.

Nous avons choisi ce sujet parce qu’il est actuel, concret et utile. Il nous permet de travailler à la fois la programmation, l’analyse logique, la structuration d’un projet, la cybersécurité et la fiabilité d’un outil informatique face à des cas réels.

L’objectif du projet est d’analyser automatiquement un email afin de le classer comme légitime, suspect ou potentiellement malveillant. Nous avons aussi voulu que le résultat soit explicable, avec des raisons détaillées, et pas seulement un score final. Ce choix a été important dès le départ, car nous ne voulions pas produire une “boîte noire”, mais un outil capable de justifier son verdict.

## 2. Organisation du travail

L’équipe est composée de :
- Myrddin Bellion ;
- Ilyan Kassous.

Répartition du travail :
- Myrddin Bellion : structuration générale du projet, extraction des données d’emails, modules d’analyse, calibration, tests et amélioration de l’explicabilité du verdict ;
- Ilyan Kassous : API locale, interface en ligne de commande, extension navigateur, documentation technique et préparation de la démonstration ;
- travail commun : définition du périmètre, choix techniques, relecture, validation finale, essais sur différents cas et préparation du dossier.

Temps passé sur le projet :
- environ 15 heures de recherche sur le phishing, le format des emails et le cadrage du sujet ;
- environ 30 heures de développement du moteur d’analyse, de l’extraction des données et des modules ;
- environ 10 heures pour l’API, l’extension, les tests et les essais sur plusieurs messages ;
- environ 8 heures pour la documentation, la préparation du dossier et de la démonstration.

## 3. Production du projet et progression

### Naissance de l’idée

Nous voulions réaliser un projet en cybersécurité, dans un domaine qui touche directement les utilisateurs et qui présente une réelle utilité. Le phishing nous a semblé particulièrement intéressant parce qu’il combine des aspects techniques et des mécanismes de manipulation.

Nous avons aussi choisi ce sujet parce qu’il permettait de produire un projet complet : lecture de fichiers, analyse de données, règles heuristiques, modularité, tests, interface locale et démonstration. Le thème était donc à la fois pertinent et suffisamment riche pour construire un véritable projet informatique.

### Première version du projet

Nous avons d’abord conçu une version simple capable de lire un email et d’en extraire le contenu principal. Cette première étape était déjà moins simple qu’elle n’en avait l’air, car un email n’est pas seulement un texte : il peut contenir des en-têtes techniques, du HTML, du texte brut, des liens, des pièces jointes, ou encore des structures différentes selon l’expéditeur.

Une première analyse textuelle, puis une première analyse des URL, ont ensuite été mises en place. Cette version initiale permettait de repérer certains éléments suspects, mais elle restait trop limitée. Elle donnait parfois des résultats peu fiables, car un mot alarmant ou un lien ne suffisent pas toujours à conclure qu’un message est malveillant.

### Première difficulté importante : la qualité des critères d’analyse

Nous avons rapidement constaté qu’un grand nombre d’emails légitimes pouvaient présenter des caractéristiques proches de celles d’un mail de phishing : présence de nombreux liens, ton incitatif, mise en page marketing, bouton d’action, urgence commerciale, etc.

Cette difficulté nous a obligés à revoir notre manière de concevoir le projet. Au lieu de reposer sur quelques signaux isolés, il fallait produire une analyse plus structurée, plus nuancée et fondée sur plusieurs indices combinés. C’est ce constat qui nous a conduits à concevoir une architecture modulaire.

### Tentative de vérification par base externe

Nous avons ensuite essayé d’utiliser une base de données servant de liste noire pour vérifier certains domaines et certaines URL. L’idée était pertinente sur le principe : comparer les liens trouvés dans les emails à des sources de réputation ou à des références déjà connues.

Cependant, cette approche a rapidement montré ses limites dans notre cadre de projet. D’une part, elle ralentissait fortement l’analyse, parfois jusqu’à plusieurs minutes pour de petits emails. D’autre part, elle rendait le fonctionnement plus dépendant de ressources externes et moins adapté à une démonstration simple, locale et reproductible.

Nous avons donc décidé de ne pas faire reposer le cœur du projet sur cette méthode. Cette étape n’a pas été inutile : elle nous a permis de comprendre qu’un bon projet n’est pas seulement un projet “plus ambitieux”, mais aussi un projet cohérent, maîtrisable et démontrable dans de bonnes conditions.

### Reprise du projet sur de meilleures bases

Après ces premiers essais, nous avons repris le projet de manière plus rigoureuse. Nous avons trouvé le projet *NightOwl* sur GitHub, créé par deFr0ggy, qui nous a aidés à mieux comprendre comment extraire proprement les données d’un fichier `.eml`. Cela nous a permis de mieux appréhender la structure réelle des emails et d’éviter certaines erreurs de lecture ou d’interprétation.

À partir de là, nous avons restructuré le projet pour le rendre plus clair, plus modulaire et plus évolutif. Nous avons séparé les traitements en plusieurs modules spécialisés :
- analyse du texte ;
- analyse des en-têtes ;
- analyse des liens ;
- analyse des domaines ;
- analyse de la réputation ;
- agrégation finale des résultats.

Cette progression a été déterminante. Elle nous a permis de passer d’un prototype assez simple à un projet plus proche d’un véritable outil d’analyse, dans lequel chaque partie a un rôle précis.

### Défis techniques rencontrés

Plusieurs défis techniques ont marqué la production du projet.

Le premier a été **l’extraction correcte des données**. Tous les emails n’ont pas la même structure, et il fallait être capable de récupérer des informations utiles sans rendre le projet fragile face à des formats variés.

Le deuxième a été **l’analyse des liens**. Un lien peut être trompeur de plusieurs façons : texte affiché différent de la destination réelle, domaine inhabituel, présence d’éléments suspects dans l’URL, ou encore usage de raccourcisseurs. Concevoir des règles pertinentes sans tomber dans l’excès a demandé de nombreux essais.

Le troisième a été **l’analyse des en-têtes techniques**. Les en-têtes d’un email contiennent des informations importantes, mais parfois difficiles à interpréter. Il fallait donc sélectionner des critères accessibles, utiles et exploitables dans le cadre de notre projet.

Le quatrième a été **la calibration du verdict final**. C’est probablement l’un des défis les plus importants du projet. Si les règles sont trop strictes, le projet génère trop de faux positifs. Si elles sont trop permissives, il laisse passer des mails suspects. Nous avons donc dû ajuster les pondérations, revoir certains seuils et rendre le verdict plus progressif.

Enfin, nous avons dû relever un défi de **lisibilité et d’explicabilité**. Un outil qui donne seulement une note finale n’est pas très utile pour comprendre le problème. Nous avons donc cherché à produire un résultat argumenté, avec des raisons détaillées, afin que l’utilisateur voie pourquoi un message a été classé d’une certaine manière.

### Éléments produits au fil du projet

Le projet final ne se limite pas à un simple script. Nous avons produit plusieurs composants complémentaires :
- un moteur d’analyse en Python ;
- un système d’extraction des données d’emails ;
- plusieurs modules spécialisés pour différents types d’indices ;
- un verdict final explicable ;
- une API locale en FastAPI ;
- une interface en ligne de commande ;
- une extension navigateur pour faciliter la démonstration ;
- des tests automatiques ;
- une documentation de lancement et d’utilisation.

Cette production progressive nous a permis d’améliorer à la fois la qualité technique du projet et sa présentation. Nous n’avons pas seulement cherché à “faire fonctionner” une idée : nous avons cherché à construire un ensemble cohérent, testable et démontrable.

## 4. Validation du fonctionnement

Au moment du dépôt, le projet est fonctionnel.

Nous avons vérifié son fonctionnement grâce à :
- des tests automatiques ;
- des essais sur plusieurs fichiers email ;
- la vérification du lancement local du projet ;
- la vérification des endpoints de l’API ;
- la relecture de la documentation et du guide d’utilisation.

Nous avons testé le projet sur plusieurs catégories de messages :
- des emails de phishing ;
- des emails légitimes ;
- des newsletters ;
- des emails promotionnels ;
- des messages contenant de nombreux liens.

Ces essais nous ont permis de vérifier que le projet était capable de produire un verdict cohérent, tout en donnant des explications compréhensibles sur les éléments détectés.

## 5. Difficultés rencontrées et solutions apportées

Nous avons rencontré plusieurs difficultés :
- l’extraction des données dans un mail ;
- la diversité des structures possibles ;
- l’analyse heuristique des liens, qui est techniquement complexe ;
- la difficulté d’interpréter certains en-têtes ;
- le risque de faux positifs ;
- la nécessité de garder le projet compréhensible, rapide et bien structuré.

Pour y répondre, nous avons :
- amélioré le module d’extraction ;
- abandonné certaines approches trop lourdes ou trop lentes ;
- séparé les traitements en modules spécialisés ;
- ajusté progressivement les règles de décision ;
- rendu le verdict final plus explicable ;
- ajouté une documentation claire ;
- mis en place des tests et une démonstration reproductible.

Une partie importante de notre travail a consisté à accepter que certaines idées intéressantes n’étaient pas adaptées à notre périmètre. Cela nous a permis de mieux cadrer le projet et de produire une version plus cohérente.

## 6. Pistes d’amélioration et limites actuelles

Le projet peut encore être amélioré de plusieurs façons :
- enrichir le jeu de tests ;
- améliorer encore la calibration ;
- renforcer l’analyse de réputation ;
- développer une interface utilisateur plus poussée ;
- étendre les cas d’usage ;
- mieux gérer certains cas complexes de structure d’emails ;
- intégrer davantage de sources de vérification externes.

Nous avons envisagé plusieurs améliorations plus ambitieuses, mais nous avons choisi de ne pas toutes les coder dans cette version pour des raisons précises.

Par exemple, une vérification plus poussée de la réputation des domaines et des URL aurait pu améliorer certains verdicts. Cependant, cela demandait soit des appels externes, soit des bases de données plus lourdes, ce qui augmentait le temps d’analyse, la complexité du projet et la dépendance à des ressources extérieures. Nous avons préféré conserver un outil plus simple à lancer, plus stable et plus facile à démontrer.

Nous avons aussi envisagé une interface plus complète, voire une récupération plus automatisée des emails, mais cela aurait déplacé une partie importante du travail vers l’ergonomie ou l’intégration, alors que notre priorité était d’abord la qualité du moteur d’analyse lui-même.

De même, il serait possible d’intégrer des méthodes plus avancées, par exemple des approches statistiques ou d’apprentissage automatique. Nous avons néanmoins choisi de rester sur des règles explicables, car elles sont plus lisibles, plus faciles à justifier et plus adaptées à un projet que nous voulions maîtriser de bout en bout.

Ces pistes d’amélioration sont donc réelles et pertinentes, mais elles n’ont pas été retenues dans cette version finale afin de conserver un projet cohérent, compréhensible, testable et compatible avec le temps dont nous disposions.

## 7. Ce que le projet nous a appris

Ce projet nous a permis de développer des compétences en Python, en architecture logicielle, en modularité, en API, en tests, en documentation et en cybersécurité.

Il nous a aussi appris qu’un projet technique ne consiste pas seulement à ajouter des fonctionnalités. Il faut également savoir choisir un périmètre réaliste, identifier les limites d’une solution, corriger ses erreurs de conception initiales et améliorer progressivement l’existant.

Nous avons ainsi appris à produire un projet plus structuré, plus argumenté et plus robuste, tout en restant attentifs à la clarté du résultat final.

## 8. Démarche d’inclusion

Nous avons essayé de répartir les tâches de manière équilibrée et de faire participer chaque membre à une partie technique réelle du projet. Nous avons aussi cherché à produire une documentation claire, afin que le projet soit compréhensible et réutilisable par d’autres élèves.

Nous avons enfin veillé à garder un projet accessible dans sa prise en main, avec une organisation lisible, des explications détaillées et une démonstration simple à suivre.
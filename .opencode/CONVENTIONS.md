# Conventions du Projet - opencode

## 🌐 Langues et Communication

### 1. Code et Documentation
**Tout le code et la documentation doivent être rédigés en anglais**, incluant :
- Commentaires de code et Docstrings
- Noms de fonctions et variables
- Messages de commit et README
- Logs et messages d'erreur

### 2. Conversation (Chat)
**Utilise toujours le français pour les conversations** avec le propriétaire du projet. Utilise le **tutoiement** ("tu").

**Ton et Style :**
Adopte un ton **cynique et bienveillant**, légèrement moqueur mais sans jugement. Reste neutre et objectif. Utilise une ironie prononcée et des observations perspicaces pour remettre en question les prémisses, sans être condescendant. Tes réponses doivent être directes, avec une pointe d'humour cynique qui souligne les absurdités ou contradictions.

---

## 🛠 Normes de Qualité du Code

### 3. Documentation du Code
Commente ton code de manière exhaustive :
- **Classes** : Docstrings complets (but, attributs, usage).
- **Fonctions** : Docstrings complets (description, paramètres avec types, retours, exceptions, exemples).

### 4. Lisibilité et Standards
- Utilise les versions stables les plus récentes des packages.
- Priorise la lisibilité : noms significatifs, fonctions courtes, éviter l'imbrication profonde.
- Utilise le typage (Type Hints en Python, etc.).

---

## 📝 Standards de Logging et Fichiers

### 5. Logging (Python)
- Utilise `coloredlogs` pour les projets Python.
- Utilise tous les niveaux de log appropriés (`DEBUG` à `CRITICAL`).

### 6. Conformité POSIX
- Chaque fichier texte doit se terminer par une nouvelle ligne (`\n`).
- Encodage UTF-8 et fins de ligne Unix (LF).

---

## 🔒 Sécurité

### 7. Gestion des Secrets
**NE JAMAIS committer de credentials ou secrets** :
- Utilise des variables d'environnement ou des fichiers `.env` (ajoutés au `.gitignore`).
- Vérifie tes commits avant de pousser.

---

## 📑 Standards README
Suis le format moderne :
1. Header avec badges (shields.io)
2. Description d'une ligne
3. Diagramme Mermaid (flowchart TB)
4. Table des fonctionnalités (avec emojis)
5. Section Installation (Docker & local)
6. Section Configuration (YAML & env vars)
7. Tables de commandes
8. Licence et Crédits

---

## 🌿 Git et Workflow

### 8. Messages de Commit (Conventional Commits)
Format : `<type>[scope]: <description>`
Types : `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`.
Utilise l'impératif en anglais (ex: "add" au lieu de "added").

### 9. Workflow Git Worktree
- **Ne travaille jamais directement sur la branche principale.**
- Crée toujours un worktree dédié dans `.worktrees/<branch-name>`.
- Utilise la skill `superpowers/using-git-worktrees` pour gérer cela.
- **Rappel obligatoire** : Chaque réponse doit se terminer par `📂 Worktree actif : <chemin>`.

---

## 🐍 Environnement Python
- Utilise exclusivement des environnements virtuels isolés.
- **Utilise `uv`** comme outil principal de gestion de packages et d'environnements.

---

## 🤖 Instructions spécifiques pour opencode

### Correspondance des outils
Lorsqu'un skill ou une instruction mentionne des outils Claude Code :
- `TodoWrite` → utiliser le système de plan interne ou `update_plan` (si disponible via plugin).
- `Task` avec subagents → utiliser la syntaxe `@mention`.
- `Skill` tool → utiliser le tool natif `skill` d'opencode.
- Opérations de fichiers → utiliser les tools natifs (`read`, `write`, `edit`).

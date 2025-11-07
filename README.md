# Realtime List (local)

## Lancer le projet

- Prérequis: Node.js 18+, npm
- Installation
  - `npm install`
  - Optionnel (init DB) : `npm run init:db`
  - Copier `.env.example` en `.env` et ajuster `APP_SECRET`
- Démarrer
  - `npm start`
  - Ouvrir `http://localhost:3000` dans deux onglets

## Architecture logique

- Serveur HTTP Express sert les fichiers statiques
- WebSocket (ws) pour la synchro bidirectionnelle
- SQLite (better-sqlite3) pour persistance locale
- Auth simple:
  - inscription/connexion via `/api/register` et `/api/login`
  - mot de passe haché `scrypt` avec sel
  - token de session signé HMAC, stocké en base et côté client (localStorage)
- Échange d’événements:
  - `auth`, `snapshot`, `added`, `edited`, `deleted`, `presence`, `ping/pong`, `error`
- Monitoring:
  - compteur de connexions actives
  - latence estimée (RTT applicatif)
  - logs côté client
  - endpoint `/api/housekeeping` pour purger les sessions expirées

## Plan de sécurité

- Règles implémentées:
  - Limitation d’actions par connexion (rate-limit 6 actions / 3s)
  - Validation/sanitisation du contenu (pas de balises, longueur max 280)
  - Autorisations: édition/suppression limitées au propriétaire de l’item
- Sessions:
  - token signé HMAC avec `exp` contrôlé et persistance en base
  - nettoyage des sessions expirées
- Défenses additionnelles possibles:
  - quotas par IP
  - liste d’autorisation stricte pour origin et headers
  - séparation des rôles (admin/lecteur)
  - journaux serveur + rotation

## Gestion des erreurs

- Côté serveur: réponses JSON `{ error }` et messages WS `{ type: 'error', error }`
- Côté client: logs visibles et non bloquants, reconnection automatique
- Scénarios gérés:
  - token invalide/expiré
  - id invalide / ressource inexistante
  - dépassement de rate-limit

## Limites et améliorations

- Stockage utilisateurs et items minimaliste (pas de recherche, pas d’index texte)
- Pas de CRDT avancé (on reste sur last-write appliqué côté serveur)
- Pas de chiffrement TLS (contexte local). À sécuriser derrière un reverse proxy pour prod
- Idées d’améliorations:
  - Backplane pub/sub si multi-process (Redis)
  - Historique et audit trail
  - CRDT type LWW-element-set ou RGA pour édition concurrente de texte
  - UI plus riche et filtres

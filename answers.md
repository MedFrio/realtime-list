# answers.md

## Question 1 – Services cloud temps réel
a) Deux services managés hors WebSocket natif
- Firebase Realtime Database
- Ably (ou Pusher)

b) Comparaison
- Modèle de données  
  Firebase RTDB: arbre JSON hiérarchique.  
  Ably: canaux pub/sub avec messages typés, pas de store de documents intégré.
- Persistance  
  Firebase: stockage persistant managé (lecture/écriture avec règles).  
  Ably: messages éphémères par défaut, historique optionnel selon plan; pas de base documents.
- Mode d'écoute  
  Firebase: listeners par chemin (on("value", "child_added", etc.)).  
  Ably: abonnement par channel et eventName, wildcards possibles.
- Scalabilité  
  Firebase: sharding et réplication gérés par Google, limites par “hot path”.  
  Ably: maillage global de brokers, fan-out massif, QoS et backpressure.

c) Cas d'usage préféré
- Firebase: listes partagées avec persistance forte et règles d'accès par document/chemin.  
- Ably: diffusion d'événements temps réel à fort fan-out (notifications, positions, dashboards live) sans gérer le stockage.

## Question 2 – Sécurité temps réel
a) Trois risques et parades
- DDoS via connexions persistantes  
  Limiter connexions par IP, quotas/surge protection, timeouts, backpressure, rate-limit applicatif.
- Injection de contenu (XSS, SQLi via champs)  
  Validation/sanitisation côté serveur, requêtes préparées, encodage à l'affichage.
- Détournement d'identité/session hijacking  
  Tokens courts signés, rotation, origin checking, SameSite/HttpOnly si cookies, contrôle des permissions à chaque action.

b) Importance de la gestion des identités  
L'identité conditionne les permissions temps réel (qui publie, qui modifie). Sans identité fiable, pas de traçabilité ni d'isolation des droits; c'est central pour limiter la propagation rapide d'actions malicieuses sur des canaux persistants.

## Question 3 – WebSockets vs Webhooks
a) Définitions  
- WebSocket: canal bidirectionnel full-duplex persistant entre client et serveur.  
- Webhook: callback HTTP sortant envoyé par un service A vers un endpoint HTTP public de B lorsqu'un événement survient.

b) Avantages / limites  
- WebSocket  
  Avantages: latence très faible; bidirectionnel en continu.  
  Limites: gestion de l'état/scale plus complexe; traversée réseau/proxies parfois délicate.
- Webhook  
  Avantages: simple à intégrer; découplage fort (push server-to-server).  
  Limites: pas bidirectionnel ni streaming; nécessite endpoint public fiable et sécurisé.
  
c) Quand préférer un Webhook  
Lorsqu'un service serveur-to-serveur doit notifier ponctuellement des événements à un consommateur sans session ouverte ni client connecté en continu.

## Question 4 – CRDT & Collaboration
a) Définition  
Un CRDT est une structure de données répliquée dont les opérations sont commutatives/associatives et convergent sans coordination globale, même avec latences et partitions.

b) Exemple concret  
Éditeur collaboratif de liste/todo où plusieurs utilisateurs ajoutent/suppriment des éléments hors-ligne puis se resynchronisent sans conflits.

c) Pourquoi pas de conflits  
Les CRDT définissent des règles de merge mathématiques (ex. horloges logiques, LWW, G-Counter) garantissant la convergence déterministe de tous les réplicas.

## Question 5 – Monitoring temps réel
a) Trois métriques clés  
- Nombre de connexions actives et taux de churn  
- Latence E2E/ping et variance  
- Taux d'erreurs/invalidations par type d'événement

b) Rôle de Prometheus/Grafana  
Prometheus scrape des métriques structurées et permet alerting/queries; Grafana visualise en temps réel et corrèle avec logs/événements.

c) Différence logs, traces, métriques  
- Logs: événements textuels horodatés.  
- Traces: parcours distribués corrélés d'une requête.  
- Métriques: valeurs numériques agrégées dans le temps.

## Question 6 – Déploiement & Connexions persistantes
a) Impact WebSockets  
- Load balancing: nécessité de sticky sessions ou d'un répartiteur L7 compatible WS; sinon partage d'état (pub/sub) entre nœuds.  
- Scalabilité: penser fan-out, backplane (Redis/NATS), et limites de fd/epoll.

b) Pourquoi Kubernetes  
Orchestre scaling horizontal, rolling updates, health probes, et offre des primitives réseau (Services/Ingress) adaptées aux WS avec tolérance aux pannes.

## Question 7 – Stratégies de résilience client
a) Trois mécanismes  
- Reconnexion automatique avec backoff et jitter  
- Buffer local/queue des actions offline et re-play à la reconnexion  
- Détection de liveness (pong timeouts) et bascule d'état UI

b) Exponential backoff  
Allonger progressivement l'intervalle entre tentatives (ex. 0.5s, 1s, 2s, 4s…) avec plafonnement et jitter pour éviter les “thundering herds”.

# Guida a PerspectiveGraph (italiano)

Guida pratica e **autosufficiente** per **installare da zero, avviare, spegnere,
usare e mettere in sicurezza** PerspectiveGraph: pensata per chi **non ha mai
visto** il codice né lo stack. Percorso consigliato per un neofita:

1. **[§3 Installazione da zero](#3-installazione-da-zero)** - strumenti + scaricare il codice.
2. **[§4 Avvio](#4-avvio-e-spegnimento)** + **[§4 → seed](#opzione-a--tutto-in-docker-consigliata)** - stack su, dati demo, dashboard.
3. **[§9 Sicurezza, autenticazione e firme](#9-sicurezza-autenticazione-e-firme-guida-completa)** - **come fare chiamate con token e firma HMAC** (la sezione chiave per chi automatizza l'API/ingest).

Per il dettaglio "come alimentarlo da un'infrastruttura reale" vedi anche
[ONBOARDING.md](./ONBOARDING.md) (in inglese); per l'architettura interna
[ARCHITECTURE.md](../ARCHITECTURE.md).

---

## 1. Cos'è (in 60 secondi)

PerspectiveGraph **non è uno scanner**. Non analizza la tua infrastruttura e non
installa agenti. È un **motore di correlazione**: prende l'output degli strumenti
di sicurezza che **già usi** (Trivy, Semgrep, Cloud Custodian, Falco) più alcune
sorgenti di *discovery* (Kubernetes, rete cloud, IAM), li unisce in **un unico
grafo** e risponde alla domanda che un elenco piatto di CVE non sa rispondere:

> *"Partendo da ciò che è esposto su internet, quali **percorsi di attacco
> realmente percorribili** portano ai miei asset critici (i 'gioielli della
> corona'), e quali sono i più pericolosi?"*

Il risultato sono **attack path** ordinati per rischio, con - per ciascuno - la
remediation pronta all'uso, le regole di detection e il contesto di minaccia
(exploit noti in the wild, conferma a runtime).

**A chi serve:** team DevSecOps, security architect, chi fa threat modeling o
deve dimostrare a un auditor *dove* è il rischio reale, non solo *quante* CVE ci
sono.

---

## 2. Concetti chiave

| Concetto | Significato |
|---|---|
| **Grafo** | Asset, identità e vulnerabilità diventano **nodi**; le relazioni (espone, instrada, sfrutta, assume, può-scalare-a…) diventano **archi** orientati. |
| **`internet_exposed`** (seed) | Un nodo è un **punto di ingresso**: da qui un attaccante può partire (es. un Load Balancer con `0.0.0.0/0`). |
| **`crown_jewel`** (target) | Un nodo è un **bersaglio di valore**: un DB con PII, un bucket sensibile, un ruolo IAM admin. |
| **Attack path** | Una catena `seed → … → crown jewel` effettivamente percorribile nel grafo. |
| **Score `S(P)`** | Probabilità che il percorso sia sfruttabile = **prodotto** delle probabilità dei suoi archi. In dashboard è la **percentuale** accanto al percorso. |
| **Choke point** | Un arco condiviso da molti percorsi: tagliarlo elimina più rischio con un solo intervento. |

Senza **almeno un seed e almeno un crown jewel collegati tra loro**, non compare
nessun attack path: è il comportamento corretto (vedi §10 Troubleshooting).

---

## 3. Installazione da zero

Pensata per chi **non ha mai visto** né il codice né lo stack. Due strade: se è la
prima volta, usa la **A (Docker)** - non devi installare Go né Node, basta Docker.

### 3.1 Strumenti da installare

| Strumento | Serve per | Come installarlo |
|---|---|---|
| **Git** | scaricare il codice | macOS: `xcode-select --install` · Ubuntu/Debian: `sudo apt install git` · Windows: [Git for Windows](https://git-scm.com/download/win) |
| **Docker Desktop** (con Compose v2) | avviare l'intero stack con un comando | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) - installalo, **avvialo e lascialo aperto** |
| `curl`, `jq`, `openssl` | chiamate API, leggere JSON, **firmare le richieste (HMAC)** | macOS/Linux: già presenti (eventualmente `brew install jq` / `sudo apt install jq`). `openssl` è quasi sempre preinstallato. |
| *(solo per il loop di sviluppo sull'host)* **Go 1.25+** e **Node 22+** | compilare backend e frontend nativi | [go.dev/dl](https://go.dev/dl/) · [nodejs.org](https://nodejs.org/) |
| *(opzionale)* `make`, `newman` | scorciatoie ai comandi e test della collection Postman | `make` di solito c'è già; `npm i -g newman` |

Verifica che l'essenziale risponda:

```bash
docker --version && docker compose version      # Docker + Compose v2
git --version && curl --version | head -1 && openssl version
```

> **Windows:** lavora dentro **WSL2** (Ubuntu) con Docker Desktop in modalità WSL2.
> Tutti i comandi di questa guida sono `bash`/`zsh` e funzionano lì senza modifiche.

### 3.2 Scaricare il codice

```bash
git clone <URL-DEL-REPO> perspectivegraph     # oppure scompatta lo zip ricevuto
cd perspectivegraph
```

**Tutti i comandi di questa guida si lanciano dalla radice del progetto** (la
cartella che contiene `Makefile`, `docker-compose.yml` e le sottocartelle
`backend/` e `frontend/`).

### 3.3 Riepilogo dei prerequisiti

- **Via Docker (consigliata):** solo Docker Desktop con Docker Compose v2.
- **Senza Docker (dev sull'host):** Go 1.25+, Node 22+, e comunque Docker per la
  sola infrastruttura (Postgres+AGE e NATS).
- Per gli esempi da terminale e per **le chiamate autenticate/firmate** (§9):
  `curl`, `jq`, `openssl`.

---

## 4. Avvio e spegnimento

### Opzione A - Tutto in Docker (consigliata)

Un solo comando costruisce e avvia **infrastruttura + backend + dashboard**:

```bash
make up-full          # = docker compose --profile app up -d --build
```

Quando i container sono `healthy` (≈ 30-60 s):

- **Dashboard:** http://localhost:3000
- **API GraphQL / playground:** http://localhost:8080/graphql
- **Webhook di ingest (per il seeding):** http://localhost:8081

Carica i dati demo e apri la dashboard:

```bash
make seed             # 6 sorgenti che correlano in attack path
make seed-discovery   # (opzionale) topologia K8s + rete cloud + grafo privesc IAM
open http://localhost:3000      # macOS (Linux: xdg-open)
```

**Stato e log:**

```bash
docker compose --profile app ps                 # stato dei container
docker compose logs -f backend                  # log del backend in tempo reale
```

**Spegnere:**

```bash
make down                       # ferma e rimuove i container (i DATI restano)
```

> I dati del grafo vivono in un volume Docker (`perspective-pgdata`) e
> **sopravvivono** a `make down`. Per ripartire da zero (grafo vuoto):
> ```bash
> docker compose --profile app down -v     # -v cancella anche il volume dati
> make up-full && make seed                # ricrea e riempie
> ```

**Variante con ricerca full-text (OpenSearch):**

```bash
docker compose --profile app --profile search up -d --build
# poi imposta OPENSEARCH_URL=http://opensearch:9200 nel file .env (vedi §9)
```

### Opzione B - Senza Docker (loop di sviluppo sull'host)

Utile per chi modifica il codice. L'infrastruttura resta in Docker; backend e
frontend girano nativi.

```bash
# 1. Solo l'infrastruttura (Postgres+AGE, NATS)
make up                # oppure make up-search per aggiungere OpenSearch

# 2. Backend Go (in un terminale) - API su :8080, ingest su :8081
make run-backend

# 3. Frontend (in un altro terminale) - Vite dev server su :5173
make run-frontend

# 4. Dati demo
make seed
```

Dashboard su **http://localhost:5173** (in questa modalità, non :3000).

**Spegnere:** `Ctrl-C` su backend e frontend, poi `make down` per l'infra.

### Porte (tutte su `127.0.0.1`, mai esposte alla rete)

| Servizio | Porta | Note |
|---|---|---|
| Dashboard (Docker) | **3000** | nginx, fa da proxy a `/graphql` |
| Dashboard (host dev) | **5173** | Vite dev server |
| API GraphQL / BFF | **8080** | `/graphql`, `/healthz`, `/export/*`, `/suppressions`, `/tickets`, `/metrics` |
| Webhook di ingest | **8081** | dove le sorgenti fanno POST |
| Postgres + Apache AGE | 5432 | il grafo |
| NATS (client / monitor) | 4222 / 8222 | event bus |
| OpenSearch (opzionale) | 9200 | indice full-text |

```bash
docker compose exec postgres psql -U perspective -d perspectivegraph
```

```bash
dentro psql
\dn                  -- schemi: ag_catalog | perspective | public
\dt perspective.*    -- le tabelle del grafo (una per label nodo + una per tipo arco)
\dt public.*         -- tabelle "normali" (qui praticamente vuoto)
\d perspective."CVE" -- struttura di una label-table
\q                   -- esci
```

```bash
LOAD 'age';
SET search_path = ag_catalog, public;

-- tutti i nodi (id + nome)
SELECT * FROM cypher('perspective',
  $$ MATCH (n) RETURN n.id, n.name, label(n) $$)
  AS (id agtype, name agtype, label agtype);

-- gli archi
SELECT * FROM cypher('perspective',
  $$ MATCH (a)-[e]->(b) RETURN a.name, type(e), b.name $$)
  AS (from_n agtype, type agtype, to_n agtype);
```
---

## 5. La dashboard, spiegata

> 💡 **Aiuto integrato.** Al primo avvio la Overview mostra il riquadro **"How to
> read this dashboard"** che spiega il modello 🌐 ingresso → 💎 bersaglio (lo
> richiami quando vuoi dal pulsante **"ⓘ How to read this"** in alto). Ogni metrica
> ha una **ⓘ**: passaci sopra il mouse per la spiegazione in linguaggio semplice.

In alto a destra c'è il selettore **Application**: lascialo su *All applications*
per la vista d'ambiente, oppure scegli un'applicazione (repo/tag) per restringere
percorsi e grafo a quella. Accanto, il pulsante **☀️/🌙 commuta tema chiaro/scuro**:
la scelta è ricordata (localStorage) e al primo avvio segue l'impostazione del
sistema operativo; anche il grafo dell'ambiente si ri-colora di conseguenza. Menu a
sinistra: 6 viste. Su **schermi stretti** (tablet/telefono) il menu laterale diventa
un cassetto: aprilo col pulsante ☰ in alto a sinistra.

### 5.1 Overview ("Security posture")

Le **card** in alto riassumono la postura:

| Card | Cosa significa |
|---|---|
| **Critical paths** | Numero di attack path `internet → crown jewel` percorribili adesso. Rosso = > 0. |
| **Account compromise** | Quantificazione **Monte Carlo**: probabilità che **almeno un** gioiello venga compromesso, e numero atteso di gioielli che "cadono". È più della somma dei singoli percorsi perché tiene conto dei percorsi multipli che condividono archi. |
| **Runtime-confirmed** | Percorsi che attraversano un nodo con un **alert Falco attivo**: non solo teorici, ma in corso di sfruttamento. |
| **KEV on paths** | CVE distinte presenti sui percorsi che sono nel catalogo **CISA KEV** (sfruttate in the wild). |
| **Policy violations** | Invarianti architetturali violate (es. *internet → crown jewel diretto*). |
| **Assets & findings** | Numero di **nodi** del grafo. |
| **Relationships** | Numero di **archi** del grafo. |

Sotto le card: il banner delle **violazioni di policy**, il banner del **piano di
remediation** (*"N fix eliminano X% del rischio"*) e l'elenco dei **Top attack
path**. Ogni riga mostra: numero, `sorgente → gioiello`, **percentuale** (lo
score `S(P)`), numero di hop e la **kill chain** per categoria di nodo
(`LoadBalancer → Container → Image → …`). Il fulmine ⚡ segnala i percorsi
runtime-confirmed (ordinati per primi). Clicca una riga per il dettaglio.

### 5.2 Attack paths (dettaglio di un percorso)

Per ogni percorso selezionato vedi:

- la **catena passo-passo**, con il **tipo di arco** di ogni hop (es. `EXPOSES`,
  `AFFECTS`, `EXPLOITS`, `CAN_ESCALATE_TO`), la sua probabilità e la **tecnica
  MITRE ATT&CK** corrispondente (badge `T1190 · Initial Access`, cliccabile →
  pagina ATT&CK): così il percorso si legge come una *kill chain* riconoscibile.
  La stessa tecnica compare anche sulle frecce del percorso evidenziato nel grafo;
- le **Remediation** generate: artefatti pronti (Kubernetes **NetworkPolicy** o
  **Terraform**) che **tagliano un arco** del percorso, con la motivazione - incluse
  le regole per la **privilege-escalation IAM** (`CAN_ESCALATE_TO` → policy di
  *deny*) e il **lateral movement cloud** (`CONNECTS_TO` → segmentazione SG);
- il **what-if**: passa il mouse su un hop della kill chain e premi **"what-if"**
  per simulare il taglio di quell'arco - vedi subito il rischio residuo (es.
  *account compromise 100% → 99.9%, 11 percorsi restano*);
- le **Detection-as-code**: regole **Falco** e **Sigma** che *rilevano* lo
  sfruttamento del percorso (delimitate per container/namespace, con la CVE e il
  gioiello). La remediation chiude il percorso, la detection lo sorveglia.

In alto a destra trovi i pulsanti **↓ OSCAL** e **↓ SIEM** per scaricare gli export
(documento di compliance NIST OSCAL e feed di arricchimento NDJSON per il SIEM).

### 5.3 Remediation plan ("choke points first")

La maggior parte dei percorsi condivide pochi archi. Questo piano è un
**set-cover greedy**: ordina gli interventi così che i primi siano i **pochi fix
che neutralizzano più rischio** (`coveragePct`), ciascuno con l'artefatto pronto
e l'eventuale residuo da rivedere a mano. È la risposta a *"se ho tempo per due
fix, quali due?"*.

#### 5.3.1 Nel flusso dev: PR-check (gate) e remediation-as-PR

Un finding cambia qualcosa solo se arriva a chi può sistemarlo, dove già lavora.
Con un solo `GITHUB_TOKEN` (dry-run finché non lo imposti) PerspectiveGraph si
innesta nella PR:

- **Commento PR** sul cambiamento che sta su un path critico (kill chain + fix);
- **Gate di merge**: uno *status* GitHub `perspectivegraph/attack-paths` che
  diventa **rosso** quando il cambiamento apre un path internet→gioiello, e
  **verde** quando non lo apre più. Rendendolo uno *status check obbligatorio*
  nella branch protection, **blocca il merge** - shift-left, non un commento da
  scrollare;
- **Remediation-as-PR**: `POST /remediation/pr` (o il bottone **"Open fix PR"** sul
  dettaglio del path) crea un branch, committa il fix generato (NetworkPolicy /
  Terraform / policy IAM) e apre una **pull request** da revisionare e mergiare -
  non più copia-incolla.

Tutto è instradato dal contesto-PR che l'analizzatore già porta sui nodi
(`repo_slug` / `pr_number` / `commit_sha`). Su GitHub Enterprise: `GITHUB_API_URL`.

### 5.4 Environment graph

Il grafo completo (Cytoscape), leggibile come un diagramma d'architettura.
**Forma + colore** del nodo ne indicano la categoria:

| Categoria | Colore / forma | Etichette (label dei nodi) |
|---|---|---|
| **Infrastructure** | blu, rettangolo | `VirtualMachine`, `Container`, `VPC`, `LoadBalancer` |
| **Data store** | oro, barile | `Database`, `Bucket` |
| **Code & artifacts** | verde acqua, esagono | `Repository`, `Image`, `Package`, `Library` |
| **Identity** | grigio, ellisse | `User`, `IAM_Role`, `ServiceAccount` |
| **Finding** | rosso, rombo | `CVE`, `Weakness`, `Misconfiguration`, `Secret` |

Gli **anelli** attorno ai nodi marcano lo stato: verde = *entry* (internet-exposed),
oro = *target* (crown jewel), arancione = *runtime-confirmed* (live). La legenda in
basso a sinistra li riepiloga.

### 5.5 Policy violations

Le **invarianti architetturali** che l'ambiente attuale rompe (forme di grafo
vietate, es. *internet → segreto*, *internet → crown jewel*). Sono regole "non
deve mai esistere un percorso così", utili come guardrail per gli architetti.

### 5.6 Search

Ricerca full-text su asset e finding indicizzati. **Richiede OpenSearch** attivo
(profilo `search` + `OPENSEARCH_URL`); senza, restituisce vuoto.

### 5.7 AI assistant (Claude o HuggingFace)

Con una chiave AI impostata, la dashboard mostra una voce **"AI assistant"**
e tre funzioni (di default alimentate da Claude, `claude-opus-4-8`):

- **Q&A in linguaggio naturale** sul grafo (es. *"quale path internet-exposed
  raggiunge i dati PII più in fretta?"*);
- **Executive summary** della postura, pronto per il board;
- **"Explain (AI)"** sul dettaglio di un path: spiegazione in chiaro di come un
  attaccante lo percorre e qual è il fix più efficace.

Ogni risposta è **ancorata** ai tuoi attack path reali (il modello riceve un
contesto compatto e limitato - riassume i tuoi dati, non li inventa). Il trasporto
è una chiamata **hand-rolled** (nessun SDK, zero dipendenze).

**Due provider, scelti dalla credenziale impostata:**

```bash
# 1) Anthropic (Claude) - preferito
ANTHROPIC_API_KEY=sk-ant-...       # abilita /ai/* e l'assistente nella dashboard
# (opzionali) ANTHROPIC_MODEL, ANTHROPIC_BASE_URL, AI_MAX_TOKENS

# 2) HuggingFace - gratuito, usato SOLO se ANTHROPIC_API_KEY è vuota.
#    HF_TOKEN è un access token (gratuito) di huggingface.co; usa lo schema
#    OpenAI-compatible, quindi HF_BASE_URL può puntare anche a Together/Groq/Ollama.
HF_TOKEN=hf_...
# (opzionali) HF_MODEL (default meta-llama/Llama-3.1-8B-Instruct), HF_BASE_URL

curl -s http://localhost:8080/ai/summary
curl -s -X POST http://localhost:8080/ai/query   -d '{"question":"cosa è più a rischio?"}'
curl -s -X POST http://localhost:8080/ai/explain -d '{"pathId":"<un id da attackPaths>"}'
```

> **Trust boundary.** Il grafo è la mappa di come attaccare l'org: inviarne una
> vista compatta a un modello esterno è una scelta deliberata. La feature è
> **spenta** finché non imposti la chiave, e **ogni chiamata AI è auditata**
> (`ai.query`/`ai.summary`/`ai.explain`) nello stesso log a prova di manomissione
> delle altre letture.

---

## 6. Provarlo sul TUO progetto

La demo "funziona" perché i dati di esempio sono coerenti. Per usarlo sui tuoi
dati reali servono tre cose (la guida completa è in [ONBOARDING.md](./ONBOARDING.md)):

**1) Invia gli output dei tuoi scanner** all'endpoint di ingest. Esempi:

```bash
export INGEST_URL=http://localhost:8081

# Trivy (CVE di dipendenze/immagini)
trivy image --format json my-image:tag > trivy.json
curl -sS -X POST "$INGEST_URL/ingest/trivy?slug=acme/my-repo" \
  -H 'Content-Type: application/json' --data-binary @trivy.json

# Kubernetes (topologia di esposizione, auto-discovery)
kubectl get ingress,service,pod,serviceaccount,role,clusterrole,rolebinding,clusterrolebinding \
  -A -o json > cluster.json
curl -sS -X POST "$INGEST_URL/ingest/k8s" \
  -H 'Content-Type: application/json' --data-binary @cluster.json

# IAM (grafo di privilege-escalation, "BloodHound for cloud") - solo lettura
aws iam get-account-authorization-details > iam.json
curl -sS -X POST "$INGEST_URL/ingest/iam" \
  -H 'Content-Type: application/json' --data-binary @iam.json

# Supply-chain (firma cosign + SLSA + SBOM) - un'immagine non firmata e
# raggiungibile da internet viola "no-internet-to-unsigned-image"
syft "$IMG" -o cyclonedx-json > sbom.json
cosign verify "$IMG" >/dev/null 2>&1 && S=true || S=false
curl -sS -X POST "$INGEST_URL/ingest/supplychain" -H 'Content-Type: application/json' \
  -d '{"image":"'"$IMG"'","signed":'"$S"',"slsa_level":3,"sbom":'"$(cat sbom.json)"'}'

# SSO / federazione identità (Okta → cloud) - l'utente senza MFA che federa in un
# ruolo admin apre "internet → Okta → utente → admin cloud"
curl -sS -X POST "$INGEST_URL/ingest/sso" -H 'Content-Type: application/json' -d '{
  "provider":"okta","users":[{"email":"alice@acme.com","mfa":false,
    "federated_roles":["arn:aws:iam::123456789012:role/admin-role"]}]}'
```

Sorgenti disponibili: `trivy`, `semgrep`, `custodian`, `falco`, `build` (CI
provenance), `k8s` (RBAC profonda **+ container-escape**), `cloudnet`, `iam`,
`supplychain`, `sso`, `dataclass` (classificazione dati Macie/DLP).
Tutte idempotenti: ri-postare è sicuro.

**2) Marca seed e gioielli.** I percorsi compaiono solo se esistono entrambi:
- `internet_exposed` arriva da Custodian (ALB `internet-facing`, IP pubblici),
  dalla rete cloud (`0.0.0.0/0`) o da un ruolo IAM con trust `Principal: *`;
- `crown_jewel` arriva dai **tag** delle tue risorse (es.
  `classification=pii`, oppure il letterale `crown-jewel=true`). Tagga i tuoi
  data store sensibili: è ciò che li rende bersagli.

**3) Allinea gli identificatori.** Usa lo **stesso riferimento immagine** in
Trivy / build provenance / Falco, e lo stesso nome repo in Semgrep, così i nodi
si deduplicano e i percorsi si "cuciono" da soli.

> Dopo l'ingest, attendi un ciclo dell'analizzatore (`ANALYZER_INTERVAL`, default
> **30 s**) e ricarica la dashboard.

### 6.1 Connettori agentless (PULL, senza upload)

Le sorgenti sopra arrivano in **push**: qualcuno deve fare POST di un report. I
**connettori** ribaltano la cosa: raggiungono *loro* un sistema esterno a
intervalli e ne tirano lo stato - nessun agente da installare, nessuno che si
deve ricordare di caricare un file. È il modello *"colleghi un ruolo in sola
lettura e vedi i tuoi attack path in minuti"*.

Un connettore pubblica sullo **stesso bus** dei webhook, quindi riusa l'intera
pipeline (risoluzione identità, grafo, analizzatore): cambia solo l'acquisizione.
Il primo connettore, **`aws`**, non aggiunge nemmeno parsing - tira lo stato di
rete EC2 (`describe-*`) e i dettagli IAM e li passa ai collector `cloudnet`/`iam`
esistenti. L'acquisizione è dietro un *transport* sostituibile: **`fixtures`**
(JSON locale, prova tutta la pull **senza credenziali**) e **`aws-sdk-go-v2`** per
AWS reale (sola lettura, `AssumeRole` cross-account opzionale).

```bash
# Demo senza account AWS: tira dai sample locali, ogni 15m (leader-only)
CONNECTORS_ENABLED=aws
AWS_CONNECTOR_MODE=fixtures
AWS_FIXTURES_DIR=./backend/testdata
# Salute per-connettore (ultima run, ultimo errore, eventi): porta di ingest
curl -s http://localhost:8081/connectors | jq

# Live (sola lettura): assume un ruolo cross-account e tira EC2 + IAM
CONNECTORS_ENABLED=aws
AWS_CONNECTOR_MODE=sdk
AWS_REGION=us-east-1
AWS_ROLE_ARN=arn:aws:iam::<account>:role/perspectivegraph-readonly
# permessi minimi sul ruolo: ec2:Describe*, iam:GetAccountAuthorizationDetails
# (≈ policy gestite SecurityAudit / ViewOnlyAccess). Catena credenziali standard
# (env / profilo / IRSA / instance role) se non imposti AWS_ROLE_ARN.
```

Connettori **leader-only** (le repliche non moltiplicano le chiamate API),
cadenza `CONNECTOR_INTERVAL`, osservabili via `GET /connectors` e metriche
`perspectivegraph_connector_*`. Vuoti di default (`CONNECTORS_ENABLED=`):
l'ingestione resta push-only finché non li accendi.

---

## 7. Funzionalità avanzate (via API GraphQL ed export)

Oltre alla dashboard, l'API espone analisi "da architetto". Esempi su
http://localhost:8080/graphql (playground attivo quando l'auth è disattivata).

> Se hai **attivato l'auth** (§9), aggiungi a ogni chiamata l'header
> `-H "Authorization: Bearer $PG_TOKEN"`; le scritture (suppression/ticket/
> validation) richiedono un token **admin**. Gli esempi qui sotto li omettono per
> brevità.

```graphql
# Rischio quantificato (Monte Carlo) per ciascun gioiello, con intervallo di confidenza
{ riskSimulation(iterations: 5000) {
    anyCompromiseProbability expectedCompromised
    crownJewels { name compromiseProbability ciLow ciHigh } } }

# Top-K percorsi verso un gioiello (algoritmo di Yen)
{ kShortestPaths(target: "customers-db (PII)", k: 5) { score nodes { name } } }

# What-if: "se taglio questo arco, quanto scende il rischio?"
{ whatIf(cuts: [{from: "public-deployer", to: "account-admin (effective)", type: "CAN_ESCALATE_TO"}]) {
    removedEdges riskReduction afterRisk { anyCompromiseProbability } } }

# Ogni percorso espone anche lo stato di triage e la provenienza delle correlazioni
{ attackPaths { id suppressed suppression { reason owner expiresAt }
    nodes { name resolutionMethod resolutionConfidence } } }

# Dimensione temporale: trend dell'esposizione, MTTR, "da quanto è aperto" e regressioni
{ history { openPaths resolvedPaths mttrSeconds oldestOpenSince
    trend { at criticalPaths riskPct } } }
{ attackPaths { id openForSeconds reopens } }   # età del path + flag regressione

# Provenienza/confidence delle probabilità (perché "58%?")
# scoreUpperBound + correlatedHops = onestà sull'assunzione di indipendenza:
# lo score è il prodotto degli hop (indipendenti); se condividono una causa la
# probabilità reale sta in [score, scoreUpperBound] (= l'hop più debole).
# scoreCiLow/High = intervallo credibile al 90% (incertezza epistemica, posteriori Beta).
# mixtureScore/profileScores = score marginalizzato sui profili d'attaccante (commodity/criminal/apt).
{ attackPaths { id score scoreUpperBound correlatedHops scoreCiLow scoreCiHigh
    mixtureScore profileScores { profile prior score }
    confidence confidenceLabel steps { edgeType probability weightBasis weightConfidence } } }

# Triage: i "5 da fixare oggi" - i path tornano già ordinati per priorità (P1 first)
{ attackPaths(limit: 5) { priority priorityLabel priorityFactors score runtimeConfirmed
    nodes { name } } }

# Azione a ciclo chiuso: remediation VERIFICATA (what-if) + ticket con owner
{ remediationPlan { title coveragePct
    verification { verified pathsEliminated riskReductionPct } } }
{ attackPaths { id ticket { id owner status } } }   # ticket aperto sul path
```

**Validazione red-team / BAS (REST):** registra il verdetto su un percorso -
`confirmed` (sfruttabile end-to-end), `refuted` (falso positivo), `partial`, o
`missed` (un percorso reale che il motore NON ha trovato). Da qui escono
**precision** = confirmed/(confirmed+refuted) e **recall** = confirmed/(confirmed+missed),
sul sottoinsieme *testato* (non una pretesa globale). Dalla dashboard: **✓ Validate**
sul percorso; card **Validation** in Overview. `make seed-validation` registra
verdetti d'esempio.

```bash
curl -s -X POST http://localhost:8080/validations -H 'Content-Type: application/json' \
  -d '{"pathId":"ap-1a2b-3c4d","outcome":"confirmed","source":"caldera","evidence":"atomic T1190"}'
curl -s http://localhost:8080/validations | jq .metrics    # precision / recall
{ validation { precision recall confirmed refuted missed tested } }   # anche via GraphQL
```

**Calibrazione (il salto demo→produzione):** precision/recall dicono se un percorso
*emerso* era reale; la **calibrazione** chiede se il *numero* significa qualcosa - i
percorsi con score ~0.8 si confermano davvero ~80% delle volte? Ogni verdetto cattura
**lo score predetto `S(P)` al momento del test** (lato server, così il tester non può
falsarlo): il registro dei verdetti diventa un dataset di calibrazione. Da qui escono
**Brier** e **ECE** (errori di calibrazione, più bassi = meglio), un **reliability
diagram** (predetto vs osservato per bucket; punti sulla diagonale = perfettamente
calibrato), un **verdetto** (well-calibrated / overconfident / underconfident) e un
fattore di **riscalatura consigliato** (`osservato/predetto`, *solo indicativo* - non
applicato in automatico, perché ricalibrare su pochi campioni significa inseguire il
rumore). È l'artefatto che permette di difendere un "55%" come *probabilità* davanti a
un auditor. In dashboard: pannello **Calibration** in Overview.

```bash
curl -s http://localhost:8080/validations | jq .calibration   # brier, ece, verdict, bins
{ calibration { samples brier ece verdict bins { low meanPredicted observedRate } } }  # via GraphQL
```

**Diagnostici di calibrazione ("e quindi cosa costruisco?"):** sapere di essere
mistarati non basta - bisogna sapere *perché*, per non costruire il fix sbagliato. Il
report aggiunge tre lenti sugli stessi verdetti e le fonde in una **diagnosi**:
(1) **ricalibrazione** isotonica → `brierRecalibrated` = il Brier che una semplice
riscalatura può raggiungere, più una `recalibrationMap` (grezzo → calibrato) che un
consumer applica *out-of-band* (il motore non riscrive mai gli score in silenzio); se
resta alto, al modello manca *risoluzione* e nessuna riscalatura lo salva.
(2) **segmenti** - calibrazione divisa per struttura del path (`correlated`/`independent`,
`long`/`short`); l'errore concentrato su path correlati/lunghi è *strutturale* → modello
correlation-aware (**#6**). (3) **detection** - su un verdetto `confirmed` l'operatore può
segnare `detected` (preso/bloccato); un alto tasso di cattura sui path ad alto score
significa che lo score sovrastima la compromissione *non rilevata* → asse detection
(**#7**). La `diagnosis` finale è `recalibrate-first | structural (#6) | detection-axis
(#7) | low-resolution`: si costruisce #6/#7 **solo** quando i verdetti reali lo provano.
Se la diagnosi indica il #6, `make and-probe` (il tool `andprobe`) risponde alla
domanda che *decide* un Bayesian Attack Graph: l'ambiente ha vera **semantica AND**
(una compromissione che richiede più prerequisiti insieme) o è pura OR-reachability
che il Monte Carlo già modella? Conta i nodi su path critici con archi entranti di
categorie eterogenee - è un *euristico di upper-bound* (un grafo puro non distingue
AND da OR: è ciò che il BAG aggiunge), quindi nomina candidati che i tuoi verdetti
`refuted` devono confermare. Vicino a zero → il #6 è un no-op, migliora invece `p(e)`.
La semantica AND è una proprietà della **topologia**, non delle CVE: dagli topologia
*reale* con `make ingest-k8s`, che snapshotta il tuo context `kubectl` corrente
(il collector accetta `kubectl get ingress,service,pod,sa,rbac -A -o json` → archi di
esposizione/privesc/escape). Punta `kubectl` a un **kind + kubernetes-goat** locale
per un cluster volutamente vulnerabile; poi `make and-probe`. Un cluster lockato (es. il
Docker Desktop di default) dà zero candidati AND - che è già la risposta.

```bash
# Registra se un tentativo confermato è stato rilevato (per l'asse detection #7):
curl -s -X POST http://localhost:8080/validations -H 'Content-Type: application/json' \
  -d '{"pathId":"ap-1a2b-3c4d","outcome":"confirmed","source":"caldera","detected":true}'
curl -s http://localhost:8080/validations | jq '.calibration | {verdict,brier_recalibrated,diagnosis,segments,detection}'
```

**Self-test senza infrastruttura reale:** non serve un ambiente volutamente
vulnerabile per *esercitare e testare lo strumento*. `make calibration-selftest
SCENARIO=...` (il sottocomando `genverdicts`) genera verdetti da una **realtà nota
che controlli tu** e verifica che la diagnosi indichi la causa giusta - come un test
d'integrazione di un sistema di calibrazione. Valida lo *strumento*, **non** gli score
del motore contro il mondo reale (quello richiede verdetti veri):

```bash
make calibration-selftest SCENARIO=overconfident   # → "recalibrate-first"
make calibration-selftest SCENARIO=correlated      # → "structural (#6)"
make calibration-selftest SCENARIO=low-resolution  # → "low-resolution"
make calibration-selftest SCENARIO=detection       # → "detection-axis (#7)"
# scenari: calibrated | overconfident | underconfident | correlated | low-resolution | detection
```

Ogni scenario inietta un difetto specifico e il gate deve nominarlo - così il tool
semina la dashboard *e* dimostra che i diagnostici distinguono davvero #6 da #7. (I
verdetti sintetici portano le proprie feature di calibrazione; per un path *live* lo
score catturato lato server vince sempre, quindi un tester reale non può falsarlo.)

**Calibrazione come programma, non istantanea:** il `brierRecalibrated` è ora
**cross-validato** (k-fold, out-of-sample: non overfitta proprio quando i dati sono
pochi, cioè il caso reale); il report porta `persistent` e la UI segnala un dataset
`in-memory` (imposta `VALIDATIONS_PATH`, o a ogni riavvio perdi i verdetti di un
ingaggio reale); e un **trend di calibrazione** (Brier/ECE/campioni campionati a ogni
pass dell'analyzer) compare in Overview come sparkline "Brier over time", per vedere
l'evidenza accumularsi e gli score migliorare nel tempo.

**Il ponte ai verdetti *reali* (BAS bridge):** quando lasci i dati sintetici, punti il
motore a un **target volutamente vulnerabile** (CloudGoat via il connettore AWS, un
OWASP Juice Shop locale, un pentest manuale - tutto su infra *tua*/sandbox, autorizzata)
e riporti gli esiti con zero integrazione. `make import-verdicts FILE=report.json` (il
sottocomando `importverdicts`) legge un report d'attacco **agnostico dallo strumento** e
mappa ogni finding su un path live tramite il **target** (nome del gioiello) + un
eventuale ingresso (o un `pathId` esplicito), così un tester dice *"ho confermato un
path verso account-admin"* senza conoscere gli id interni. `outcome` ∈
confirmed/refuted/partial/missed, più `detected` per l'asse #7. Chiude il loop sul
reale: **target vulnerabile → ingest (connettore AWS `fixtures`/`sdk`, o uno scanner) →
path live → BAS → `import-verdicts` → calibrazione**; con `VALIDATIONS_PATH` i verdetti
di un ingaggio persistono.

**Reale a costo zero in ~15 minuti (Trivy → log4shell):** nessuna spesa cloud, solo un
target locale davvero sfruttabile. `make ingest-real IMAGE=<img>` (il sottocomando
`ingestreal`) scansiona un'immagine vulnerabile con **Trivy** (CVE/CVSS reali; KEV/EPSS
reali con `THREATINTEL=on`) e inietta la topologia minima così la CVE sta *sul* path
internet → gioiello:

```bash
git clone https://github.com/vulhub/vulhub && cd vulhub/log4j/CVE-2021-44228 && docker compose up -d
make ingest-real IMAGE=<immagine vulhub>   # → internet-lb → image → log4j-core → CVE-2021-44228 → crown-jewel
# ...sfrutti il target per davvero, poi registri il verdetto:
make import-verdicts FILE=mio-report.json  # {"target":"secrets-vault","outcome":"confirmed"}
```

La CVE, la sua severità e KEV/EPSS sono **reali** (solo la topologia di deployment è
modellata - usa il collector `k8s` su un cluster locale per rendere reale anche quella).

**Ticketing (REST):** apri un ticket *con owner* su un percorso e chiudilo quando
è risolto (dalla dashboard: **Create ticket** / **close**). Un solo ticket
aperto per percorso.

```bash
curl -s -X POST http://localhost:8080/tickets -H 'Content-Type: application/json' \
  -d '{"pathId":"ap-1a2b-3c4d","owner":"secops@acme"}'
curl -s http://localhost:8080/tickets                          # la board dei ticket
curl -s -X POST http://localhost:8080/tickets/tk-abc123/close   # chiudi (lavoro fatto)
```

**Triage / soppressione (REST):** togli dalla "board attiva" un percorso che hai
già valutato - `accept-risk`, `false-positive`, `mitigating-control` o
`duplicate` - con un **owner responsabile** e una **scadenza** opzionale (dopo la
quale il percorso torna automaticamente attivo). Nella dashboard: **⊘ suppress /
triage** sul percorso e il toggle **Show suppressed** nella lista.

```bash
# Sopprimi un percorso (ruolo admin se l'auth è attiva); pathId = attackPaths { id }
curl -s -X POST http://localhost:8080/suppressions -H 'Content-Type: application/json' -d '{
  "pathId": "ap-1a2b-3c4d", "reason": "mitigating-control",
  "owner": "secops@acme", "note": "Bloccato dal WAF", "ttlDays": 30 }'
curl -s http://localhost:8080/suppressions                       # la board di triage (incl. scaduti)
curl -s -X DELETE http://localhost:8080/suppressions/ap-1a2b-3c4d  # riattiva il percorso
```

Imposta `SUPPRESSIONS_PATH` per rendere le decisioni persistenti (altrimenti
restano solo in memoria). La soppressione è una decisione *di vista*: non
modifica il grafo né il `riskSimulation`, ma l'Overview conta i percorsi
**attivi** separandoli dai soppressi.

**Export per altri strumenti:**

```bash
curl -s http://localhost:8080/export/ndjson > enrichment.ndjson   # arricchimento per SIEM (Splunk/Elastic/Sentinel)
curl -s http://localhost:8080/export/oscal  > oscal.json          # assessment-results NIST OSCAL per GRC/auditor
```

Una **collection Postman** pronta è in
[`perspectivegraph.postman_collection.json`](./perspectivegraph.postman_collection.json)
(importala in Postman, oppure: `newman run docs/perspectivegraph.postman_collection.json`).

Altre funzioni opzionali (vedi `.env.example`): **threat intel KEV+EPSS**
(`THREATINTEL=on`), **drift alerting** verso Slack/SOAR, **audit log**
tamper-evident, **multi-tenancy**.

---

## 8. Cosa significano i dati (riferimento rapido)

- **Percentuale di un percorso** = `S(P)` = prodotto delle probabilità degli
  archi = quanto è verosimile che quel percorso sia sfruttabile end-to-end.
- **Tipi di arco** più importanti: `EXPOSES`/`ROUTES_TO` (esposizione di rete),
  `AFFECTS`/`EXPLOITS` (vulnerabilità), `ASSUMES`/`HAS_PERMISSION` (identità),
  **`CAN_ESCALATE_TO`** (privilege escalation IAM verso l'admin dell'account),
  `CONNECTS_TO` (raggiungibilità di rete).
- **`account-admin (effective)`** è un nodo **sintetico**: rappresenta il
  controllo totale dell'account, bersaglio delle catene di privesc IAM.
- **KEV** = la CVE è confermata sfruttata in the wild (catalogo CISA). **EPSS** =
  probabilità stimata di sfruttamento a 30 giorni (FIRST). Insieme ri-pesano gli
  archi così che lo score rifletta lo sfruttamento *reale*, non solo la severità.
  > **Caveat sugli input (proprio ciò che la calibrazione serve a far emergere):**
  > EPSS è una probabilità *marginale* - P(qualsiasi attività di exploitation in 30gg)
  > - non la P(un attaccante attraversa *questo* arco in *questo* ambiente) che serve
  > allo score. È un base rate globale (di solito basso), quindi usarlo come `p(e)`
  > tende a *sottostimare* un attaccante presente. Lo passiamo così com'è di proposito
  > e lasciamo che il loop di calibrazione riveli/corregga il bias sui verdetti reali,
  > invece di trasformarlo a naso; anche gli ancoraggi `severity → p` (0.9/0.7/0.4/0.2)
  > sono euristiche, per questo portano basi a bassa confidence.
- **SSO / federazione (Okta → cloud)** - l'IdP è un nodo `IdentityProvider`
  internet-facing; `AUTHENTICATES → User → ASSUMES → IAM_Role`. I ruoli federati
  (per ARN) convergono col grafo IAM, quindi un utente **senza MFA** verso un
  ruolo admin/escalation accende *internet → Okta → utente → admin cloud* (hop
  senza-MFA pesato come facilmente phishabile).
- **RBAC K8s profonda** - oltre ai ruoli wildcard/"admin", un ruolo con una
  primitiva di escalation (`create pods`, `read secrets`, `bind`/`escalate`,
  `impersonate`, token SA) traccia `CAN_ESCALATE_TO` verso un **cluster-admin**
  sintetico (BloodHound-for-K8s).
- **Subject Group/User nei binding** - un `(Cluster)RoleBinding` il cui subject e
  un **Group** o **User** (non solo `ServiceAccount`) concede comunque il ruolo ai
  workload che copre. I gruppi serviceaccount di sistema si espandono ai pod reali:
  `system:serviceaccounts:<ns>` alle SA di quel namespace, `system:serviceaccounts`/
  `system:authenticated` a ogni SA; `system:unauthenticated`/`system:anonymous`
  lega il ruolo a un **principal anonimo internet-exposed** (nessuna credenziale);
  un gruppo/utente nominato (es. OIDC, senza membership visibile nel cluster) viene
  registrato come principal a se, cosi la concessione resta visibile. Cosi
  *internet → pod → SA (via binding di gruppo) → cluster-admin* emerge, dove la
  vista solo-ServiceAccount non disegnava alcun arco (era un falso negativo reale).
- **Container escape** - un pod che rompe il confine col nodo (container
  `privileged`, una **capability Linux pericolosa aggiunta** - `SYS_ADMIN`/
  `SYS_MODULE`/`SYS_PTRACE`/`SYS_RAWIO`/`SYS_BOOT`/`DAC_READ_SEARCH`/`DAC_OVERRIDE`/
  `BPF`, o `ALL`, equivalenti a privileged secondo CISA/NSA anche senza
  `privileged:true` -, mount `hostPath`, `hostPID`/`hostNetwork`/`hostIPC`) traccia
  `ESCAPES_TO` verso il cluster-admin: *internet → pod privileged → host → presa
  del cluster* diventa un attack path di primo livello, mappato ad **ATT&CK
  T1611 (Escape to Host)**, distinto dalla privesc RBAC.
- **Crown jewel: classificazione vs euristica** - un data store classificato da
  un **classificatore reale** (Macie/DLP via `POST /ingest/dataclass`, oppure una
  tag-policy) diventa gioiello con `crown_jewel_basis="classified:<source>:<kind>"`
  (badge **"crown jewel (classified)"** + chip della classe, es. `pii`) -
  autorevole. In assenza, l'euristica di nome (pii/customer/payment/…) marca
  `inferred:<segnale>` (badge "inferred"). Un **tag esplicito** dell'owner vince
  sempre su entrambi.
- **Supply-chain (firma / SLSA / SBOM)** - ogni immagine porta `signed`
  (verifica cosign), `slsaLevel` e `sbomComponents`; i componenti dell'SBOM
  diventano nodi `Library`/`Package` con arco `DEPENDS_ON`. Un'immagine **non
  firmata** raggiungibile da internet è un vettore di manomissione: scatta
  l'invariante `no-internet-to-unsigned-image` (vista Violations) e in kill chain
  l'immagine è marcata **⚠ unsigned**. `signed` assente = "non valutata" (≠ non
  firmata, nessuna violazione).
- **Provenienza delle probabilità (onestà, non falsa precisione)** - ogni arco
  dichiara *da dove* viene il suo peso: `kev`/`epss`/`runtime` (evidenza) vs
  `cvss`/`severity`/`heuristic` (stima). In kill chain ogni hop ha un chip
  (verde = evidenza, grigio = "assumed"), e il path porta una **confidence**
  (`high`/`medium`/`low`): la risposta onesta a "perché 58%?" - *"58%, low
  confidence, poggia su euristiche di severità"* - invece di un numero finto-preciso.
- **Indipendenza degli hop (banda di score)** - lo score `∏p` assume gli hop
  **indipendenti**; quando condividono una causa comune (una debolezza che apre
  più passi) il prodotto *sottostima*. Ogni path espone perciò `scoreUpperBound`
  (= l'hop più debole `min p`, lo score se gli hop fossero perfettamente
  correlati) e il flag `correlatedHops` (≥2 hop sullo stesso `weightBasis`): la
  probabilità reale sta in **`[score, scoreUpperBound]`** e la UI mostra *"↑ fino a
  X% se correlati"* invece di spacciare il punto come esatto.
- **Incertezza epistemica (intervallo credibile)** - domanda diversa: non *"gli
  hop sono correlati?"* ma *"quanto conosciamo ogni `p`?"*. Ogni arco è una
  **posteriore Beta** la cui ampiezza dipende dall'evidenza (stretta per
  kev/runtime, larga per un'euristica), propagata nel prodotto fino a un
  **intervallo credibile al 90%** sullo score (`scoreCiLow`/`scoreCiHigh`, in UI
  *"90% CI 39-71%"*). Le stesse posteriori guidano il Monte Carlo: al posto del
  vecchio ±30% piatto, la banda *"modeled X-Y%"* è ora un ciclo esterno che
  ricampiona ogni arco dalla sua posteriore. I valori puntuali non cambiano - si
  quantifica solo quanto fidarsi (`uncertainty.go`, sampler Marsaglia-Tsang, zero
  dipendenze).
- **Profili d'attaccante (la correzione dell'indipendenza)** - il prodotto `∏p`
  sbaglia perché i passi sono correlati attraverso una variabile latente: la
  *capacità dell'attaccante*. Lo score viene perciò marginalizzato su un insieme di
  **profili** (commodity / criminal / apt), ognuno con un priore `P(c)` e una skill
  che sposta gli odds di ogni hop in base a quanto quel passo dipende davvero
  dall'abilità (poco per un exploit KEV pubblico, molto per un'euristica):
  `S(P) = Σ P(c)·∏ p(e|c)`. *Dentro* un profilo l'indipendenza è onesta;
  *marginalizzando* rientra la correlazione che il prodotto perde. In UI ogni path
  mostra il breakdown *"72% vs APT, 18% vs commodity"* + il valore `blended`. I
  priori si ritarano sul proprio threat model con `ATTACKER_PROFILE_PRIORS`; lo
  `score` ingenuo resta come baseline indipendente. Anche la **reliability headline**
  (`riskSimulation`) è ora marginalizzata allo stesso modo (`mixtureCompromiseProbability
  = Σ_c P(c)·R_c` + `profileCompromise`, riga "compromise by attacker profile" in
  Overview), così il numero d'ambiente e gli score per-path condividono **un solo
  modello di correlazione** invece del Monte Carlo che assumeva archi indipendenti.
- **Priorità di triage (cosa fixare prima)** - lo score dice *quanto è facile*, non
  *quanto deve importarti*. Ogni path porta una **priorità composita** 0–100
  (banda **P1/P2/P3**) che fonde: sfruttabilità + confidenza, conferma **runtime**
  (Falco), presenza di una **KEV** sul percorso, **sensibilità del bersaglio**
  (gioiello classificato > taggato > inferito) e **blast radius** dell'entry. I path
  tornano **ordinati per priorità**, quindi `attackPaths(limit:5)` *è* la lista "da
  fixare oggi", e ogni priorità è **spiegabile** (porta i `priorityFactors`: es.
  "runtime-confirmed (active)", "KEV on path", "classified PII target"). Effetto: un
  path **runtime-confirmed verso PII al 36%** supera uno **non corroborato al 90%**.
  Chip P1/P2/P3 + pill dei fattori nella UI; pesi e soglie documentati e regolabili.
- **Igiene dei dati: niente segreti nel grafo** - l'output degli scanner può
  contenere una **credenziale viva** (una chiave AWS hardcoded in uno snippet
  Semgrep, un token su una command line Falco). Il grafo è una mappa di *come
  attaccare l'org*, quindi non deve mai diventare un magazzino di segreti: all'
  ingest i pattern ad alta precisione (token AWS/GitHub/Slack/Google, chiavi
  private PEM, JWT, assegnazioni `secret=…`) sono **redatti dai valori delle
  proprietà** prima dello store - il finding resta (*"chiave AWS hardcoded in
  `config.py:7`"*), il valore diventa `***redacted:<kind>***` e il nodo è marcato
  `secrets_scrubbed` (badge "secret scrubbed"). Gli identificatori (id, nome, SHA,
  digest, ref) non si toccano mai. Attivo di default (`SCRUB_INGEST`); la
  retention dei finding scrubbati è governata da `GRAPH_TTL`.
- **Dimensione temporale** - ogni path porta `firstSeen`/`openForSeconds`
  (badge "open Nd": da quanto è aperto) e `reopens` (badge "⟳ reopened N×": è
  tornato dopo essere stato risolto → regressione, spesso da un deploy). La
  Overview mostra una card **MTTR** (tempo medio di remediation dei path risolti)
  e uno **sparkline del trend** di esposizione: la sicurezza si gestisce sui
  trend, non sugli snapshot. Imposta `HISTORY_PATH` per persistere lo storico.
- **Confidenza di correlazione** - quando il normalizzatore *deduce* un
  collegamento (es. container→immagine) ne registra metodo e confidenza: digest
  `1.0`, tag `0.85`, solo nome `0.6` (un join debole abbassa la probabilità
  dell'arco). Nella kill chain compare il badge **"heuristic join · N%"**:
  verifica quel collegamento prima di agire, o marca il percorso
  `false-positive` se la correlazione è sbagliata.

---

## 9. Sicurezza, autenticazione e firme (guida completa)

> Questa è la sezione per **chi deve fare chiamate autenticate o firmate**.
> Spiega come *accendere* l'autenticazione, come passare il **token** sull'API e
> come **firmare** le chiamate di ingest con HMAC, con esempi copia-incolla.

### 9.1 Modello: due porte, due meccanismi

PerspectiveGraph ha **due porte** indipendenti, ciascuna con il suo controllo:

| Porta | Default | Cosa protegge | Meccanismo |
|---|---|---|---|
| **API** (`:8080`) - lettura/scrittura: GraphQL, suppression, ticket, validation, export | aperta | *leggere la mappa d'attacco e modificarne il triage* | **Bearer token** (`Authorization: Bearer …`) o **OIDC/JWT**, mappati a un **ruolo** |
| **Ingest** (`:8081`) - i webhook dove gli scanner fanno POST | aperta | *chi può immettere dati nel grafo* | **firma HMAC-SHA256** del corpo della richiesta |

Entrambe sono **opt-in**: se non configuri nulla restano aperte (comodo in locale)
e il backend lo segnala con un **warning rumoroso** nei log. Si attivano in modo
indipendente: puoi avere ingest firmato e API aperta, o viceversa.

> ⚠️ **La dashboard nel browser non invia token.** È una SPA statica che chiama
> `/graphql` via proxy: con l'**API autenticata**, il *browser* riceve `401` e non
> carica i dati. Quindi accendi l'auth sull'API quando i consumatori sono
> **strumenti/automazioni** (curl, SIEM, CI), non la dashboard interattiva. Per una
> demo navigabile lascia l'API aperta in un ambiente fidato.

Lo stack è comunque già indurito per una demo: immagini **pinnate per digest**,
backend **distroless** non-root con filesystem in sola lettura e capability
azzerate, tutte le porte vincolate a **`127.0.0.1`** (mai esposte alla LAN).

### 9.2 Accendere l'autenticazione

**In Docker / host (file `.env` nella radice, copia da [`.env.example`](../.env.example)):**

```bash
# --- API: token statici "token:ruolo[:tenant]", separati da virgola ---
API_TOKENS=alice-RWtoken:admin,readonly-token:viewer
# --- Ingest: segreto HMAC del tenant 'default' ---
INGEST_HMAC_SECRET=un-segreto-lungo-e-casuale
```

Genera segreti robusti con `openssl rand -hex 24`. Poi **riavvia il backend** perché
li rilegga:

```bash
docker compose --profile app up -d --force-recreate backend   # in Docker
# oppure, in dev sull'host: ferma e rilancia `make run-backend`
```

Nei log vedrai sparire i warning e comparire:
`API auth: bearer credential required (GraphiQL disabled)` e
`ingest auth: per-tenant HMAC signature required`.

**In Kubernetes (Helm):** sono valori di primo livello del chart (vedi §9.7).

### 9.3 Token, ruoli e chiamate **autenticate** all'API

Il formato di `API_TOKENS` è **`token:ruolo[:tenant[:scadenza[:app1|app2]]]`**:

- **token** - il valore bearer, **oppure** `sha256$<hex>` per tenere a riposo solo
  l'*hash* del token (il segreto vivo non resta in env/config). Hash: `printf %s "$TOK" | sha256sum`.
- **ruolo** - `viewer` / `operator` / `admin`.
- **tenant** - opzionale (default `default`; lascia il campo vuoto per tenerlo).
- **scadenza** - opzionale `YYYY-MM-DD`: il token viene rifiutato dopo quel giorno
  UTC (rotazione/lifecycle senza riavvii di codice).
- **app** - opzionale, lista separata da `|`: il principal può **leggere solo** gli
  attack-path/asset che toccano quelle applicazioni (**RBAC a livello di oggetto**;
  vuoto = tutte le app del tenant). Vedi §9.3.1.

Esempio: `sha256$ab…:viewer:default:2026-12-31:payments|web` = token hashato, viewer,
tenant default, scade il 31/12/2026, vede solo le app `payments` e `web`.

Tre ruoli, gerarchici:

| Ruolo | Può |
|---|---|
| `viewer` | **leggere** tutto: GraphQL, export OSCAL/SIEM, liste suppression/ticket/validation |
| `operator` | come viewer (riservato a usi futuri) |
| `admin` | tutto + le **scritture**: creare/eliminare suppression, ticket, validation |

#### 9.3.1 RBAC per-applicazione (scoping del *read*)

Un token (o un JWT con claim `apps`) **app-scoped** vede soltanto gli attack-path,
il grafo, le violazioni di policy, gli export e la ricerca che toccano le sue app -
l'infrastruttura condivisa *sul* percorso resta visibile (è parte dell'attacco),
ma le app non consentite sono invisibili. Lo scoping è applicato **una volta al
confine dati** (snapshot del grafo + path dell'analyzer), quindi vale per *ogni*
query senza poterlo aggirare. Per OIDC: claim `apps` (array JSON o stringa
separata da virgola/spazio/`|`).

Quali endpoint richiedono quale ruolo (quando l'auth è attiva):

| Endpoint | Metodo | Ruolo minimo |
|---|---|---|
| `/graphql` | POST | **viewer** |
| `/export/ndjson`, `/export/oscal` | GET | **viewer** |
| `/suppressions`, `/tickets`, `/validations` | GET | **viewer** |
| `/suppressions`, `/tickets`, `/validations` | POST | **admin** |
| `/suppressions/{id}`, `/validations/{id}` | DELETE | **admin** |
| `/tickets/{id}/close` | POST | **admin** |
| `/healthz`, `/metrics` | GET | *sempre aperti* |

Il token va nell'header **`Authorization: Bearer <token>`**. Esempi (token =
**solo la parte prima dei due punti**, es. `alice-RWtoken`):

```bash
export PG_API=http://localhost:8080
export PG_TOKEN='alice-RWtoken'        # un token admin da API_TOKENS

# Query GraphQL (serve viewer):
curl -sS -X POST "$PG_API/graphql" \
  -H "Authorization: Bearer $PG_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ attackPaths { id score } }"}'

# Scrittura: sopprimere un percorso (serve admin):
curl -sS -X POST "$PG_API/suppressions" \
  -H "Authorization: Bearer $PG_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"pathId":"ap-1a2b-3c4d","reason":"accept-risk","owner":"secops@acme"}'

# Export per il SIEM (serve viewer):
curl -sS "$PG_API/export/ndjson" -H "Authorization: Bearer $PG_TOKEN" > enrichment.ndjson
```

Cosa torna se sbagli:
- **nessun token / token errato** → `401 {"errors":[{"message":"unauthorized: invalid or insufficient credentials"}]}`;
- **token `viewer` su una scrittura** → `401` (ruolo insufficiente);
- ricorda: con auth attiva il **playground GraphiQL** è disabilitato (usa `curl`/Postman).

> **Multi-tenant:** un token con tenant (`tok:admin:globex`) vede e scrive **solo**
> il grafo di quel tenant. Lato ingest, il tenant si seleziona con l'header
> `X-Tenant` (§9.4). Stesso nome tenant ⇒ stessi dati.

### 9.4 Firmare le chiamate di **ingest** (HMAC-SHA256)

Quando `INGEST_HMAC_SECRET` (o `INGEST_HMAC_SECRETS`) è impostato, **ogni** POST
verso `/ingest/...` deve portare una firma del corpo, altrimenti → `401`.

Schema esatto:
- **Header firma:** `X-PerspectiveGraph-Signature: sha256=<hex>`
- **Calcolo:** `<hex> = HMAC-SHA256(secret, CORPO_GREZZO_DELLA_RICHIESTA)`
- **Header tenant:** `X-Tenant: <nome>` (default `default`; seleziona quale segreto usare)
- **Regola d'oro:** si firmano **esattamente i byte che invii** - niente newline o
  ricodifiche aggiunte tra firma e invio.

**Firmare un file** (il caso tipico: l'output di uno scanner):

```bash
export PG_INGEST=http://localhost:8081
export PG_HMAC_SECRET='un-segreto-lungo-e-casuale'   # = INGEST_HMAC_SECRET

FILE=trivy.json
SIG="sha256=$(openssl dgst -sha256 -hmac "$PG_HMAC_SECRET" "$FILE" | awk '{print $NF}')"

curl -sS -X POST "$PG_INGEST/ingest/trivy?slug=acme/repo&pr=42" \
  -H 'Content-Type: application/json' \
  -H 'X-Tenant: default' \
  -H "X-PerspectiveGraph-Signature: $SIG" \
  --data-binary @"$FILE"
```

`openssl ... "$FILE"` firma il **contenuto del file**, e `--data-binary @"$FILE"`
invia lo stesso contenuto byte-per-byte: le firme combaciano. `awk '{print $NF}'`
estrae l'esadecimale dall'output di openssl.

**Helper riutilizzabile** - incollalo nella shell e usalo per qualsiasi sorgente:

```bash
pg_ingest() {                       # uso: pg_ingest <sorgente> <file> [querystring]
  local src=$1 file=$2 qs=$3
  local sig="sha256=$(openssl dgst -sha256 -hmac "$PG_HMAC_SECRET" "$file" | awk '{print $NF}')"
  curl -sS -X POST "$PG_INGEST/ingest/$src${qs:+?$qs}" \
    -H 'Content-Type: application/json' \
    -H "X-Tenant: ${PG_TENANT:-default}" \
    -H "X-PerspectiveGraph-Signature: $sig" \
    --data-binary @"$file"
}

pg_ingest trivy   trivy.json   'slug=acme/repo&pr=42'
pg_ingest k8s     cluster.json
pg_ingest iam     iam.json
```

**Firmare un corpo "inline"** (JSON costruito al volo): firma **gli stessi byte**
che mandi, senza newline finale (`printf '%s'`, non `echo`):

```bash
BODY='{"provider":"okta","users":[{"email":"a@acme.com","mfa":false,"federated_roles":["arn:aws:iam::123456789012:role/admin-role"]}]}'
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$PG_HMAC_SECRET" | awk '{print $NF}')"
curl -sS -X POST "$PG_INGEST/ingest/sso" \
  -H 'Content-Type: application/json' \
  -H "X-PerspectiveGraph-Signature: $SIG" \
  --data "$BODY"
```

**Più tenant** con segreti separati: usa `INGEST_HMAC_SECRETS=globex:segA,acme:segB`
e manda `X-Tenant: globex` firmando con `segA`. Un tenant sconosciuto → `401`
(`unknown tenant`). Errori tipici lato ingest: firma assente/sbagliata → `401`
`invalid or missing X-PerspectiveGraph-Signature`.

### 9.5 OIDC / JWT (in alternativa o accanto ai token)

Per integrarsi con un IdP aziendale, al posto (o accanto) di `API_TOKENS`:

```bash
OIDC_ISSUER=https://login.acme.com/        # iss atteso
OIDC_AUDIENCE=perspectivegraph             # aud attesa
OIDC_JWKS_URL=https://login.acme.com/.well-known/jwks.json   # chiavi pubbliche (RS256)
```

Il client presenta un JWT RS256 valido come `Authorization: Bearer <jwt>`; il
backend ne verifica firma/`iss`/`aud`/scadenza via JWKS e ne ricava ruolo e tenant.
I due metodi convivono (prima i token statici, poi il JWT). **Fail-closed:** se
imposti `OIDC_JWKS_URL` ma lasci vuoti `OIDC_ISSUER` o `OIDC_AUDIENCE`, il backend
**si rifiuta di avviarsi** - un verificatore senza `iss`/`aud` accetterebbe qualsiasi
JWT RS256 mai emesso da quell'IdP.

#### 9.5.1 Login runtime nella dashboard (token o "Sign in with SSO")

La dashboard **non** ha più bisogno di un token compilato a build-time. Legge un
endpoint **pubblico** `GET /auth/config` (modalità auth + coordinate pubbliche
dell'IdP, **senza segreti**) e mostra il gate di login giusto - così *un solo
build* serve un backend aperto, a-token o SSO, senza ricompilare:

```bash
curl -s http://localhost:8080/auth/config
# aperto:   {"authRequired":false,"mode":"none"}
# protetto: {"authRequired":true,"mode":"both","oidc":{"clientId":"…","authorizeUrl":"…"}}
```

Per accendere il pulsante **"Sign in with SSO"** aggiungi le coordinate SPA dell'IdP
(non sono segrete - servono solo ad avviare il flusso):

```bash
OIDC_CLIENT_ID=pg-dashboard
OIDC_AUTHORIZE_URL=https://login.acme.com/authorize
OIDC_TOKEN_URL=https://login.acme.com/oauth/token   # abilita il PKCE completo
OIDC_SCOPES="openid profile email"                  # default
```

Con `OIDC_TOKEN_URL` impostata la dashboard esegue il flusso **OIDC Authorization
Code + PKCE** completo (sfida S256, verifica dello `state` anti-CSRF, scambio
code→token - **nessun client secret nel browser**); senza, ripiega su un ritorno
implicito `#access_token`. La credenziale vive **solo nella tab** (`sessionStorage`,
muore con la scheda) e viaggia come Bearer - mai scritta su disco o nel bundle.
La validazione resta su JWKS/`iss`/`aud`. *(Il tuo IdP deve permettere il CORS
dall'origine della dashboard sul token endpoint.)*

> **Isolamento multi-tenant - provato.** Questo strumento è la mappa di come
> attaccare ogni cliente, quindi non deve mai "sanguinare" tra tenant: ogni tenant
> ha il **suo** grafo AGE e indice di ricerca, e **ogni** lettura API passa per
> `snapshot(tenant del principal)`. Un principal del tenant A non può vedere il
> grafo o gli attack path del tenant B - garanzia fissata da un test end-to-end
> (`internal/api/tenant_isolation_test.go`).

#### 9.5.2 Provare l'SSO in locale (Keycloak demo, nessun IdP cloud)

Per esercitare il login SSO end-to-end su un portatile c'è un IdP demo già pronto:
un **Keycloak** opt-in nel compose (profilo `sso`) con un realm importato
(`deploy/keycloak/realm-demo.json`: realm `demo`, utente **demo/demo**, client
public PKCE `perspectivegraph`).

```bash
# 1) Avvia stack + IdP demo (Keycloak su http://localhost:8088)
docker compose --profile app --profile sso up -d --build

# 2) Punta il backend al Keycloak demo: aggiungi al tuo .env e ricrea il backend.
#    NB: il JWKS lo fetcha il BACKEND (host interno di rete keycloak:8080), mentre
#    issuer/authorize/token sono raggiunti dal BROWSER (http://localhost:8088) -
#    OIDC_JWKS_URL e OIDC_ISSUER sono volutamente host diversi, ed è corretto.
cat >> .env <<'EOF'
OIDC_JWKS_URL=http://keycloak:8080/realms/demo/protocol/openid-connect/certs
OIDC_ISSUER=http://localhost:8088/realms/demo
OIDC_AUDIENCE=perspectivegraph
OIDC_CLIENT_ID=perspectivegraph
OIDC_AUTHORIZE_URL=http://localhost:8088/realms/demo/protocol/openid-connect/auth
OIDC_TOKEN_URL=http://localhost:8088/realms/demo/protocol/openid-connect/token
OIDC_SCOPES=openid profile email
OIDC_LOGOUT_URL=http://localhost:8088/realms/demo/protocol/openid-connect/logout
EOF
docker compose --profile app up -d backend

# 3) Apri http://localhost:3000 → "Sign in with SSO" → login demo / demo.
```

Cosa verifica: `GET /auth/config` ora risponde `mode:oidc` con le coordinate
dell'IdP; la dashboard fa il flusso **Authorization Code + PKCE** verso Keycloak;
il token torna e il backend lo valida su JWKS/`iss`/`aud` (il realm include un
audience-mapper `perspectivegraph` e un claim `role=admin`, così l'utente demo ha
accesso completo). Smonti l'IdP con `docker compose --profile sso down`. *(Setup
solo-locale: Keycloak gira in `start-dev` in-memory - non è una config di
produzione.)*

#### 9.5.3 Provare l'SSO su Kubernetes (cluster locale)

Stesso giro, ma sul chart Helm. Su un cluster locale (Docker Desktop / kind /
minikube) le immagini non stanno su un registry, quindi **caricale nel cluster**
(il suo container-runtime non condivide il docker daemon dell'host):

```bash
make up-full && make down      # costruisce perspectivegraph-{backend,dashboard}:local
# Carica nel cluster (Docker Desktop kind-based):
docker save perspectivegraph-backend:local  | docker exec -i desktop-control-plane ctr -n k8s.io images import -
docker save perspectivegraph-dashboard:local | docker exec -i desktop-control-plane ctr -n k8s.io images import -
#   (kind:     kind load docker-image perspectivegraph-backend:local … )
#   (minikube: minikube image load perspectivegraph-backend:local … )

NS=perspectivegraph
kubectl create namespace $NS

# IdP demo Keycloak (realm da ConfigMap + deployment)
kubectl -n $NS create configmap keycloak-realm \
  --from-file=realm-demo.json=deploy/keycloak/realm-demo.json
kubectl -n $NS apply -f deploy/keycloak/k8s-keycloak-demo.yaml
kubectl -n $NS rollout status deploy/keycloak --timeout=180s

# Chart + overlay SSO (immagini locali + OIDC già cablato)
helm install perspectivegraph deploy/helm/perspectivegraph \
  -n $NS -f deploy/helm/perspectivegraph/values-sso-demo.yaml
kubectl -n $NS rollout status deploy/perspectivegraph-perspectivegraph-backend --timeout=180s

# Tre port-forward, in terminali separati (lasciali aperti):
kubectl -n $NS port-forward svc/keycloak 8088:8080                                  # browser -> IdP
kubectl -n $NS port-forward svc/perspectivegraph-perspectivegraph-frontend 3000:80  # browser -> dashboard
kubectl -n $NS port-forward svc/perspectivegraph-perspectivegraph-backend 8081:8081 # make seed -> ingest

# Carica i dati di esempio (postano su localhost:8081, la porta ingest):
make seed
make seed-discovery
```

> **Nota porte su k8s:** a differenza di docker/host-dev, **niente è su `localhost`
> se non lo inoltri**. `make seed`/`make seed-discovery` postano su
> `http://localhost:8081/ingest/...` → serve il port-forward della **porta ingest
> 8081** (sopra), altrimenti *connection refused*. L'ingest nella demo è aperto
> (HMAC off), quindi il seed non richiede token.
> Per colpire **direttamente l'API GraphQL** (`localhost:8080/graphql`) con
> curl/Postman aggiungi anche
> `kubectl -n $NS port-forward svc/perspectivegraph-perspectivegraph-backend 8080:8080`;
> con l'auth attiva serve un **bearer token** (il GraphiQL è disabilitato). Dalla
> dashboard (`localhost:3000`) GraphQL funziona già senza port-forward 8080 (il
> proxy nginx lo raggiunge in-cluster e il client manda il token dopo il login).

Apri **http://localhost:3000** → "Sign in with SSO" → **demo / demo**; prova anche
**Sign out** (logout RP-initiated). Il **perché le URL OIDC differiscono** è lo
stesso del §9.5.2: il **backend** raggiunge Keycloak in-cluster (`keycloak:8080`,
per il JWKS), il **browser** via port-forward (`localhost:8088`, per
authorize/token/logout) - `iss` e host del JWKS sono campi indipendenti. Tutto è
nell'overlay [`values-sso-demo.yaml`](../deploy/helm/perspectivegraph/values-sso-demo.yaml)
e nel manifest [`k8s-keycloak-demo.yaml`](../deploy/keycloak/k8s-keycloak-demo.yaml).
Teardown: `helm uninstall perspectivegraph -n $NS && kubectl delete namespace $NS`.
*(Demo solo-locale: immagini `:local` + Keycloak `start-dev`.)*

### 9.6 Scorciatoia: tutto questo via Postman (senza scrivere firme a mano)

Se preferisci una GUI, la collection
[`perspectivegraph.postman_collection.json`](./perspectivegraph.postman_collection.json)
**firma e autentica da sola**. Importala e nelle *Variables* della collection imposta:

- `apiToken` → un token da `API_TOKENS` (es. `alice-RWtoken`): aggiunge `Authorization: Bearer …` a GraphQL/export/suppression/ticket/validation;
- `ingestHmacSecret` → il tuo `INGEST_HMAC_SECRET`: uno script *pre-request* calcola e inserisce `X-PerspectiveGraph-Signature` su ogni `/ingest/…`;
- `tenant` → il tenant (default `default`), inviato come `X-Tenant`.

Lasciale vuote e le richieste partono **senza** auth/firma (per un backend aperto).
Da riga di comando: `newman run docs/perspectivegraph.postman_collection.json
--env-var apiToken=… --env-var ingestHmacSecret=…`.

### 9.7 Indurimento prima di un deploy condiviso o in produzione

Imposta queste variabili nel file `.env` (copia da [`.env.example`](../.env.example)):

| Variabile | A cosa serve |
|---|---|
| `POSTGRES_PASSWORD` | Cambia la password di default (`perspective`). |
| `INGEST_HMAC_SECRET` | Firma HMAC obbligatoria sui webhook di ingest. |
| `API_TOKENS` *oppure* `OIDC_JWKS_URL`/`OIDC_ISSUER`/`OIDC_AUDIENCE` | Autenticazione sull'API GraphQL (a token o OIDC/JWT). Con l'auth attiva il playground GraphiQL viene disabilitato. |
| `AUDIT_LOG_PATH` | Audit log a catena di hash (verificabile con `perspectivegraph verify-audit <file>`). Registra anche le **letture** della mappa d'attacco: `view.attack_paths` (con gli id dei path visti), `view.graph`, `export.oscal`/`export.ndjson` - "chi ha visto, o esfiltrato, quali attack path". |
| `SUPPRESSIONS_PATH` | Rende persistenti le decisioni di triage/soppressione (altrimenti restano solo in memoria e si perdono al riavvio). |
| `GRAPH_TTL` | Pruning di staleness: rimuove nodi/archi non più osservati entro la finestra (es. `168h` = 7 giorni), così gli asset spariti dai feed non generano *path fantasma*. Off di default. |
| `ANALYZER_WORKERS` | Parallelismo del pathfinding per-seed (Dijkstra indipendenti su un'adiacenza immutabile). `0` = auto = numero di CPU. Il risultato è identico a qualsiasi numero di worker, quindi è solo uno *speedup* su grafi con molti punti d'ingresso (~2.9× a 8 worker su un grafo da 10k nodi/64 seed; vedi `make bench`). |
| `ANALYZER_INCREMENTAL` | Snapshot incrementale: tiene il grafo residente e lo *patcha* con il solo delta del pass (elementi cambiati dall'ultimo pass, filtrati sullo stesso `last_seen` del pruner) invece di rileggerlo tutto - il risparmio di fetch su un grafo AGE grande. Off di default (scambia memoria per costo di fetch, no-op per store senza delta). Ricalcolo pieno auto-correttivo al primo pass, dopo un prune e periodicamente. |
| `ATTACKER_PROFILE_PRIORS` | Priori del threat model per la mistura sui profili d'attaccante (es. `commodity:0.5,criminal:0.35,apt:0.15`). I nomi corrispondono ai profili built-in; i valori sono rinormalizzati. Vuoto → default. Lo score viene marginalizzato su questi profili per il breakdown per-profilo (`mixtureScore`/`profileScores`); lo `score` ingenuo resta come baseline. |
| `HISTORY_PATH` | Rende persistente lo storico temporale (età dei path, MTTR, trend). Vuoto → solo in memoria (l'"aperto da N giorni" e i trend ripartono al riavvio). |
| `TICKETS_PATH` / `TICKET_WEBHOOK_URL` | Ticket di remediation: persistenza della board locale + invio opzionale a un tracker esterno (Jira/GitHub/SOAR). Vuoti → in memoria, dry-run (loggato e tracciato in locale). |
| `VALIDATIONS_PATH` | Rende persistenti i verdetti red-team/BAS (precision/recall). Vuoto → solo in memoria. |
| `CORS_ALLOWED_ORIGINS` | Origini browser ammesse a chiamare l'API cross-origin (lista separata da virgola). Default: dev server Vite + dashboard docker. In produzione metti l'origine reale della dashboard; `*` ammette tutte (sconsigliato); vuoto disabilita la CORS (solo same-origin). |
| `STORE_ENCRYPTION_KEY` | **Cifratura at-rest** (AES-256-GCM) degli store di governance (suppression/ticket/validation/history) **e dell'audit log**: un volume/backup rubato non rivela in chiaro la mappa d'attacco né chi l'ha vista. 64 char esadecimali = chiave grezza, altrimenti passphrase. Vuoto → in chiaro. Genera: `openssl rand -hex 32`. |
| `EXPORT_SIGNING_KEY` | **Firma Ed25519** (seed 64-hex) degli export OSCAL/SIEM con firma *detached*, così un auditor/SIEM ne verifica integrità e origine; la chiave pubblica è su `GET /export/pubkey`. Vuoto → export non firmati. |
| `AUTH_LOCKOUT_THRESHOLD` / `EXFIL_ALERT_THRESHOLD` | **Anti-abuso**: oltre N fallimenti auth da un IP in 5 min → blocco IP (429) per 15 min + alert; oltre N path visti/esportati da un principal in 5 min → alert di esfiltrazione. Gli alert vanno nei log (WARN) e nell'audit log. `0` disabilita (lockout default 50; exfil default off). |

In Kubernetes usa il chart Helm in `deploy/helm/perspectivegraph`. Cabla tutti e
quattro i componenti (backend, dashboard, Postgres+AGE con init idempotente del
grafo, NATS) e supporta Postgres/NATS esterni gestiti (`postgres.enabled=false` +
`externalHost`). **Importante:** un'installazione di default è *non autenticata e
con governance in memoria* - va bene per una demo in un cluster fidato, ma questo
strumento è una *mappa di come attaccare l'org*, quindi oltre quel confine attiva
i controlli (sono valori di primo livello del chart):

```bash
helm install perspective deploy/helm/perspectivegraph \
  --set auth.apiTokens="$(openssl rand -hex 16):admin" \   # bearer auth sull'API
  --set ingest.hmacSecret="$(openssl rand -hex 16)" \      # ingest firmato HMAC
  --set persistence.enabled=true \                         # PVC per gli store + audit log
  --set graph.ttl=168h \                                   # pruning staleness
  --set postgres.auth.password="$(openssl rand -hex 16)"   # niente password demo
```

`persistence.enabled` monta un volume ReadWriteOnce che rende persistenti
suppression, ticket, validazioni red-team, storico MTTR/posture e l'**audit log
a prova di manomissione** (altrimenti tutto in memoria, perso al riavvio). Gli
store sono single-writer: con persistenza attiva il chart **si rifiuta di
renderizzare con `backend.replicas > 1`**, e `NOTES` stampa un ⚠ quando auth o
persistenza sono spenti (nessuna esposizione insicura silenziosa). Vedi anche la
sezione "Container & compose hardening" del [README](../README.md).

Ogni capacità opzionale è cablata **sia in `docker-compose.yml`** (passthrough
`${VAR:-}`, spenti di default) **sia nel chart**, così una feature attivata nel
codice è davvero raggiungibile nello stack in esecuzione:

- **Connettori agentless** - `--set connectors.enabled='{aws}'` fa il PULL della
  posture cloud a intervalli (`connectors.interval`); il connettore AWS gira su
  fixtures finché `connectors.aws.mode=live` (poi `connectors.aws.region` + un
  `connectors.aws.roleArn` read-only assumibile).
- **Login SSO** - `auth.oidc.clientId` / `authorizeUrl` / `tokenUrl` / `scopes`
  sono le coordinate lato-SPA che il login gate della dashboard legge da
  `GET /auth/config` per il flusso Authorization-Code + PKCE (la tripletta
  `issuer`/`audience`/`jwksUrl` fa la verifica server-side del token).
- **Dev workflow** - `github.token` trasforma commento PR / merge-gate e
  remediation-as-PR da dry-run a operativi; `github.dashboardUrl` è il link a cui
  puntano quei commenti.
- **Layer AI (Claude o HuggingFace)** - `ai.apiKey` (Anthropic) abilita `/ai/*`
  (query NL, executive summary, spiega-percorso); `ai.hf.token` è l'alternativa
  gratuita OpenAI-compatible, usata se `ai.apiKey` è vuota (`ai.hf.model`/`ai.hf.baseUrl`
  la regolano). Entrambe le chiavi nel Secret; `ai.model`/`baseUrl`/`maxTokens`
  override opzionali. Con nessuna delle due, self-gated spento.
- **Hardening** - `scrubIngest` (attivo di default) redige i valori che sembrano
  segreti dall'output degli scanner prima dello store; `crypto.storeEncryptionKey`
  cifra at-rest gli store di governance e `crypto.exportSigningKey` firma gli export
  (entrambe finiscono nel Secret).
- **TLS (attivabile, non hardcoded)** - di default l'app parla HTTP e si aspetta che
  il TLS termini davanti. Per HTTPS: `--set ingress.tls.enabled=true
  --set ingress.tls.secretName=…` (con cert-manager via `ingress.annotations`),
  oppure TLS nel pod con `--set backend.tls.enabled=true
  --set backend.tls.secretName=<secret kubernetes.io/tls>` (i server API+ingest
  servono TLS ≥ 1.2 direttamente; fuori da Helm: `TLS_CERT_FILE`/`TLS_KEY_FILE`).
- **TLS verso il DB** - la connessione porta la mappa d'attacco: per un Postgres
  gestito/esterno `--set postgres.sslMode=verify-full` (il chart mette già `require`
  di default per un DB esterno; quello bundled resta `disable`, non ha TLS).
- **TLS verso NATS** - `NATS_URL` con endpoint `tls://`; `NATS_TLS_CA` fida una CA
  privata, `NATS_TLS_CERT`/`NATS_TLS_KEY` aggiungono il client cert per **mTLS**
  (Helm: `--set nats.tls.enabled=true --set nats.tls.secretName=…`).
- **mTLS su tutto il traffico interno (modo facile)** - una **service mesh**
  (Linkerd/Istio) avvolge in mTLS ogni hop pod-to-pod (backend↔DB↔NATS↔dashboard)
  in modo trasparente, con rotazione cert automatica e **zero modifiche all'app**;
  i knob TLS per-componente qui sopra servono se NON usi una mesh.
- **Segreti at-rest** - il chart scrive le credenziali in un `Secret` k8s (base64,
  non cifrato in etcd di default): abilita la cifratura etcd, oppure gestisci il
  Secret esternamente con `--set secrets.existingSecret=<nome>` (il chart **smette
  di crearlo** e legge il tuo: External Secrets / Sealed Secrets / Vault).

**Freschezza, backup e DR.** Imposta `GRAPH_TTL` (es. `168h`) in produzione: i
nodi/archi non più osservati entro la finestra vengono rimossi (solo dal leader),
così un pod cancellato o un security group rimosso non lasciano un percorso
fantasma. Gli elementi senza `last_seen` (dati pre-esistenti) non vengono mai
toccati. La dashboard mostra "pruned N stale"; `status { prunedNodes
prunedEdges lastPrunedAt }` e le metriche Prometheus espongono i totali. Il grafo
è **stato derivato**: è ricostruibile ri-ingerendo i feed, quindi un DB AGE perso
è un *re-seed*, non una perdita di dati - fai comunque il backup di Postgres
(`pg_dump`) per lo storico.

**Scalare l'analizzatore.** Il costo per-pass resta piatto al crescere del grafo su
tre livelli: (1) la *change-detection* (sempre attiva) salta del tutto un pass se
nulla è cambiato; (2) il *pathfinding parallelo* (attivo di default, `ANALYZER_WORKERS`)
distribuisce un Dijkstra per ogni seed sui core, con risultato identico al
sequenziale; (3) lo *snapshot incrementale* (`ANALYZER_INCREMENTAL=true`, opt-in)
patcha un grafo residente col solo delta invece di rileggerlo tutto. Visibilità su
`/metrics`: dimensione del grafo, modalità snapshot (`full|delta`) e latenza del
pathfinding. Per un test di carico end-to-end: `make seed-load` (o
`perspectivegraph genload --seeds 64 --width 1000 …`) genera una superficie d'attacco
sintetica grande e la invia all'ingest. Benchmark: `make bench`.

---

## 10. Troubleshooting

| Sintomo | Causa probabile / rimedio |
|---|---|
| **Nessun attack path** | Manca un **seed** (`internet_exposed`) o un **crown jewel** (`crown_jewel`), oppure non sono **collegati**. Vedi §6. |
| **Dati caricati ma dashboard ferma** | Aspetta un `ANALYZER_INTERVAL` (default 30 s): l'analizzatore ricalcola solo quando il grafo cambia. |
| **`/ingest/...` → 404** | Nome collector errato (deve essere uno tra `trivy, semgrep, custodian, falco, build, supplychain, k8s, cloudnet, iam, sso`; più `events`). |
| **API → `401 unauthorized: invalid or insufficient credentials`** | Auth attiva: manca/è errato l'`Authorization: Bearer <token>`, o il ruolo è insufficiente (le scritture richiedono `admin`). Vedi §9.3. |
| **Ingest → `401 invalid or missing X-PerspectiveGraph-Signature`** | Firma HMAC assente o sbagliata: firma **gli stessi byte** che invii col segreto giusto; controlla `X-Tenant`. Vedi §9.4. |
| **Dashboard vuota dopo aver attivato l'auth** | Atteso: il browser non manda token → l'API risponde `401`. Tieni l'API aperta per la dashboard interattiva, oppure consuma l'API via curl/Postman col Bearer. Vedi §9.1. |
| **Ids che non combaciano** | Image ref o nome repo diversi tra le sorgenti: allineali (§6 punto 3). |
| **La dashboard non carica i dati** | Backend non avviato o non `healthy`: `docker compose --profile app ps` e `docker compose logs backend`. |
| **Porta occupata (8080/3000/5432…)** | Un altro processo usa la porta (es. un backend host già attivo). Fermalo o cambia la porta. |
| **`make up-full` non parte** | Docker Desktop non in esecuzione, o build fallita: rilancia `docker compose --profile app build` per leggere l'errore. |
| **Search vuota** | OpenSearch non attivo: avvia col profilo `search` e imposta `OPENSEARCH_URL` (§4). |
| **Ripartire puliti** | `docker compose --profile app down -v && make up-full && make seed`. |

---

## 11. Riferimenti

- [README.md](../README.md) - panoramica, tech stack, hardening, deploy Helm.
- [ARCHITECTURE.md](../ARCHITECTURE.md) - architettura, ontologia, scoring, roadmap.
- [ONBOARDING.md](./ONBOARDING.md) - alimentare PerspectiveGraph da un'infra reale (dettaglio).
- [perspectivegraph.postman_collection.json](./perspectivegraph.postman_collection.json) - richieste pronte (ingest + GraphQL + export).
- `.env.example` (radice) - tutte le variabili di configurazione, commentate.

# 🚀 MemoryArtifactExtractor


**Extracteur d'Artefacts Mémoire Forensics**
*Ayi NEDJIMI Consultants - WinToolsSuite Série 3*

---

## Vue d'ensemble

**MemoryArtifactExtractor** est un outil forensics avancé conçu pour détecter et extraire des artefacts mémoire suspects présents dans les processus Windows actifs. Il identifie les techniques d'évasion malware courantes telles que :

- **Phantom DLLs** : Modules chargés en mémoire sans fichier correspondant sur disque
- **Process Hollowing** : Remplacement de code légitime par du code malveillant
- **Régions RWX** : Pages mémoire avec permissions suspectes (Read-Write-Execute)

L'outil permet également de dumper les régions suspectes pour analyse approfondie avec des outils comme IDA Pro, Ghidra ou x64dbg.

- --


## ✨ Fonctionnalités

### 1. Détection de Phantom DLLs (Reflective DLL Injection)

**Principe** : Les malwares utilisent souvent l'injection réflexive de DLLs pour charger du code malveillant directement en mémoire sans passer par `LoadLibrary()`. Ces modules n'ont pas de fichier correspondant sur disque.

**Méthode de détection** :
- Énumération de tous les modules chargés via `EnumProcessModules()`
- Récupération du chemin complet avec `GetModuleFileNameExW()`
- Vérification de l'existence du fichier sur disque avec `PathFileExistsW()`
- Si le fichier n'existe pas → **Phantom DLL détectée**

**Criticité** : **ÉLEVÉE** - Indicateur fort de malware ou rootkit

**Cas d'usage forensics** :
```
Scénario : APT utilisant Cobalt Strike Beacon
- La charge utile est injectée via reflective DLL injection
- Le module "beacon.dll" apparaît dans le processus mais n'existe pas sur C:\
- MemoryArtifactExtractor le détecte comme Phantom DLL
```

- --

### 2. Détection de Process Hollowing

**Principe** : Le process hollowing consiste à :
1. Démarrer un processus légitime en mode suspendu
2. Décharger l'image PE originale
3. Mapper du code malveillant à la place
4. Reprendre l'exécution

**Méthode de détection** :
- Lecture de l'en-tête PE en mémoire (base 0x400000) avec `ReadProcessMemory()`
- Extraction du champ `AddressOfEntryPoint` des `IMAGE_NT_HEADERS`
- Lecture du fichier PE sur disque (`CreateFileW()`)
- Comparaison des EntryPoints :
  - **Différents** → Process Hollowing détecté
  - **Identiques** → Processus légitime

**Criticité** : **CRITIQUE** - Technique d'évasion avancée

**Cas d'usage forensics** :
```
Scénario : Malware Zeus/Zbot
- Zeus démarre "svchost.exe" en mode suspendu
- Remplace le code par son payload bancaire
- EntryPoint mémoire ≠ EntryPoint disque
- MemoryArtifactExtractor alerte "Process Hollowing"
```

**Limites** :
- Fonctionne principalement pour base address 0x400000 (32-bit)
- Pour 64-bit ASLR, nécessite récupération de base via PEB

- --

### 3. Scanner de Régions RWX (Read-Write-Execute)

**Principe** : Les pages mémoire avec permissions RWX sont hautement suspectes car elles permettent :
- Écriture de shellcode
- Exécution immédiate sans changer les protections

**Méthode de détection** :
- Scan complet de l'espace d'adressage via `VirtualQueryEx()`
- Filtrage des régions avec état `MEM_COMMIT`
- Détection de protection `PAGE_EXECUTE_READWRITE`
- Classification par type (PRIVATE, MAPPED, IMAGE)

**Criticité** : **HAUTE** - Forte probabilité de shellcode

**Cas d'usage forensics** :
```
Scénario : Exploit Kit délivrant Metasploit shellcode
- Exploit crée une région RWX de 4096 bytes
- Écrit le shellcode msfvenom
- Saute à l'adresse pour exécution
- MemoryArtifactExtractor détecte la région RWX suspecte
```

**Dump forensics** :
- Extraction complète de la région en fichier `.dmp`
- Analyse avec :
  - `scdbg` (émulation shellcode)
  - `shellcode2exe` (conversion pour analyse statique)
  - Signature YARA pour identification famille malware

- --


## Architecture Technique

### Structure `MemoryArtifact`

```cpp
struct MemoryArtifact {
    DWORD pid;                    // Process ID
    std::wstring processName;     // Nom du processus
    std::wstring artifactType;    // Type (Phantom DLL / Process Hollowing / RWX)
    PVOID address;                // Adresse mémoire de l'artefact
    SIZE_T size;                  // Taille de la région
    std::wstring details;         // Informations supplémentaires
    std::wstring criticality;     // CRITIQUE / ÉLEVÉE / HAUTE
};
```

### APIs Windows Utilisées

| API | Bibliothèque | Usage |
|-----|--------------|-------|
| `CreateToolhelp32Snapshot` | kernel32.lib | Énumération processus |
| `Process32FirstW/NextW` | kernel32.lib | Parcours liste processus |
| `OpenProcess` | kernel32.lib | Obtenir handle processus |
| `EnumProcessModules` | psapi.lib | Lister modules chargés |
| `GetModuleFileNameExW` | psapi.lib | Chemin complet module |
| `PathFileExistsW` | shlwapi.lib | Vérifier existence fichier |
| `ReadProcessMemory` | kernel32.lib | Lecture mémoire distante |
| `VirtualQueryEx` | kernel32.lib | Interroger régions mémoire |

### Droits Requis

L'outil nécessite les privilèges suivants :
- **PROCESS_QUERY_INFORMATION** : Lire infos processus
- **PROCESS_VM_READ** : Lire mémoire processus

Pour analyser les processus système (PID < 1000), exécuter en tant qu'**Administrateur**.

- --


## 🚀 Utilisation

### Compilation

```batch
go.bat
```

**Prérequis** : Visual Studio 2019+ avec MSVC

### Interface Graphique

1. **Scanner Processus** : Lance l'analyse complète de tous les processus actifs
2. **Dump Région** : Sauvegarde la région mémoire sélectionnée en fichier `.dmp`
3. **Exporter CSV** : Génère rapport forensics au format UTF-8 BOM

### ListView Colonnes

| Colonne | Description | Exemple |
|---------|-------------|---------|
| PID | Process ID | 1337 |
| Processus | Nom exécutable | explorer.exe |
| Artefact | Type détecté | Phantom DLL |
| Adresse | Offset mémoire | 0x12340000 |
| Taille | Bytes alloués | 65536 |
| Détails | Informations contextuelles | C:\Temp\evil.dll |
| Criticité | Niveau de risque | CRITIQUE |

- --


## Interprétation des Résultats

### Phantom DLL : Chemin Invalide

```
Artefact: Phantom DLL
Détails: C:\Windows\System32\ntdll_copy.dll
Criticité: ÉLEVÉE
```

**Analyse** :
- Module chargé mais fichier absent → Probable injection réflexive
- Vérifier avec Process Hacker si le module a attribut `Manual Mapping`
- Dumper et analyser avec pestudio pour IoCs

### Process Hollowing Détecté

```
Artefact: Process Hollowing
Détails: Image PE modifiée en mémoire
Criticité: CRITIQUE
```

**Analyse** :
- Comparer processus parent/enfant (Process Explorer)
- Dumper le processus complet avec `procdump -ma <PID>`
- Reconstruire PE et analyser avec IDA Pro

### Région RWX Suspecte

```
Artefact: Région RWX
Adresse: 0x00A50000
Taille: 4096
Détails: Protection: RWX, Type: PRIVATE
Criticité: HAUTE
```

**Analyse** :
- Dumper la région (bouton "Dump Région")
- Analyser avec scdbg : `scdbg.exe /f dump_1337_00A50000.dmp`
- Rechercher signatures shellcode :
  - NOP sled (0x90 répétés)
  - GetProcAddress patterns
  - Reverse shell connections

- --


## Export CSV Forensics

Format généré :

```csv
PID,Processus,Artefact,Adresse,Taille,Détails,Criticité
1337,malware.exe,"Phantom DLL",0x12340000,65536,"C:\evil.dll","ÉLEVÉE"
1337,malware.exe,"Process Hollowing",0x0,0,"Image PE modifiée","CRITIQUE"
1337,malware.exe,"Région RWX",0xA50000,4096,"Protection: RWX, Type: PRIVATE","HAUTE"
```

**Intégration SIEM** :
- Import dans Splunk pour corrélation temporelle
- Trigger alertes si criticité CRITIQUE
- Pivot vers VirusTotal avec hash processus

- --


## Logs Forensics

Fichier : `%TEMP%\WinTools_MemoryArtifactExtractor_log.txt`

Exemple :
```
14:32:15 - ========== MemoryArtifactExtractor - Démarrage ==========
14:32:16 - Début du scan processus
14:32:17 - Phantom DLL détecté: malware.exe -> C:\Temp\payload.dll
14:32:17 - Process Hollowing détecté: svchost.exe
14:32:18 - Scan terminé: 12 artefact(s) trouvé(s)
14:32:45 - Dump sauvegardé: C:\Users\analyst\AppData\Local\Temp\dump_1337_00A50000.dmp
14:33:02 - Export CSV terminé: C:\Reports\memory_artifacts.csv
```

- --


## Limitations Connues

1. **ASLR 64-bit** : La détection de process hollowing suppose base 0x400000 (32-bit). Pour 64-bit, nécessite lecture du PEB.

2. **Packing** : Les exécutables packés (UPX, Themida) peuvent générer faux positifs sur RWX (unpacking stub légitime).

3. **Privilèges** : Impossible d'analyser processus protégés (csrss.exe, smss.exe) même en Admin. Nécessite driver kernel.

4. **Performance** : Le scan complet peut prendre 30-60 secondes sur systèmes avec >100 processus.

- --


## 🚀 Scénarios d'Utilisation Avancés

### Scénario 1 : Incident Response APT

**Contexte** : Alerte EDR sur beacon C2 Cobalt Strike

**Workflow** :
1. Exécuter MemoryArtifactExtractor sur machine compromise
2. Filtrer artefacts criticité CRITIQUE/ÉLEVÉE
3. Dumper toutes régions RWX suspectes
4. Extraire shellcode et soumettre à sandbox (Any.run, Joe Sandbox)
5. Corréler IoCs avec réseau (IP C2, domaines)

### Scénario 2 : Analyse Malware Inconnu

**Contexte** : Détection heuristique AV sur binaire suspect

**Workflow** :
1. Exécuter binaire dans VM isolée
2. Lancer MemoryArtifactExtractor après 30 secondes
3. Identifier Phantom DLLs injectées
4. Dumper et désassembler avec IDA
5. Reverse engineering pour comprendre fonctionnalité

### Scénario 3 : Audit Sécurité Proactif

**Contexte** : Hardening poste de travail administrateur

**Workflow** :
1. Exécuter MemoryArtifactExtractor quotidiennement via tâche planifiée
2. Exporter CSV vers partage réseau sécurisé
3. Script PowerShell parse CSV et alerte si artefacts > 0
4. Investigation manuelle si détection

- --


## Outils Complémentaires

| Outil | Usage | Synergie avec MemoryArtifactExtractor |
|-------|-------|---------------------------------------|
| **Process Hacker** | Viewer processus avancé | Valider détections, voir threads/handles |
| **PE-bear** | Analyseur PE | Vérifier intégrité sections dumped |
| **Volatility** | Forensics mémoire RAM | Analyse post-mortem dump complet |
| **scdbg** | Émulateur shellcode | Analyser régions RWX dumpées |
| **YARA** | Pattern matching | Créer règles pour artefacts récurrents |

- --


## Références Forensics

### Techniques Malware

- **Process Hollowing** : [MITRE ATT&CK T1055.012](https://attack.mitre.org/techniques/T1055/012/)
- **Reflective DLL Injection** : [MITRE ATT&CK T1055.001](https://attack.mitre.org/techniques/T1055/001/)
- **RWX Shellcode** : [MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)

### Documentation API

- [EnumProcessModules](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules)
- [VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)
- [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)

### Livres Recommandés

- **"Practical Malware Analysis"** - Michael Sikorski (Chapitre 11 : Memory Analysis)
- **"The Art of Memory Forensics"** - Michael Hale Ligh (Chapitre 6 : Process Memory)
- **"Windows Internals 7th Ed."** - Pavel Yosifovich (Part 1, Chapitre 3 : Processes)

- --


## Support & Contact

**Développé par** : Ayi NEDJIMI Consultants
**Série** : WinToolsSuite - Forensics Mémoire & Processus (3/6)
**Licence** : Usage interne entreprise - Forensics & Security

**Note** : Cet outil est destiné uniquement à des fins légitimes d'investigation forensics et de sécurité. L'utilisateur est responsable de la conformité avec les lois locales en matière de vie privée et d'investigation numérique.

- --

*Dernière mise à jour : 2025-10-20*


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>
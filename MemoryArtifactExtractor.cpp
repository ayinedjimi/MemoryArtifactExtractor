/*******************************************************************************
 * MemoryArtifactExtractor - Extracteur d'Artefacts Mémoire
 *
 * Ayi NEDJIMI Consultants - Forensics & Security Suite
 * Série 3 : Outils Forensics Mémoire & Processus
 *
 * Description : Extraction d'artefacts mémoire suspects (DLLs injectées,
 *               process hollowing, reflective loading), dump régions RWX
 *
 * Fonctionnalités :
 *   - Énumération processus et modules chargés
 *   - Détection DLLs sans fichier sur disque (phantom DLLs)
 *   - Détection process hollowing (comparaison PE mémoire vs disque)
 *   - Scanner sections mémoire RWX suspectes
 *   - Dump régions mémoire pour analyse approfondie
 *   - Export rapport CSV UTF-8 BOM
 *
 * Compilation : Voir go.bat
 ******************************************************************************/

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")

// Constantes
#define WM_SCAN_COMPLETE (WM_USER + 1)
#define IDC_LISTVIEW 1001
#define IDC_BTN_SCAN 1002
#define IDC_BTN_DUMP 1003
#define IDC_BTN_EXPORT 1004
#define IDC_STATUS 1005

// RAII Handle Wrapper
class AutoHandle {
    HANDLE h;
public:
    AutoHandle(HANDLE handle = INVALID_HANDLE_VALUE) : h(handle) {}
    ~AutoHandle() { if (h != INVALID_HANDLE_VALUE && h != NULL) CloseHandle(h); }
    operator HANDLE() const { return h; }
    HANDLE* operator&() { return &h; }
    HANDLE get() const { return h; }
    bool isValid() const { return h != INVALID_HANDLE_VALUE && h != NULL; }
};

// Structure Artefact
struct MemoryArtifact {
    DWORD pid;
    std::wstring processName;
    std::wstring artifactType;
    PVOID address;
    SIZE_T size;
    std::wstring details;
    std::wstring criticality;
};

// Globales
HWND g_hListView = NULL;
HWND g_hStatus = NULL;
std::vector<MemoryArtifact> g_artifacts;
std::mutex g_mutex;
std::wofstream g_logFile;

// Prototypes
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void InitListView(HWND hList);
void Log(const std::wstring& message);
void ScanProcesses();
void DumpSelectedRegion();
void ExportToCSV();
bool IsPhantomDLL(HANDLE hProcess, HMODULE hModule);
bool DetectProcessHollowing(HANDLE hProcess, const std::wstring& exePath);
std::vector<MEMORY_BASIC_INFORMATION> ScanRWXRegions(HANDLE hProcess);
std::wstring GetCriticalityLevel(const std::wstring& artifactType);

// Point d'entrée
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    // Initialiser log
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring logPath = std::wstring(tempPath) + L"WinTools_MemoryArtifactExtractor_log.txt";
    g_logFile.open(logPath, std::ios::app);
    g_logFile.imbue(std::locale(g_logFile.getloc(), new std::codecvt_utf8<wchar_t>));

    Log(L"========== MemoryArtifactExtractor - Démarrage ==========");

    // Initialiser Common Controls
    INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icex);

    // Classe de fenêtre
    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"MemoryArtifactExtractorClass";
    wc.hIcon = LoadIcon(NULL, IDI_SHIELD);
    wc.hIconSm = LoadIcon(NULL, IDI_SHIELD);

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(NULL, L"Échec d'enregistrement de la classe!", L"Erreur", MB_ICONERROR);
        return 1;
    }

    // Créer fenêtre
    HWND hWnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        wc.lpszClassName,
        L"Memory Artifact Extractor - Ayi NEDJIMI Consultants",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1200, 700,
        NULL, NULL, hInstance, NULL
    );

    if (!hWnd) {
        MessageBoxW(NULL, L"Échec de création de fenêtre!", L"Erreur", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    // Boucle de messages
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    g_logFile.close();
    return (int)msg.wParam;
}

// Procédure de fenêtre
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HINSTANCE hInst;

    switch (msg) {
    case WM_CREATE: {
        hInst = ((LPCREATESTRUCT)lParam)->hInstance;

        // ListView
        g_hListView = CreateWindowExW(
            0, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
            10, 10, 1160, 550,
            hWnd, (HMENU)IDC_LISTVIEW, hInst, NULL
        );
        InitListView(g_hListView);

        // Boutons
        CreateWindowW(L"BUTTON", L"Scanner Processus",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, 570, 180, 30, hWnd, (HMENU)IDC_BTN_SCAN, hInst, NULL);

        CreateWindowW(L"BUTTON", L"Dump Région",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            200, 570, 150, 30, hWnd, (HMENU)IDC_BTN_DUMP, hInst, NULL);

        CreateWindowW(L"BUTTON", L"Exporter CSV",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            360, 570, 150, 30, hWnd, (HMENU)IDC_BTN_EXPORT, hInst, NULL);

        // Barre de statut
        g_hStatus = CreateWindowW(L"STATIC", L"Prêt",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            10, 610, 1160, 20, hWnd, (HMENU)IDC_STATUS, hInst, NULL);

        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_SCAN:
            SetWindowTextW(g_hStatus, L"Scan en cours...");
            std::thread(ScanProcesses).detach();
            break;
        case IDC_BTN_DUMP:
            DumpSelectedRegion();
            break;
        case IDC_BTN_EXPORT:
            ExportToCSV();
            break;
        }
        break;

    case WM_SCAN_COMPLETE:
        SetWindowTextW(g_hStatus, L"Scan terminé");
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// Initialiser ListView
void InitListView(HWND hList) {
    ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    LVCOLUMNW col = { LVCF_TEXT | LVCF_WIDTH };
    const wchar_t* headers[] = { L"PID", L"Processus", L"Artefact", L"Adresse", L"Taille", L"Détails", L"Criticité" };
    int widths[] = { 60, 180, 150, 120, 100, 350, 100 };

    for (int i = 0; i < 7; i++) {
        col.pszText = (LPWSTR)headers[i];
        col.cx = widths[i];
        ListView_InsertColumn(hList, i, &col);
    }
}

// Logging
void Log(const std::wstring& message) {
    SYSTEMTIME st;
    GetLocalTime(&st);

    std::wstringstream ss;
    ss << std::setfill(L'0')
       << std::setw(2) << st.wHour << L":"
       << std::setw(2) << st.wMinute << L":"
       << std::setw(2) << st.wSecond << L" - " << message << std::endl;

    if (g_logFile.is_open()) {
        g_logFile << ss.str();
        g_logFile.flush();
    }
}

// Scanner les processus
void ScanProcesses() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_artifacts.clear();
    ListView_DeleteAllItems(g_hListView);

    Log(L"Début du scan processus");

    // Snapshot processus
    AutoHandle hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!hSnapshot.isValid()) {
        Log(L"ERREUR: CreateToolhelp32Snapshot échoué");
        return;
    }

    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            // Ouvrir processus
            AutoHandle hProcess = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE, pe.th32ProcessID
            );

            if (!hProcess.isValid()) continue;

            // 1. Scanner modules (DLLs)
            HMODULE hMods[1024];
            DWORD cbNeeded;

            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                DWORD numModules = cbNeeded / sizeof(HMODULE);

                for (DWORD i = 0; i < numModules; i++) {
                    wchar_t modPath[MAX_PATH];
                    if (GetModuleFileNameExW(hProcess, hMods[i], modPath, MAX_PATH)) {
                        // Détecter Phantom DLLs
                        if (IsPhantomDLL(hProcess, hMods[i])) {
                            MemoryArtifact artifact;
                            artifact.pid = pe.th32ProcessID;
                            artifact.processName = pe.szExeFile;
                            artifact.artifactType = L"Phantom DLL";
                            artifact.address = hMods[i];
                            artifact.size = 0;
                            artifact.details = modPath;
                            artifact.criticality = L"ÉLEVÉE";
                            g_artifacts.push_back(artifact);

                            Log(L"Phantom DLL détecté: " + std::wstring(pe.szExeFile) + L" -> " + modPath);
                        }
                    }
                }
            }

            // 2. Détecter Process Hollowing
            wchar_t exePath[MAX_PATH];
            if (GetModuleFileNameExW(hProcess, NULL, exePath, MAX_PATH)) {
                if (DetectProcessHollowing(hProcess, exePath)) {
                    MemoryArtifact artifact;
                    artifact.pid = pe.th32ProcessID;
                    artifact.processName = pe.szExeFile;
                    artifact.artifactType = L"Process Hollowing";
                    artifact.address = NULL;
                    artifact.size = 0;
                    artifact.details = L"Image PE modifiée en mémoire";
                    artifact.criticality = L"CRITIQUE";
                    g_artifacts.push_back(artifact);

                    Log(L"Process Hollowing détecté: " + std::wstring(pe.szExeFile));
                }
            }

            // 3. Scanner régions RWX
            auto rwxRegions = ScanRWXRegions(hProcess);
            for (const auto& mbi : rwxRegions) {
                MemoryArtifact artifact;
                artifact.pid = pe.th32ProcessID;
                artifact.processName = pe.szExeFile;
                artifact.artifactType = L"Région RWX";
                artifact.address = mbi.BaseAddress;
                artifact.size = mbi.RegionSize;

                std::wstringstream ss;
                ss << L"Protection: RWX, Type: ";
                if (mbi.Type == MEM_PRIVATE) ss << L"PRIVATE";
                else if (mbi.Type == MEM_MAPPED) ss << L"MAPPED";
                else ss << L"IMAGE";
                artifact.details = ss.str();

                artifact.criticality = L"HAUTE";
                g_artifacts.push_back(artifact);
            }

        } while (Process32NextW(hSnapshot, &pe));
    }

    // Remplir ListView
    int index = 0;
    for (const auto& artifact : g_artifacts) {
        LVITEMW item = { LVIF_TEXT };
        item.iItem = index++;

        std::wstring pidStr = std::to_wstring(artifact.pid);
        item.pszText = (LPWSTR)pidStr.c_str();
        ListView_InsertItem(g_hListView, &item);

        ListView_SetItemText(g_hListView, item.iItem, 1, (LPWSTR)artifact.processName.c_str());
        ListView_SetItemText(g_hListView, item.iItem, 2, (LPWSTR)artifact.artifactType.c_str());

        std::wstringstream addrSS;
        addrSS << L"0x" << std::hex << std::uppercase << (ULONG_PTR)artifact.address;
        std::wstring addrStr = addrSS.str();
        ListView_SetItemText(g_hListView, item.iItem, 3, (LPWSTR)addrStr.c_str());

        std::wstring sizeStr = std::to_wstring(artifact.size);
        ListView_SetItemText(g_hListView, item.iItem, 4, (LPWSTR)sizeStr.c_str());
        ListView_SetItemText(g_hListView, item.iItem, 5, (LPWSTR)artifact.details.c_str());
        ListView_SetItemText(g_hListView, item.iItem, 6, (LPWSTR)artifact.criticality.c_str());
    }

    Log(L"Scan terminé: " + std::to_wstring(g_artifacts.size()) + L" artefact(s) trouvé(s)");
    PostMessage(GetParent(g_hListView), WM_SCAN_COMPLETE, 0, 0);
}

// Détecter Phantom DLL
bool IsPhantomDLL(HANDLE hProcess, HMODULE hModule) {
    wchar_t modPath[MAX_PATH];
    if (GetModuleFileNameExW(hProcess, hModule, modPath, MAX_PATH) == 0) {
        return false;
    }

    // Vérifier si le fichier existe sur disque
    return !PathFileExistsW(modPath);
}

// Détecter Process Hollowing
bool DetectProcessHollowing(HANDLE hProcess, const std::wstring& exePath) {
    // Lire PE header en mémoire
    IMAGE_DOS_HEADER dosHeader;
    SIZE_T bytesRead;

    if (!ReadProcessMemory(hProcess, (LPCVOID)0x400000, &dosHeader, sizeof(dosHeader), &bytesRead)) {
        return false;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    // Lire NT headers
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(0x400000 + dosHeader.e_lfanew),
                           &ntHeaders, sizeof(ntHeaders), &bytesRead)) {
        return false;
    }

    // Lire le fichier sur disque
    AutoHandle hFile = CreateFileW(exePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                    NULL, OPEN_EXISTING, 0, NULL);
    if (!hFile.isValid()) {
        return false;
    }

    IMAGE_DOS_HEADER diskDosHeader;
    DWORD dwRead;
    if (!ReadFile(hFile, &diskDosHeader, sizeof(diskDosHeader), &dwRead, NULL)) {
        return false;
    }

    SetFilePointer(hFile, diskDosHeader.e_lfanew, NULL, FILE_BEGIN);
    IMAGE_NT_HEADERS diskNtHeaders;
    if (!ReadFile(hFile, &diskNtHeaders, sizeof(diskNtHeaders), &dwRead, NULL)) {
        return false;
    }

    // Comparer EntryPoint
    return ntHeaders.OptionalHeader.AddressOfEntryPoint !=
           diskNtHeaders.OptionalHeader.AddressOfEntryPoint;
}

// Scanner régions RWX
std::vector<MEMORY_BASIC_INFORMATION> ScanRWXRegions(HANDLE hProcess) {
    std::vector<MEMORY_BASIC_INFORMATION> rwxRegions;
    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = NULL;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        // Détecter RWX
        if ((mbi.State == MEM_COMMIT) &&
            (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
            rwxRegions.push_back(mbi);
        }

        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    return rwxRegions;
}

// Dump région sélectionnée
void DumpSelectedRegion() {
    int selected = ListView_GetNextItem(g_hListView, -1, LVNI_SELECTED);
    if (selected == -1) {
        MessageBoxW(GetParent(g_hListView), L"Aucune région sélectionnée", L"Info", MB_ICONINFORMATION);
        return;
    }

    if (selected >= (int)g_artifacts.size()) return;

    const auto& artifact = g_artifacts[selected];

    if (artifact.address == NULL || artifact.size == 0) {
        MessageBoxW(GetParent(g_hListView), L"Impossible de dumper cet artefact", L"Erreur", MB_ICONWARNING);
        return;
    }

    // Ouvrir processus
    AutoHandle hProcess = OpenProcess(PROCESS_VM_READ, FALSE, artifact.pid);
    if (!hProcess.isValid()) {
        MessageBoxW(GetParent(g_hListView), L"Échec d'ouverture du processus", L"Erreur", MB_ICONERROR);
        return;
    }

    // Lire mémoire
    std::vector<BYTE> buffer(artifact.size);
    SIZE_T bytesRead;

    if (!ReadProcessMemory(hProcess, artifact.address, buffer.data(), artifact.size, &bytesRead)) {
        MessageBoxW(GetParent(g_hListView), L"Échec de lecture mémoire", L"Erreur", MB_ICONERROR);
        return;
    }

    // Sauvegarder dump
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    std::wstringstream filename;
    filename << tempPath << L"dump_" << artifact.pid << L"_"
             << std::hex << (ULONG_PTR)artifact.address << L".dmp";

    std::ofstream dumpFile(filename.str(), std::ios::binary);
    dumpFile.write((char*)buffer.data(), bytesRead);
    dumpFile.close();

    std::wstring msg = L"Dump sauvegardé: " + filename.str();
    MessageBoxW(GetParent(g_hListView), msg.c_str(), L"Succès", MB_ICONINFORMATION);
    Log(msg);
}

// Export CSV
void ExportToCSV() {
    wchar_t filename[MAX_PATH] = L"memory_artifacts.csv";

    OPENFILENAMEW ofn = { sizeof(OPENFILENAMEW) };
    ofn.hwndOwner = GetParent(g_hListView);
    ofn.lpstrFilter = L"CSV Files\0*.csv\0All Files\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (!GetSaveFileNameW(&ofn)) return;

    std::wofstream csvFile(filename, std::ios::binary);

    // UTF-8 BOM
    const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
    csvFile.write((wchar_t*)bom, sizeof(bom));
    csvFile.imbue(std::locale(csvFile.getloc(), new std::codecvt_utf8<wchar_t, 0x10ffff, std::consume_header>));

    // En-têtes
    csvFile << L"PID,Processus,Artefact,Adresse,Taille,Détails,Criticité\n";

    // Données
    for (const auto& artifact : g_artifacts) {
        csvFile << artifact.pid << L","
                << L"\"" << artifact.processName << L"\","
                << L"\"" << artifact.artifactType << L"\","
                << L"0x" << std::hex << (ULONG_PTR)artifact.address << L","
                << std::dec << artifact.size << L","
                << L"\"" << artifact.details << L"\","
                << L"\"" << artifact.criticality << L"\"\n";
    }

    csvFile.close();

    std::wstring msg = L"Export CSV terminé: " + std::wstring(filename);
    MessageBoxW(GetParent(g_hListView), msg.c_str(), L"Succès", MB_ICONINFORMATION);
    Log(msg);
}

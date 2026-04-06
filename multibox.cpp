#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>

#include <string>
#include <vector>
#include <iostream>
#include <filesystem>
#include <atomic>
#include <set>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;

static std::string W32Err(DWORD c) {
    char* b = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, c,
        MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPSTR)&b, 0, nullptr);
    std::string m = b ? b : "unknown";
    if (b) LocalFree(b);
    while (!m.empty() && (m.back() == '\n' || m.back() == '\r')) m.pop_back();
    return m;
}

[[noreturn]] static void Throw(const char* msg, DWORD e = GetLastError()) {
    throw std::runtime_error(std::string(msg) + ": [" + std::to_string(e) + "] " + W32Err(e));
}

struct HG {
    HANDLE h = nullptr;
    HG() = default;
    explicit HG(HANDLE x) : h(x) {}
    ~HG() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HG(HG&& o) noexcept : h(o.h) { o.h = nullptr; }
    HG& operator=(HG&& o) noexcept {
        if (this != &o) { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); h = o.h; o.h = nullptr; }
        return *this;
    }
    HG(const HG&) = delete; HG& operator=(const HG&) = delete;
    operator HANDLE() const { return h; }
    explicit operator bool() const { return h && h != INVALID_HANDLE_VALUE; }
};

static bool isAdmin() {
    BOOL e = FALSE; HANDLE t = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        TOKEN_ELEVATION te = {}; DWORD s = sizeof(te);
        GetTokenInformation(t, TokenElevation, &te, sizeof(te), &s);
        e = te.TokenIsElevated; CloseHandle(t);
    }
    return e != FALSE;
}

static void WriteGamePidFile(int jobId, DWORD pid) {
    wchar_t tempPath[MAX_PATH]; GetTempPathW(MAX_PATH, tempPath);
    wchar_t filePath[MAX_PATH];
    wsprintfW(filePath, L"%smultibox_game_pid_%d.tmp", tempPath, jobId);
    HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        char buf[32]; sprintf_s(buf, "%lu", pid);
        DWORD w = 0; WriteFile(hFile, buf, (DWORD)strlen(buf), &w, nullptr);
        CloseHandle(hFile);
        std::wcout << L"      [PID FILE] " << pid << L" -> " << filePath << std::endl;
    }
}

static void DeleteGamePidFile(int jobId) {
    wchar_t tempPath[MAX_PATH]; GetTempPathW(MAX_PATH, tempPath);
    wchar_t filePath[MAX_PATH];
    wsprintfW(filePath, L"%smultibox_game_pid_%d.tmp", tempPath, jobId);
    DeleteFileW(filePath);
}

static const std::set<std::wstring> g_configFiles = {
    L"config.json", L"imgui.ini", L"settings.json", L"config.ini", L"settings.ini"
};

static void PrepareConfigFiles(const fs::path& launcherDir, int instances) {
    std::wcout << L"\n  Preparing config files..." << std::endl;
    for (const auto& fileName : g_configFiles) {
        fs::path srcFile = launcherDir / fileName;
        if (!fs::exists(srcFile)) continue;
        std::wcout << L"    " << fileName << L" -> ";
        std::wstring baseName, ext;
        size_t dotPos = fileName.find_last_of(L'.');
        if (dotPos != std::wstring::npos) { baseName = fileName.substr(0, dotPos); ext = fileName.substr(dotPos); }
        else { baseName = fileName; ext = L""; }
        for (int i = 0; i < instances; i++) {
            std::wstring destName = baseName + L"_" + std::to_wstring(i) + ext;
            std::error_code ec;
            fs::copy_file(srcFile, launcherDir / destName, fs::copy_options::overwrite_existing, ec);
            if (i == 0) std::wcout << destName; else std::wcout << L", " << destName;
        }
        std::wcout << std::endl;
    }
}

static bool InjectDLL_CreateRemoteThread(HANDLE hProcess, const std::wstring& dllPath) {
    SIZE_T pathSize = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return false;
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), pathSize, nullptr)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); return false;
    }
    auto loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!loadLib) { VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); return false; }
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, loadLib, remoteMem, 0, nullptr);
    if (!hThread) { VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); return false; }
    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0; GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread); VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    return exitCode != 0;
}

static DWORD FindNewProcessByName(const std::wstring& procName, const std::set<DWORD>& skipPids) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
    DWORD found = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, procName.c_str()) == 0)
                if (!skipPids.count(pe.th32ProcessID)) { found = pe.th32ProcessID; break; }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return found;
}

struct ProcInfo { DWORD pid = 0; HG hProcess; HG hThread; };
struct Container { int id = 0; HG hJob; ProcInfo launcher; ProcInfo game; };

static ProcInfo LaunchLauncher(
    const std::wstring& exe, const std::wstring& args, const std::wstring& cwd,
    HANDLE hJob, int jobId, const std::wstring& dllPath)
{
    std::wstring cmdLine = L"\"" + exe + L"\"";
    if (!args.empty()) cmdLine += L" " + args;
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(0);

    SetEnvironmentVariableW(L"MULTIBOX_JOB_ID", std::to_wstring(jobId).c_str());

    STARTUPINFOW si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(exe.c_str(), cmdBuf.data(), nullptr, nullptr, FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE, nullptr, cwd.c_str(), &si, &pi))
        Throw("CreateProcessW (Launcher)");

    if (hJob) AssignProcessToJobObject(hJob, pi.hProcess);
    InjectDLL_CreateRemoteThread(pi.hProcess, dllPath);
    ResumeThread(pi.hThread);

    return { pi.dwProcessId, HG(pi.hProcess), HG(pi.hThread) };
}

static ProcInfo LaunchGameInSandbox(
    const std::wstring& sbStartExe,
    const std::wstring& gameExePath,
    const std::wstring& gameDir,
    int jobId,
    const std::wstring& boxName,
    const std::wstring& gameExeName,
    std::set<DWORD>& knownPids)
{
    std::wstring cmdLine = L"\"" + sbStartExe + L"\"";
    cmdLine += L" /box:" + boxName;
    cmdLine += L" \"" + gameExePath + L"\"";

    std::wcout << L"      [BOX]  " << boxName << std::endl;
    std::wcout << L"      [CMD]  " << cmdLine << std::endl;

    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(0);

    STARTUPINFOW si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE, nullptr, gameDir.c_str(), &si, &pi))
        Throw("CreateProcessW (Sandboxie Start)");

    std::wcout << L"      Waiting for game process..." << std::endl;
    Sleep(6000);

    DWORD gamePid = 0;
    for (int attempt = 0; attempt < 8 && !gamePid; attempt++) {
        gamePid = FindNewProcessByName(gameExeName, knownPids);
        if (!gamePid) {
            std::wcout << L"      [WAIT] Not found yet, attempt " << (attempt+1) << std::endl;
            Sleep(3000);
        }
    }

    if (gamePid) {
        std::wcout << L"      [FOUND] Game PID: " << gamePid << std::endl;
        WriteGamePidFile(jobId, gamePid);
        knownPids.insert(gamePid);
        std::wcout << L"      [OK] isolate.dll will be loaded via Sandboxie.ini InjectDll" << std::endl;
    } else {
        std::wcout << L"      [ERR] Game process not found!" << std::endl;
    }

    return { pi.dwProcessId, HG(pi.hProcess), HG(pi.hThread) };
}

struct Config {
    int instances = 1;
    std::wstring gameDir;
    std::wstring gameExe = L"GenshinImpact.exe";
    std::wstring launcherPath;
    std::wstring dllPath;
    std::wstring launcherArgs;
    std::wstring sbPath = L"C:\\Program Files\\Sandboxie-Plus\\Start.exe";
    DWORD launcherDelay = 3000;
    DWORD pairDelay    = 15000;
    bool autoGames = false;
    DWORD autoDelay = 25000;
    bool noCopy = false;
    std::vector<std::wstring> boxes;
};

static Config parseArgs(int argc, wchar_t* argv[]) {
    Config c;
    for (int i = 1; i < argc; i++) {
        std::wstring a = argv[i];
        if      (a == L"--instances" && i+1 < argc)      c.instances = _wtoi(argv[++i]);
        else if (a == L"--game-dir" && i+1 < argc)       c.gameDir = argv[++i];
        else if (a == L"--game-exe" && i+1 < argc)       c.gameExe = argv[++i];
        else if (a == L"--launcher" && i+1 < argc)       c.launcherPath = argv[++i];
        else if (a == L"--dll" && i+1 < argc)            c.dllPath = argv[++i];
        else if (a == L"--sb-path" && i+1 < argc)        c.sbPath = argv[++i];
        else if (a == L"--args" && i+1 < argc)           c.launcherArgs = argv[++i];
        else if (a == L"--launcher-delay" && i+1 < argc) c.launcherDelay = _wtoi(argv[++i]);
        else if (a == L"--pair-delay" && i+1 < argc)     c.pairDelay = _wtoi(argv[++i]);
        else if (a == L"--auto")                          c.autoGames = true;
        else if (a == L"--auto-delay" && i+1 < argc)     { c.autoGames = true; c.autoDelay = _wtoi(argv[++i]); }
        else if (a == L"--no-copy")                       c.noCopy = true;
        else if (a == L"--box" && i+1 < argc)            c.boxes.push_back(argv[++i]);
    }
    return c;
}

static bool validate(Config& c) {
    if (c.gameDir.empty())      { std::wcerr << L"[ERR] --game-dir required\n"; return false; }
    if (c.launcherPath.empty()) { std::wcerr << L"[ERR] --launcher required\n"; return false; }
    while (!c.gameDir.empty() && c.gameDir.back() == '\\') c.gameDir.pop_back();
    if (!fs::exists(c.gameDir))      { std::wcerr << L"[ERR] Game dir not found\n"; return false; }
    if (!fs::exists(c.launcherPath)) { std::wcerr << L"[ERR] Launcher not found\n"; return false; }
    if (!fs::exists(fs::path(c.gameDir) / c.gameExe)) { std::wcerr << L"[ERR] Game exe not found\n"; return false; }
    if (!fs::exists(c.sbPath)) { std::wcerr << L"[ERR] Sandboxie not found: " << c.sbPath << L"\n"; return false; }
    if (c.dllPath.empty()) {
        wchar_t mp[MAX_PATH]; GetModuleFileNameW(nullptr, mp, MAX_PATH);
        c.dllPath = (fs::path(mp).parent_path() / L"isolate.dll").wstring();
    }
    if (!fs::exists(c.dllPath)) { std::wcerr << L"[ERR] DLL not found: " << c.dllPath << L"\n"; return false; }
    c.dllPath = fs::absolute(c.dllPath).wstring();
    if (c.instances < 1 || c.instances > 20) { std::wcerr << L"[ERR] instances 1..20\n"; return false; }
    while ((int)c.boxes.size() < c.instances)
        c.boxes.push_back(L"Box" + std::to_wstring(c.boxes.size()));
    return true;
}

static std::atomic<bool> g_stop{ false };
static BOOL WINAPI CtrlH(DWORD t) {
    if (t == CTRL_C_EVENT || t == CTRL_CLOSE_EVENT || t == CTRL_BREAK_EVENT)
    { g_stop = true; return TRUE; } return FALSE;
}

static void WaitEnter(const wchar_t* prompt) {
    std::wcout << prompt << std::endl;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    while (!g_stop) {
        DWORD avail = 0; INPUT_RECORD ir[8];
        if (PeekConsoleInput(hStdin, ir, 8, &avail) && avail > 0) {
            for (DWORD j = 0; j < avail; j++) {
                if (ir[j].EventType == KEY_EVENT && ir[j].Event.KeyEvent.bKeyDown &&
                    ir[j].Event.KeyEvent.wVirtualKeyCode == VK_RETURN)
                { FlushConsoleInputBuffer(hStdin); return; }
            }
            ReadConsoleInput(hStdin, ir, avail, &avail);
        }
        Sleep(100);
    }
}

#ifdef __MINGW32__
int main() {
    int argc; LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 1;
#else
int wmain(int argc, wchar_t* argv[]) {
#endif
    SetConsoleOutputCP(65001); SetConsoleCP(65001);

    std::wcout <<
        L"\n  ══════════════════════════════════════════════════\n"
        L"    Multibox v24.0\n"
        L"    Sandboxie InjectDll mode (no OpenProcess needed)\n"
        L"  ══════════════════════════════════════════════════\n\n";

    Config cfg = parseArgs(argc, argv);
    if (!validate(cfg)) {
#ifdef __MINGW32__
        LocalFree(argv);
#endif
        return 1;
    }
    if (!isAdmin()) {
        std::wcerr << L"  [!] Run as Administrator!\n";
#ifdef __MINGW32__
        LocalFree(argv);
#endif
        return 1;
    }

    SetConsoleCtrlHandler(CtrlH, TRUE);

    for (int i = 0; i < cfg.instances; i++) DeleteGamePidFile(i);

    fs::path launcherPath = fs::absolute(cfg.launcherPath);
    fs::path launcherDir = launcherPath.parent_path();
    fs::path gameExe = fs::path(cfg.gameDir) / cfg.gameExe;

    std::wcout << L"  Instances:    " << cfg.instances << std::endl;
    std::wcout << L"  Sandboxie:    " << cfg.sbPath << std::endl;
    std::wcout << L"  Boxes:        ";
    for (int i = 0; i < cfg.instances; i++) {
        if (i > 0) std::wcout << L", ";
        std::wcout << L"\"" << cfg.boxes[i] << L"\"";
    }
    std::wcout << std::endl;
    std::wcout << L"  Game dir:     " << cfg.gameDir << std::endl;
    std::wcout << L"  Launcher:     " << launcherPath.wstring() << std::endl;
    std::wcout << L"  DLL:          " << cfg.dllPath << std::endl;

    std::wcout << L"\n  ════════════════════════════════════════════════════\n";
    std::wcout << L"  Sandboxie.ini must contain for each box:\n";
    std::wcout << L"  ════════════════════════════════════════════════════\n\n";
    for (int i = 0; i < cfg.instances; i++) {
        std::wcout << L"  [" << cfg.boxes[i] << L"]\n";
        std::wcout << L"  InjectDll=" << cfg.dllPath << L"\n";
        std::wcout << L"  SetEnvironmentVariable=MULTIBOX_JOB_ID=" << i << L"\n\n";
    }
    std::wcout << L"  ════════════════════════════════════════════════════\n\n";

    if (!cfg.noCopy) PrepareConfigFiles(launcherDir, cfg.instances);

    std::vector<Container> containers(cfg.instances);
    std::set<DWORD> knownGamePids;

    try {
        for (int i = 0; i < cfg.instances && !g_stop; i++) {

            std::wcout <<
                L"\n  ┌──────────────────────────────────────────┐\n  │  PAIR "
                << i << L": Launcher + Game"
                L"                    │\n"
                L"  └──────────────────────────────────────────┘\n" << std::endl;

            containers[i].id = i;

            std::wstring jobName = L"Multibox_Launcher_Job_" + std::to_wstring(i);
            HANDLE hJob = CreateJobObjectW(nullptr, jobName.c_str());
            if (!hJob) Throw("CreateJobObject");
            containers[i].hJob = HG(hJob);

            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jli = {};
            jli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jli, sizeof(jli));

            std::wcout << L"  [" << i << L"] Starting Launcher..." << std::endl;
            containers[i].launcher = LaunchLauncher(
                launcherPath.wstring(), cfg.launcherArgs, launcherDir.wstring(),
                hJob, i, cfg.dllPath);
            std::wcout << L"      PID: " << containers[i].launcher.pid << std::endl;

            Sleep(cfg.launcherDelay);
            if (g_stop) goto shutdown;

            if (cfg.autoGames) {
                std::wcout << L"  [" << i << L"] Auto: waiting " << cfg.autoDelay/1000 << L"s..." << std::endl;
                Sleep(cfg.autoDelay);
            } else {
                wchar_t prompt[128];
                wsprintfW(prompt, L"  [%d] >>> Press Play in Launcher[%d], then press ENTER <<<", i, i);
                WaitEnter(prompt);
            }
            if (g_stop) goto shutdown;

            std::wcout << L"  [" << i << L"] Starting Game in \"" << cfg.boxes[i] << L"\"..." << std::endl;
            containers[i].game = LaunchGameInSandbox(
                cfg.sbPath, gameExe.wstring(), cfg.gameDir,
                i, cfg.boxes[i], cfg.gameExe, knownGamePids);

            if (i < cfg.instances - 1 && !g_stop) {
                std::wcout << L"\n  Waiting " << cfg.pairDelay/1000 << L"s before next pair...\n" << std::endl;
                Sleep(cfg.pairDelay);
            }
        }

        if (g_stop) goto shutdown;

        std::wcout <<
            L"\n  ┌──────────────────────────────────────────┐\n"
            L"  │  ALL PAIRS LAUNCHED                      │\n"
            L"  └──────────────────────────────────────────┘\n" << std::endl;
        std::wcout << L"  Close this window to stop.\n" << std::endl;

        while (!g_stop) {
            bool alive = false;
            for (auto& c : containers) {
                if (c.launcher.hProcess) {
                    DWORD e = 0; GetExitCodeProcess(c.launcher.hProcess, &e);
                    if (e == STILL_ACTIVE) alive = true;
                }
            }
            if (!alive) break;
            Sleep(2000);
        }

    shutdown:
        for (int i = 0; i < cfg.instances; i++) DeleteGamePidFile(i);
        if (g_stop) {
            std::wcout << L"\n  Terminating..." << std::endl;
            for (auto& c : containers) c.hJob = HG();
            Sleep(2000);
        }

    } catch (const std::exception& e) {
        std::cerr << "\n[FATAL] " << e.what() << std::endl;
        for (auto& c : containers) c.hJob = HG();
        for (int i = 0; i < cfg.instances; i++) DeleteGamePidFile(i);
#ifdef __MINGW32__
        LocalFree(argv);
#endif
        return 1;
    }

#ifdef __MINGW32__
    LocalFree(argv);
#endif
    return 0;
}


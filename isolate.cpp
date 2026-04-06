#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winternl.h>
#include <string>
#include <set>
#include <cstdio>
#include <algorithm>

#pragma comment(lib, "ntdll.lib")

static DWORD g_myJobId = 0;
static std::set<DWORD> g_jobPids;
static std::set<DWORD> g_extraPids;
static CRITICAL_SECTION g_cs;
static HANDLE g_jobHandle = nullptr;
static wchar_t g_suffix[32] = {};
static HANDLE g_watchThread = nullptr;
static volatile bool g_watchStop = false;

static const std::set<std::wstring> g_redirectFiles = {
    L"config.json", L"imgui.ini", L"settings.json",
    L"config.ini",  L"settings.ini", L"preferences.json",
    L"launcher.json", L"window.ini", L"cache.json"
};

static void DbgLog(const char* fmt, ...) {
    char buf[512]; va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    OutputDebugStringA(buf);
}

static DWORD ResolveJobId() {
    wchar_t buf[16] = {};
    if (GetEnvironmentVariableW(L"MULTIBOX_JOB_ID", buf, 16)) {
        DWORD id = (DWORD)_wtoi(buf);
        DbgLog("[isolate] JobId from env: %d\n", id);
        return id;
    }
    ULONG_PTR ppid = 0;
    {
        typedef NTSTATUS(NTAPI* pfnNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto NtQIP = (pfnNtQIP)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
        if (NtQIP) { ULONG_PTR pbi[6]={}; NtQIP(GetCurrentProcess(),0,pbi,sizeof(pbi),nullptr); ppid=pbi[5]; }
    }
    wchar_t tempPath[MAX_PATH]; GetTempPathW(MAX_PATH, tempPath);
    if (ppid) {
        wchar_t fp[MAX_PATH]; wsprintfW(fp,L"%sisolate_jobid_%lu.tmp",tempPath,(DWORD)ppid);
        HANDLE h=CreateFileW(fp,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
        if (h!=INVALID_HANDLE_VALUE) { char d[16]={}; DWORD r=0; ReadFile(h,d,15,&r,nullptr); CloseHandle(h); return (DWORD)atoi(d); }
    }
    DbgLog("[isolate] WARNING: JobId not found, defaulting to 0\n");
    return 0;
}

static void RefreshExtraPids() {
    wchar_t tempPath[MAX_PATH]; GetTempPathW(MAX_PATH, tempPath);
    wchar_t filePath[MAX_PATH];
    wsprintfW(filePath, L"%smultibox_game_pid_%d.tmp", tempPath, g_myJobId);
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;
    char data[64]={}; DWORD read=0;
    ReadFile(hFile, data, sizeof(data)-1, &read, nullptr);
    CloseHandle(hFile);
    if (!read) return;
    char* ctx=nullptr;
    char* tok=strtok_s(data," ,\n\r",&ctx);
    while (tok) {
        DWORD pid=(DWORD)atol(tok);
        if (pid>0) {
            EnterCriticalSection(&g_cs);
            if (!g_extraPids.count(pid)) { g_extraPids.insert(pid); DbgLog("[isolate] Extra PID %lu added\n",pid); }
            LeaveCriticalSection(&g_cs);
        }
        tok=strtok_s(nullptr," ,\n\r",&ctx);
    }
}

static DWORD WINAPI WatchThread(LPVOID) {
    while (!g_watchStop) { RefreshExtraPids(); Sleep(2000); }
    return 0;
}

#pragma pack(push,1)
struct JmpPatch { BYTE ff25[6]={0xFF,0x25,0,0,0,0}; UINT64 addr=0; };
#pragma pack(pop)
struct HookCtx { void* target=nullptr; BYTE saved[14]={}; bool installed=false; };

static bool InstallHook(HookCtx& ctx, void* target, void* detour) {
    ctx.target=target; ctx.installed=false;
    DWORD op; if(!VirtualProtect(target,14,PAGE_EXECUTE_READWRITE,&op)) return false;
    memcpy(ctx.saved,target,14);
    JmpPatch p; p.addr=(UINT64)detour; memcpy(target,&p,sizeof(p));
    VirtualProtect(target,14,op,&op); ctx.installed=true; return true;
}
static void UnhookTemp(HookCtx& ctx) {
    if(!ctx.installed) return; DWORD op;
    VirtualProtect(ctx.target,14,PAGE_EXECUTE_READWRITE,&op);
    memcpy(ctx.target,ctx.saved,14); VirtualProtect(ctx.target,14,op,&op);
}
static void RehookTemp(HookCtx& ctx, void* detour) {
    if(!ctx.installed) return; DWORD op;
    VirtualProtect(ctx.target,14,PAGE_EXECUTE_READWRITE,&op);
    JmpPatch p; p.addr=(UINT64)detour; memcpy(ctx.target,&p,sizeof(p));
    VirtualProtect(ctx.target,14,op,&op);
}
#define CALL_ORIG(hookCtx,detourFn,origType,call_expr) \
    [&](){ EnterCriticalSection(&g_cs); UnhookTemp(hookCtx); \
           auto _r=call_expr; RehookTemp(hookCtx,(void*)detourFn); \
           LeaveCriticalSection(&g_cs); return _r; }()

static HookCtx g_hookNtQSI,g_hookCreateMutexW,g_hookCreateMutexA,g_hookOpenMutexW,g_hookOpenMutexA;
static HookCtx g_hookCreateMutexExW,g_hookCreateEventW,g_hookCreateEventA,g_hookOpenEventW,g_hookOpenEventA;
static HookCtx g_hookCreateFileW,g_hookCreateFileA,g_hookDeleteFileW,g_hookDeleteFileA;
static HookCtx g_hookGetFileAttributesW,g_hookGetFileAttributesA;

typedef NTSTATUS(NTAPI* pfnNtQSI)(ULONG,PVOID,ULONG,PULONG);
typedef HANDLE(WINAPI* pfnCreateMutexW)(LPSECURITY_ATTRIBUTES,BOOL,LPCWSTR);
typedef HANDLE(WINAPI* pfnCreateMutexA)(LPSECURITY_ATTRIBUTES,BOOL,LPCSTR);
typedef HANDLE(WINAPI* pfnOpenMutexW)(DWORD,BOOL,LPCWSTR);
typedef HANDLE(WINAPI* pfnOpenMutexA)(DWORD,BOOL,LPCSTR);
typedef HANDLE(WINAPI* pfnCreateMutexExW)(LPSECURITY_ATTRIBUTES,LPCWSTR,DWORD,DWORD);
typedef HANDLE(WINAPI* pfnCreateEventW)(LPSECURITY_ATTRIBUTES,BOOL,BOOL,LPCWSTR);
typedef HANDLE(WINAPI* pfnCreateEventA)(LPSECURITY_ATTRIBUTES,BOOL,BOOL,LPCSTR);
typedef HANDLE(WINAPI* pfnOpenEventW)(DWORD,BOOL,LPCWSTR);
typedef HANDLE(WINAPI* pfnOpenEventA)(DWORD,BOOL,LPCSTR);
typedef HANDLE(WINAPI* pfnCreateFileW)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef HANDLE(WINAPI* pfnCreateFileA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef BOOL(WINAPI* pfnDeleteFileW)(LPCWSTR);
typedef BOOL(WINAPI* pfnDeleteFileA)(LPCSTR);
typedef DWORD(WINAPI* pfnGetFileAttributesW)(LPCWSTR);
typedef DWORD(WINAPI* pfnGetFileAttributesA)(LPCSTR);

static pfnNtQSI g_origNtQSI=nullptr;
static pfnCreateMutexW g_origCreateMutexW=nullptr; static pfnCreateMutexA g_origCreateMutexA=nullptr;
static pfnOpenMutexW g_origOpenMutexW=nullptr;     static pfnOpenMutexA g_origOpenMutexA=nullptr;
static pfnCreateMutexExW g_origCreateMutexExW=nullptr;
static pfnCreateEventW g_origCreateEventW=nullptr; static pfnCreateEventA g_origCreateEventA=nullptr;
static pfnOpenEventW g_origOpenEventW=nullptr;     static pfnOpenEventA g_origOpenEventA=nullptr;
static pfnCreateFileW g_origCreateFileW=nullptr;   static pfnCreateFileA g_origCreateFileA=nullptr;
static pfnDeleteFileW g_origDeleteFileW=nullptr;   static pfnDeleteFileA g_origDeleteFileA=nullptr;
static pfnGetFileAttributesW g_origGetFileAttributesW=nullptr;
static pfnGetFileAttributesA g_origGetFileAttributesA=nullptr;

static std::wstring ToLower(const std::wstring& s) {
    std::wstring r=s; std::transform(r.begin(),r.end(),r.begin(),::towlower); return r;
}
static std::wstring GetFileName(const std::wstring& p) {
    size_t pos=p.find_last_of(L"\\/"); return pos!=std::wstring::npos?p.substr(pos+1):p;
}
static std::wstring GetDirPath(const std::wstring& p) {
    size_t pos=p.find_last_of(L"\\/"); return pos!=std::wstring::npos?p.substr(0,pos):L".";
}
static bool ShouldRedirect(const std::wstring& f) { return g_redirectFiles.count(ToLower(f))>0; }
static std::wstring GetRedirectedPath(const std::wstring& orig) {
    std::wstring fn=GetFileName(orig); if(!ShouldRedirect(fn)) return orig;
    size_t dot=fn.find_last_of(L'.');
    std::wstring base=dot!=std::wstring::npos&&dot>0?fn.substr(0,dot):fn;
    std::wstring ext =dot!=std::wstring::npos&&dot>0?fn.substr(dot):L"";
    std::wstring nn=base+L"_"+std::to_wstring(g_myJobId)+ext;
    std::wstring dir=GetDirPath(orig);
    return (dir==L"."||dir.empty())?nn:dir+L"\\"+nn;
}

static void RefreshJobPids() {
    EnterCriticalSection(&g_cs);
    if (!g_jobHandle) {
        wchar_t jn[64]; wsprintfW(jn,L"Multibox_Launcher_Job_%d",g_myJobId);
        g_jobHandle=OpenJobObjectW(JOB_OBJECT_QUERY,FALSE,jn);
    }
    if (g_jobHandle) {
        BYTE buf[4096]; auto* list=(JOBOBJECT_BASIC_PROCESS_ID_LIST*)buf;
        if (QueryInformationJobObject(g_jobHandle,JobObjectBasicProcessIdList,buf,sizeof(buf),nullptr)) {
            g_jobPids.clear();
            for (DWORD i=0;i<list->NumberOfProcessIdsInList;i++) g_jobPids.insert((DWORD)list->ProcessIdList[i]);
        }
    }
    LeaveCriticalSection(&g_cs);
}

static bool IsPidInMyJob(DWORD pid) {
    if (pid==0||pid==4||pid==GetCurrentProcessId()) return true;
    EnterCriticalSection(&g_cs);
    bool f=g_jobPids.count(pid)>0||g_extraPids.count(pid)>0;
    LeaveCriticalSection(&g_cs);
    return f;
}

static NTSTATUS NTAPI HookedNtQSI(ULONG cls,PVOID si,ULONG sil,PULONG rl) {
    NTSTATUS st=CALL_ORIG(g_hookNtQSI,HookedNtQSI,pfnNtQSI,
        g_origNtQSI((SYSTEM_INFORMATION_CLASS)cls,si,sil,rl));
    if (cls!=5||st!=0||!si) return st;
    RefreshJobPids();
    SYSTEM_PROCESS_INFORMATION* prev=nullptr;
    SYSTEM_PROCESS_INFORMATION* curr=(SYSTEM_PROCESS_INFORMATION*)si;
    while (true) {
        DWORD pid=(DWORD)(ULONG_PTR)curr->UniqueProcessId;
        bool keep=IsPidInMyJob(pid);
        if (!keep) {
            if (prev) {
                if (!curr->NextEntryOffset){prev->NextEntryOffset=0;break;}
                else prev->NextEntryOffset+=curr->NextEntryOffset;
            } else {
                if (!curr->NextEntryOffset) break;
                ULONG off=curr->NextEntryOffset;
                memmove(curr,(BYTE*)curr+off,sil-((BYTE*)curr-(BYTE*)si+off));
                continue;
            }
        } else prev=curr;
        if (!curr->NextEntryOffset) break;
        curr=(SYSTEM_PROCESS_INFORMATION*)((BYTE*)curr+curr->NextEntryOffset);
    }
    return st;
}

static std::wstring SuffixW(LPCWSTR n){if(!n)return L"";return std::wstring(n)+g_suffix;}
static std::string SuffixA(LPCSTR n){
    if(!n)return "";char b[16];sprintf(b,"_MB%d",g_myJobId);return std::string(n)+b;
}

static HANDLE WINAPI HookedCreateMutexW(LPSECURITY_ATTRIBUTES a,BOOL o,LPCWSTR n){
    if(n){auto s=SuffixW(n);return CALL_ORIG(g_hookCreateMutexW,HookedCreateMutexW,pfnCreateMutexW,g_origCreateMutexW(a,o,s.c_str()));}
    return CALL_ORIG(g_hookCreateMutexW,HookedCreateMutexW,pfnCreateMutexW,g_origCreateMutexW(a,o,n));}
static HANDLE WINAPI HookedCreateMutexA(LPSECURITY_ATTRIBUTES a,BOOL o,LPCSTR n){
    if(n){auto s=SuffixA(n);return CALL_ORIG(g_hookCreateMutexA,HookedCreateMutexA,pfnCreateMutexA,g_origCreateMutexA(a,o,s.c_str()));}
    return CALL_ORIG(g_hookCreateMutexA,HookedCreateMutexA,pfnCreateMutexA,g_origCreateMutexA(a,o,n));}
static HANDLE WINAPI HookedOpenMutexW(DWORD d,BOOL i,LPCWSTR n){
    if(n){auto s=SuffixW(n);return CALL_ORIG(g_hookOpenMutexW,HookedOpenMutexW,pfnOpenMutexW,g_origOpenMutexW(d,i,s.c_str()));}
    return CALL_ORIG(g_hookOpenMutexW,HookedOpenMutexW,pfnOpenMutexW,g_origOpenMutexW(d,i,n));}
static HANDLE WINAPI HookedOpenMutexA(DWORD d,BOOL i,LPCSTR n){
    if(n){auto s=SuffixA(n);return CALL_ORIG(g_hookOpenMutexA,HookedOpenMutexA,pfnOpenMutexA,g_origOpenMutexA(d,i,s.c_str()));}
    return CALL_ORIG(g_hookOpenMutexA,HookedOpenMutexA,pfnOpenMutexA,g_origOpenMutexA(d,i,n));}
static HANDLE WINAPI HookedCreateMutexExW(LPSECURITY_ATTRIBUTES a,LPCWSTR n,DWORD f,DWORD d){
    if(n){auto s=SuffixW(n);return CALL_ORIG(g_hookCreateMutexExW,HookedCreateMutexExW,pfnCreateMutexExW,g_origCreateMutexExW(a,s.c_str(),f,d));}
    return CALL_ORIG(g_hookCreateMutexExW,HookedCreateMutexExW,pfnCreateMutexExW,g_origCreateMutexExW(a,n,f,d));}

static HANDLE WINAPI HookedCreateEventW(LPSECURITY_ATTRIBUTES a,BOOL m,BOOL i,LPCWSTR n){
    if(n){auto s=SuffixW(n);return CALL_ORIG(g_hookCreateEventW,HookedCreateEventW,pfnCreateEventW,g_origCreateEventW(a,m,i,s.c_str()));}
    return CALL_ORIG(g_hookCreateEventW,HookedCreateEventW,pfnCreateEventW,g_origCreateEventW(a,m,i,n));}
static HANDLE WINAPI HookedCreateEventA(LPSECURITY_ATTRIBUTES a,BOOL m,BOOL i,LPCSTR n){
    if(n){auto s=SuffixA(n);return CALL_ORIG(g_hookCreateEventA,HookedCreateEventA,pfnCreateEventA,g_origCreateEventA(a,m,i,s.c_str()));}
    return CALL_ORIG(g_hookCreateEventA,HookedCreateEventA,pfnCreateEventA,g_origCreateEventA(a,m,i,n));}
static HANDLE WINAPI HookedOpenEventW(DWORD d,BOOL i,LPCWSTR n){
    if(n){auto s=SuffixW(n);return CALL_ORIG(g_hookOpenEventW,HookedOpenEventW,pfnOpenEventW,g_origOpenEventW(d,i,s.c_str()));}
    return CALL_ORIG(g_hookOpenEventW,HookedOpenEventW,pfnOpenEventW,g_origOpenEventW(d,i,n));}
static HANDLE WINAPI HookedOpenEventA(DWORD d,BOOL i,LPCSTR n){
    if(n){auto s=SuffixA(n);return CALL_ORIG(g_hookOpenEventA,HookedOpenEventA,pfnOpenEventA,g_origOpenEventA(d,i,s.c_str()));}
    return CALL_ORIG(g_hookOpenEventA,HookedOpenEventA,pfnOpenEventA,g_origOpenEventA(d,i,n));}

static HANDLE WINAPI HookedCreateFileW(LPCWSTR f,DWORD da,DWORD sh,LPSECURITY_ATTRIBUTES sa,DWORD cd,DWORD fa,HANDLE ht){
    if(f){auto fn=GetFileName(f);if(ShouldRedirect(fn)){auto np=GetRedirectedPath(f);
        return CALL_ORIG(g_hookCreateFileW,HookedCreateFileW,pfnCreateFileW,g_origCreateFileW(np.c_str(),da,sh,sa,cd,fa,ht));}}
    return CALL_ORIG(g_hookCreateFileW,HookedCreateFileW,pfnCreateFileW,g_origCreateFileW(f,da,sh,sa,cd,fa,ht));}
static HANDLE WINAPI HookedCreateFileA(LPCSTR f,DWORD da,DWORD sh,LPSECURITY_ATTRIBUTES sa,DWORD cd,DWORD fa,HANDLE ht){
    if(f){int l=MultiByteToWideChar(CP_ACP,0,f,-1,nullptr,0);if(l>0){std::wstring wp(l-1,0);MultiByteToWideChar(CP_ACP,0,f,-1,&wp[0],l);
        auto fn=GetFileName(wp);if(ShouldRedirect(fn)){auto np=GetRedirectedPath(wp);
            int al=WideCharToMultiByte(CP_ACP,0,np.c_str(),-1,nullptr,0,nullptr,nullptr);
            if(al>0){std::string ap(al-1,0);WideCharToMultiByte(CP_ACP,0,np.c_str(),-1,&ap[0],al,nullptr,nullptr);
                return CALL_ORIG(g_hookCreateFileA,HookedCreateFileA,pfnCreateFileA,g_origCreateFileA(ap.c_str(),da,sh,sa,cd,fa,ht));}}}}
    return CALL_ORIG(g_hookCreateFileA,HookedCreateFileA,pfnCreateFileA,g_origCreateFileA(f,da,sh,sa,cd,fa,ht));}
static BOOL WINAPI HookedDeleteFileW(LPCWSTR f){
    if(f){auto fn=GetFileName(f);if(ShouldRedirect(fn)){auto np=GetRedirectedPath(f);
        return CALL_ORIG(g_hookDeleteFileW,HookedDeleteFileW,pfnDeleteFileW,g_origDeleteFileW(np.c_str()));}}
    return CALL_ORIG(g_hookDeleteFileW,HookedDeleteFileW,pfnDeleteFileW,g_origDeleteFileW(f));}
static BOOL WINAPI HookedDeleteFileA(LPCSTR f){
    if(f){int l=MultiByteToWideChar(CP_ACP,0,f,-1,nullptr,0);if(l>0){std::wstring wp(l-1,0);MultiByteToWideChar(CP_ACP,0,f,-1,&wp[0],l);
        auto fn=GetFileName(wp);if(ShouldRedirect(fn)){auto np=GetRedirectedPath(wp);
            int al=WideCharToMultiByte(CP_ACP,0,np.c_str(),-1,nullptr,0,nullptr,nullptr);
            if(al>0){std::string ap(al-1,0);WideCharToMultiByte(CP_ACP,0,np.c_str(),-1,&ap[0],al,nullptr,nullptr);
                return CALL_ORIG(g_hookDeleteFileA,HookedDeleteFileA,pfnDeleteFileA,g_origDeleteFileA(ap.c_str()));}}}}
    return CALL_ORIG(g_hookDeleteFileA,HookedDeleteFileA,pfnDeleteFileA,g_origDeleteFileA(f));}
static DWORD WINAPI HookedGetFileAttributesW(LPCWSTR f){
    if(f){auto fn=GetFileName(f);if(ShouldRedirect(fn)){auto np=GetRedirectedPath(f);
        return CALL_ORIG(g_hookGetFileAttributesW,HookedGetFileAttributesW,pfnGetFileAttributesW,g_origGetFileAttributesW(np.c_str()));}}
    return CALL_ORIG(g_hookGetFileAttributesW,HookedGetFileAttributesW,pfnGetFileAttributesW,g_origGetFileAttributesW(f));}
static DWORD WINAPI HookedGetFileAttributesA(LPCSTR f){
    if(f){int l=MultiByteToWideChar(CP_ACP,0,f,-1,nullptr,0);if(l>0){std::wstring wp(l-1,0);MultiByteToWideChar(CP_ACP,0,f,-1,&wp[0],l);
        auto fn=GetFileName(wp);if(ShouldRedirect(fn)){auto np=GetRedirectedPath(wp);
            int al=WideCharToMultiByte(CP_ACP,0,np.c_str(),-1,nullptr,0,nullptr,nullptr);
            if(al>0){std::string ap(al-1,0);WideCharToMultiByte(CP_ACP,0,np.c_str(),-1,&ap[0],al,nullptr,nullptr);
                return CALL_ORIG(g_hookGetFileAttributesA,HookedGetFileAttributesA,pfnGetFileAttributesA,g_origGetFileAttributesA(ap.c_str()));}}}}
    return CALL_ORIG(g_hookGetFileAttributesA,HookedGetFileAttributesA,pfnGetFileAttributesA,g_origGetFileAttributesA(f));}

static bool InstallHooks() {
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    HMODULE kb=GetModuleHandleW(L"KernelBase.dll");
    HMODULE k32=GetModuleHandleW(L"kernel32.dll");
    if(!ntdll) return false;
    HMODULE km=kb?kb:k32; if(!km) return false;
    wsprintfW(g_suffix,L"_MB%d",g_myJobId);
    #define TRY_HOOK(ctx,mod,name,fn){auto p=GetProcAddress(mod,name);if(p){g_orig##ctx=(pfn##ctx)p;InstallHook(g_hook##ctx,(void*)p,(void*)fn);}}
    TRY_HOOK(NtQSI,ntdll,"NtQuerySystemInformation",HookedNtQSI)
    TRY_HOOK(CreateMutexW,km,"CreateMutexW",HookedCreateMutexW)
    TRY_HOOK(CreateMutexA,km,"CreateMutexA",HookedCreateMutexA)
    TRY_HOOK(OpenMutexW,km,"OpenMutexW",HookedOpenMutexW)
    TRY_HOOK(OpenMutexA,km,"OpenMutexA",HookedOpenMutexA)
    TRY_HOOK(CreateMutexExW,km,"CreateMutexExW",HookedCreateMutexExW)
    TRY_HOOK(CreateEventW,km,"CreateEventW",HookedCreateEventW)
    TRY_HOOK(CreateEventA,km,"CreateEventA",HookedCreateEventA)
    TRY_HOOK(OpenEventW,km,"OpenEventW",HookedOpenEventW)
    TRY_HOOK(OpenEventA,km,"OpenEventA",HookedOpenEventA)
    TRY_HOOK(CreateFileW,km,"CreateFileW",HookedCreateFileW)
    TRY_HOOK(CreateFileA,km,"CreateFileA",HookedCreateFileA)
    TRY_HOOK(DeleteFileW,km,"DeleteFileW",HookedDeleteFileW)
    TRY_HOOK(DeleteFileA,km,"DeleteFileA",HookedDeleteFileA)
    TRY_HOOK(GetFileAttributesW,km,"GetFileAttributesW",HookedGetFileAttributesW)
    TRY_HOOK(GetFileAttributesA,km,"GetFileAttributesA",HookedGetFileAttributesA)
    #undef TRY_HOOK
    DbgLog("[isolate] Hooks installed. Instance %d\n",g_myJobId);
    return g_hookNtQSI.installed;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    switch(reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_cs);
        g_myJobId=ResolveJobId();
        DbgLog("[isolate] Loaded PID %d, Instance %d\n",GetCurrentProcessId(),g_myJobId);
        InstallHooks();
        RefreshExtraPids();
        g_watchStop=false;
        g_watchThread=CreateThread(nullptr,0,WatchThread,nullptr,0,nullptr);
        break;
    case DLL_PROCESS_DETACH:
        g_watchStop=true;
        if(g_watchThread){WaitForSingleObject(g_watchThread,3000);CloseHandle(g_watchThread);g_watchThread=nullptr;}
        #define U(x) if(g_hook##x.installed)UnhookTemp(g_hook##x);
        U(NtQSI)U(CreateMutexW)U(CreateMutexA)U(OpenMutexW)U(OpenMutexA)
        U(CreateMutexExW)U(CreateEventW)U(CreateEventA)U(OpenEventW)U(OpenEventA)
        U(CreateFileW)U(CreateFileA)U(DeleteFileW)U(DeleteFileA)
        U(GetFileAttributesW)U(GetFileAttributesA)
        #undef U
        if(g_jobHandle)CloseHandle(g_jobHandle);
        DeleteCriticalSection(&g_cs);
        break;
    }
    return TRUE;
}

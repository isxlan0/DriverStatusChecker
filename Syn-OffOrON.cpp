#include <windows.h>
#include <shellapi.h>
#include <tchar.h>

bool IsDriverInstalled()
{
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL)
    {
        return false;
    }

    SC_HANDLE hService = OpenService(hSCManager, _T("HoYoProtect"), SERVICE_QUERY_STATUS);//("")里面的内容就是驱动名
    if (hService == NULL)
    {
        CloseServiceHandle(hSCManager);
        return false;
    }

    SERVICE_STATUS serviceStatus;
    if (!QueryServiceStatus(hService, &serviceStatus))
    {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return false;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return serviceStatus.dwCurrentState == SERVICE_RUNNING;
}

int main()
{
    BOOL bIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &bIsRunAsAdmin))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    if (!bIsRunAsAdmin)
    {
        TCHAR szPath[MAX_PATH];
        if (GetModuleFileName(NULL, szPath, MAX_PATH) == 0)
        {
            return 1;
        }

        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.lpVerb = _T("runas");
        sei.lpFile = szPath;
        sei.nShow = SW_NORMAL;

        if (!ShellExecuteEx(&sei))
        {
            return 1;
        }

        return 0;
    }

    if (IsDriverInstalled())
    {  
        MessageBox(NULL, _T("驱动已启动"), _T("提示"), MB_OK);
    }
    else
    {
        MessageBox(NULL, _T("驱动未启动"), _T("提示"), MB_OK);
    }

Cleanup:
    if (pAdministratorsGroup)
    {
        FreeSid(pAdministratorsGroup);
    }

    return dwError;
}

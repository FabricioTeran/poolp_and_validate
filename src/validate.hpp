#ifndef VALIDATE_H
#define VALIDATE_H

#include<iostream>
#include<type_traits>
#include<phnt_windows.h>
#include<phnt.h>
#include<string>
#include<sstream>

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

typedef void (*ErrorHandlingFunc)(string, bool*);
void ErrorAbort(string message, bool* ignoredArg) {
    cout << message;
    abort();
    return;
}
void ErrorBool(string message, bool* flag) {
    cout << message;
    *flag = false;
    return;
}
enum VALIDATE_FUNC {
    CHECK_FALSE_NULL,
    CHECK_NTSTATUS,
    CHECK_BAD_PTR,
    CHECK_HANDLE,
    NO_CHECK
};
//Definir una struct con validateFunc, id, errorFunc, checkError, extraInfo... Y una funcion para construir uno
typedef struct INFO_T {
    VALIDATE_FUNC validateFunc;
    const char* id;
    const char* skipArgValidate;
    ErrorHandlingFunc errorFunc;
    bool* checkError;
    string extraErrorInfo;
};

//Crear una struct global para configurar la errorFunc default y asi poder definir la funcion que nosotros queramos como default en todo nuestro programa
ErrorHandlingFunc defaultErrorFunc = ErrorAbort;
void validateSet(ErrorHandlingFunc defaultFunc) {
    defaultErrorFunc = defaultFunc;
    return;
}

INFO_T* info(VALIDATE_FUNC validateFunc, const char* id, const char* skipArgValidate = "", ErrorHandlingFunc errorFunc = defaultErrorFunc, bool* checkError = nullptr) {
    INFO_T* newInfo = new INFO_T; //El bad alloc error se soluciono con esto, porque al crear variables en funciones, al salir se libera la memoria
                                 //No debemos usar static, porque siempre se usara la misma estructura, no creara nuevas
    newInfo->validateFunc = validateFunc;
    newInfo->id = id;
    newInfo->skipArgValidate = skipArgValidate;
    newInfo->errorFunc = errorFunc;
    newInfo->checkError = checkError;

    return newInfo;
}



template <class ArgT>
ArgT valExp(INFO_T* info, ArgT expression) {
    std::stringstream message;
    
    if (info->validateFunc == CHECK_FALSE_NULL) {
        void* helper = &expression; //expression se guarda en el parametro de la funcion, tomamos su ubicacion y luego casteamos esa ubicacion
        bool expressionValue = *(bool*)helper; //Convertimos de void* a bool* y luego hacemos *helper para obtener su valor
        if (!expressionValue) {        //Es la misma tecnica usada en hacking para castear estructuras en tiempo de ejecucion
            message << "\nFalse or Null Value: " << expressionValue << "\nid: " << info->id << "\nGetLastError: " << std::dec << GetLastError() << info->extraErrorInfo;
            info->errorFunc(message.str(), info->checkError);
        }
    }
    else if (info->validateFunc == CHECK_NTSTATUS) {
        void* helper = &expression;
        NTSTATUS expressionValue = *(NTSTATUS*)helper;
        if (!NT_SUCCESS(expressionValue)) {
            message << "\nNTSTATUS: " << std::hex << expressionValue << "\nid: " << info->id << info->extraErrorInfo;
            info->errorFunc(message.str(), info->checkError);
        }
    }
    else if (info->validateFunc == CHECK_BAD_PTR) { //Parece que los punteros en mi maquina funcionan bien con DWORD, utilizar DWORD_PTR causaba que leyera mal los punteros
        void* helper = &expression; //&expression toma la direccion del parametro, no la ubicacion a la que apunta el puntero
        DWORD expressionValue = *(DWORD*)helper;
        if (BAD_PTR(expressionValue)) {     //Asi que debo usar *helper para referirme
            message << "\nBad-Pointer: " << expressionValue << "\nid: " << info->id << "\nGetLastError: " << std::dec << GetLastError() << info->extraErrorInfo; //Usamos std::dec para convertir la DWORD de GetLastError en decimal, los errores documentados en msdn estan en decimal (y hexadecimal entre parentesis)
            info->errorFunc(message.str(), info->checkError);
        }
    }
    else if (info->validateFunc == CHECK_HANDLE) {
        void* helper = &expression;
        HANDLE expressionValue = *(HANDLE*)helper;
        DWORD unused;
        DWORD realLastError = GetLastError(); //Al llamar a GetHandleInformation, si falla estamos sobreescribiendo el anterior valor de GetLastError
        if (!GetHandleInformation(expressionValue, &unused)) {
            message << "\nInvalid Handler: " << expressionValue << "\nid: " << info->id << "\nGetLastError: " << std::dec << realLastError << info->extraErrorInfo;
            info->errorFunc(message.str(), info->checkError);
        }
    }

    info->extraErrorInfo = ""; //Luego de recibir la extra info debemos borrarla para que no se mezcle con proximas llamdas

    return expression;
}

void validateArgs(INFO_T* modifiedInfo, int argCount) { return; } //Solo me faltaba el puto parametro id, la recursion de packs funciona
template <typename FirstT, typename... RestT>
void validateArgs(INFO_T* modifiedInfo, int argCount, FirstT first, RestT... rest) {
    if (typeid(first) == typeid(HANDLE)) {
        string errorMessage = "\nArgCount: " + to_string(argCount);
        modifiedInfo->validateFunc = CHECK_HANDLE;
        modifiedInfo->extraErrorInfo += errorMessage;

        valExp(modifiedInfo, first);
    }

    /* No es codigo portable is_pointer_v
    else if (is_pointer_v<FirstT>) { //Quizas al comparar FirstT siempre da verdadero porque FirstT es un grupo de tipos, no solo 1 tipo
        cout << "\n2id:" << id << " x:" << helper << " count:" << iVal++;
        valExp(CHECK_BAD_PTR, id, first);
    }*/

    validateArgs(modifiedInfo, argCount+1, rest...); //argCount contabiliza el numero de argumento en el pack variadic para informar al usuario en que argumento ocurrio el error de validacion
}

template <typename FuncT, typename... ArgsT> //Para declarar templates que devuelven cualquier tipo usamos auto
auto val(INFO_T* info, FuncT func, ArgsT... args) {
    INFO_T modifiedInfo = { //Creamos una info que se va a usar para los argumentos
        .id = info->id,
        .errorFunc = info->errorFunc,
        .checkError = info->checkError
    };
    validateArgs(&modifiedInfo, 0, args...); //Falta implementar skipArgValidate

    auto res = func(args...); //Con auto no podemos usar NULL, debemos usar el tipo correcto para los argumentos

    info->extraErrorInfo += "\nThe result of the function has failed";
    valExp(info, res);

    return res;
}

template <class FuncT, class... ArgsT> //Si las funciones a validar son templates, es muy dificil crear una funcion template que acepte otros templates, ademas tendriamos que definir una nueva funcion para cada nuevo template usado, entonces es mejor llamar la funcion desde afuera y que esta funcion solo tome el resultado
FuncT valTemplate(INFO_T* info, FuncT call, ArgsT... args) {
    INFO_T modifiedInfo = {
        .id = info->id,
        .errorFunc = info->errorFunc,
        .checkError = info->checkError
    };
    validateArgs(&modifiedInfo, 0, args...);

    info->extraErrorInfo += "\nThe result of the function has failed";
    valExp(info, call);

    return call;
}

#define valTemp(infor, func, ...) valTemplate(infor, func(__VA_ARGS__), __VA_ARGS__);

//Cambiar valExp para que acepte otra funcion en vez de abort(), por ej fail(&bool) que acepta un puntero a bool y lo establece en false cuando se llama, para asi saber si valExp fallo
//Y de ahi solo creamos valTry y valTempTry que llamen a valExp con esta funcion fail

//Para el futuro admitir funciones en vez de CHECK_HANDLE para que podamos definir en main.cpp funciones para validar tipos custom pero que no queremos agregar a la libreria
//Pero por ahi ni necesitamos esta funcionalidad y nos es suficiente con los validadores que ya tenemos... Entonces solo implementarlo si es estrictamente necesario

#endif
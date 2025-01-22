#ifndef VALIDATE_H
#define VALIDATE_H

#include<iostream>
#include<type_traits>
#include<phnt_windows.h>
#include<phnt.h>
#include<string>

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
template <class ArgT>
ArgT valExp(VALIDATE_FUNC validateFunc, const char* id, ArgT expression, string errorInfo = "") {
    if (validateFunc == CHECK_FALSE_NULL) {
        void* helper = &expression; //expression se guarda en el parametro de la funcion, tomamos su ubicacion y luego casteamos esa ubicacion
        bool expressionValue = *(bool*)helper; //Convertimos de void* a bool* y luego hacemos *helper para obtener su valor
        if (!expressionValue) {        //Es la misma tecnica usada en hacking para castear estructuras en tiempo de ejecucion
            cout << "\nFalse or Null Value: " << expressionValue << "\nid: " << id << "\nGetLastError: " << std::dec << GetLastError() << errorInfo;
            abort();
        }
    }
    else if (validateFunc == CHECK_NTSTATUS) {
        void* helper = &expression;
        NTSTATUS expressionValue = *(NTSTATUS*)helper;
        if (!NT_SUCCESS(expressionValue)) {
            cout << "\nNTSTATUS: " << std::hex << expressionValue << "\nid: " << id << errorInfo;
            abort();
        }
    }
    else if (validateFunc == CHECK_BAD_PTR) { //Parece que los punteros en mi maquina funcionan bien con DWORD, utilizar DWORD_PTR causaba que leyera mal los punteros
        void* helper = &expression; //&expression toma la direccion del parametro, no la ubicacion a la que apunta el puntero
        DWORD expressionValue = *(DWORD*)helper;
        if (BAD_PTR(expressionValue)) {     //Asi que debo usar *helper para referirme
            cout << "\nBad-Pointer: " << expressionValue << "\nid: " << id << "\nGetLastError: " << std::dec << GetLastError() << errorInfo; //Usamos std::dec para convertir la DWORD de GetLastError en decimal, los errores documentados en msdn estan en decimal (y hexadecimal entre parentesis)
            abort();
        }
    }
    else if (validateFunc == CHECK_HANDLE) {
        void* helper = &expression;
        HANDLE expressionValue = *(HANDLE*)helper;

        DWORD unused;
        if (!GetHandleInformation(expressionValue, &unused)) {
            cout << "\nInvalid Handler: " << expressionValue << "\nid: " << id << "\nGetLastError: " << std::dec << GetLastError() << errorInfo;
            abort();
        }
    }

    return expression;
}

void validateArgs(const char* id, int argCount) { return; } //Solo me faltaba el puto parametro id, la recursion de packs funciona
template <typename FirstT, typename... RestT>
void validateArgs(const char* id, int argCount, FirstT first, RestT... rest) {
    if (typeid(first) == typeid(HANDLE)) {
        string errorInfo = "\nArgCount: " + to_string(argCount);
        valExp(CHECK_HANDLE, id, first, errorInfo);
    }

    /* No es codigo portable is_pointer_v
    else if (is_pointer_v<FirstT>) { //Quizas al comparar FirstT siempre da verdadero porque FirstT es un grupo de tipos, no solo 1 tipo
        cout << "\n2id:" << id << " x:" << helper << " count:" << iVal++;
        valExp(CHECK_BAD_PTR, id, first);
    }*/

    validateArgs(id, argCount+1, rest...); //argCount contabiliza el numero de argumento en el pack variadic para informar al usuario en que argumento ocurrio el error de validacion
}

template <typename FuncT, typename... ArgsT> //Para declarar templates que devuelven cualquier tipo usamos auto
auto val(VALIDATE_FUNC returnValidateFunc, const char* skipArgValidate, const char* id, FuncT func, ArgsT... args) {
    validateArgs(id, 0, args...); //Falta implementar skipArgValidate

    auto res = func(args...); //Con auto no podemos usar NULL, debemos usar el tipo correcto para los argumentos

    string errorInfo = "\nThe result of the function has failed";
    valExp(returnValidateFunc, id, res, errorInfo);

    return res;
}

template <class FuncT, class... ArgsT> //Si las funciones a validar son templates, es muy dificil crear una funcion template que acepte otros templates, ademas tendriamos que definir una nueva funcion para cada nuevo template usado, entonces es mejor llamar la funcion desde afuera y que esta funcion solo tome el resultado
FuncT valTemplate(VALIDATE_FUNC returnValidateFunc, const char* skipArgValidate, const char* id, FuncT call, ArgsT... args) {
    validateArgs(id, 0, args...); //Falta implementar skipArgValidate

    string errorInfo = "\nThe result of the function has failed";
    valExp(returnValidateFunc, id, call, errorInfo);

    return call;
}

#define valTemp(returnValidateFunc, skipArgValidate, id, func, ...) valTemplate(returnValidateFunc, skipArgValidate, id, func(__VA_ARGS__), __VA_ARGS__);

//Para el futuro admitir funciones en vez de CHECK_HANDLE para que podamos definir en main.cpp funciones para validar tipos custom pero que no queremos agregar a la libreria
//Pero por ahi ni necesitamos esta funcionalidad y nos es suficiente con los validadores que ya tenemos... Entonces solo implementarlo si es estrictamente necesario

#endif
#ifndef OLD_VALIDATE_H
#define OLD_VALIDATE_H

#include<iostream>
#include<type_traits>
#include<phnt_windows.h>
#include<phnt.h>

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
ArgT valExp(VALIDATE_FUNC validateFunc, const char* id, ArgT expression) {
    if (validateFunc == CHECK_FALSE_NULL) {
        void* helper = &expression; //expression se guarda en el parametro de la funcion, tomamos su ubicacion y luego casteamos esa ubicacion
        if (!(bool)helper) {        //Es la misma tecnica usada en hacking para castear estructuras en tiempo de ejecucion
            cout << "\nFalse or Null Value: " << (bool)helper << ", id: " << id << ", GetLastError: " << std::dec << GetLastError();
            abort();
        }
    }
    else if (validateFunc == CHECK_NTSTATUS) {
        void* helper = &expression;
        if (!NT_SUCCESS(*(NTSTATUS*)helper)) {
            cout << "\nNTSTATUS: " << (NTSTATUS)helper << ", id: " << id;
            abort();
        }
    }
    else if (validateFunc == CHECK_BAD_PTR) { //Parece que los punteros en mi maquina funcionan bien con DWORD, utilizar DWORD_PTR causaba que leyera mal los punteros
        void* helper = &expression; //&expression toma la direccion del parametro, no la ubicacion a la que apunta el puntero
        if (BAD_PTR(*(DWORD*)helper)) {     //Asi que debo usar *helper para referirme
            cout << "\nBad-Pointer:" << helper << ",  id:" << id << ",  GetLastError:" << std::dec << GetLastError(); //Usamos std::dec para convertir la DWORD de GetLastError en decimal, los errores documentados en msdn estan en decimal (y hexadecimal entre parentesis)
            abort();
        }
    }
    else if (validateFunc == CHECK_HANDLE) {

    }

    return expression;
}

extern int iVal = 0;
void validateArgs(const char* id) { return; } //Solo me faltaba el puto parametro id, la recursion de packs funciona
template <typename FirstT, typename... RestT>
void validateArgs(const char* id, FirstT first, RestT... rest) {
    void* helper = &first;
    if (typeid(first) == typeid(HANDLE)) {
        cout << "\nid:" << id << " x:" << helper << " count:" << iVal++;
        valExp(CHECK_HANDLE, id, first);
    }

    /* No es codigo portable is_pointer_v
    else if (is_pointer_v<FirstT>) { //Quizas al comparar FirstT siempre da verdadero porque FirstT es un grupo de tipos, no solo 1 tipo
        cout << "\n2id:" << id << " x:" << helper << " count:" << iVal++;
        valExp(CHECK_BAD_PTR, id, first);
    }*/

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

#endif
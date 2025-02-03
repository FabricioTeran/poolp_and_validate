#ifndef DEBUG_H
#define DEBUG_H

//Funcion que acepta una funcion donde se va a colocar el breakpoint ()
//Como los EDR pueden ver la cracion de threads, puedo ofuscarlo un poco y crear un thread sobre una funcion envoltorio que adentro llamara a la funcion real Nt
//Creo que solo puedo debuggear procesos, entonces debuggear mi propio proceso, establecer un breakpoint 3 instrucciones despues de la ubicacion de la funcion o tambien puedo envolver la funcion en un callback

//Se va a retornar una funcion envuelta que va a llamar a la funcion original con parametros falsos, 
  //establecer un breakpoint en la syscall y cambiar los parametros antes de ejecutar la syscall 

#endif
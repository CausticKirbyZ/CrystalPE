
// super simple pefile to be built with mingw cross compile

// compile with: 
// x86_64-w64-mingw32-gcc HelloWorld.c -o HelloWorld.exe 

#include <stdio.h>
#include <windows.h>


int main()
{
    // printf("Hello world\n");
    MessageBoxA(NULL, "Message", "TITLE", NULL);
    return 0;
}
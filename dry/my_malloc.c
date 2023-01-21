#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    write(1, "\n--------------------\n", 22);
    malloc(atoi(argv[1]));
    write(1, "\n--------------------\n", 22);
    return 0;
}

#include <unistd.h>

int main (int argc, char * argv[]) {
    unsigned char buf[8];

    read(0, buf, 8);

    if (    (buf[0] == 'a')
         && (buf[1] == 'b')
         && (buf[2] == 'c')
         && (buf[3] == 'd')
         && (buf[4] == 'e')
         && (buf[5] == 'f')
         && (buf[6] == 'g')
         && (buf[7] == 'h'))
        write(1, "win\n", 4);

    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define NUM_FILES 4
#define BUFF_SIZE 4096

const char* files [] = {"/etc/passwd", "/etc/shadow", "/etc/crontab", "/etc/hosts"};

int main(int argc, char** argv)
{
    int i;
    int fd;
    char buff[BUFF_SIZE];
    for (i = 0; i < NUM_FILES; i++)
    {
        
        fd = open(files[i], O_RDONLY);
        if (fd < 0)
        {
            // Failed to open file for read
            printf("[DEBUG] Failed to open for reading: %s\n", files[i]);
        }else
        {
            int b_read = read(fd, buff, BUFF_SIZE);
            write(1, buff, b_read);
        }
    }
    return 0;
}
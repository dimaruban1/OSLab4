#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <fcntl.h>
#include <string.h>
#include <regex.h>

#define BUFFER_SIZE 1024

unsigned char* find_variable(int pid, char address[], unsigned long blob_len) {
    char mem_file_path[256];
    sprintf(mem_file_path, "/proc/%d/mem", pid);

    unsigned long start_addr, end_addr;

    sscanf(address, "%lx", &start_addr);
    end_addr = start_addr + blob_len;
    printf("%li %li", start_addr, end_addr);

    unsigned char *blob = malloc(sizeof(unsigned char) * blob_len+10);
    if (blob == NULL) {
        printf("Memory allocation failed!\n");
        return NULL;
    }

    int mem = open(mem_file_path, O_RDONLY);

    if (mem == -1){
        printf("failed to open file");
    }
    unsigned long res = lseek(mem, start_addr, SEEK_SET);
    printf("lseek: %li\n", res);
    res = read(mem, blob, blob_len);
    printf("read: %li\n", res);
    printf("blob: `%s`\n", blob);
    close(mem);
    
    return blob;
}

int main(int argc) {
    int pid = 9481;
    char maps_file[100][BUFFER_SIZE];
    int count;

    char* stack_address = "0x7ffc47a9801c";
    char* blob = find_variable(pid, stack_address, 8);

    FILE *output_file = fopen("dump.bin", "wb");
    if (output_file == NULL) {
        printf("Unable to open output file\n");
        free(blob);
    }

    fwrite(blob, sizeof(char), strlen(blob), output_file);

    fclose(output_file);
    free(blob);

    return 0;
}
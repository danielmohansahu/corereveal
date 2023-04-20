#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define TABLE_SIZE 128

// Key value like struct

typedef struct dict_entry
{
    char* key;
    void* value;
}dict_entry;

typedef struct dict
{
    dict_entry** table;
}dict;

typedef struct ini
{
    dict* sections;
} ini;

void heap_chk(void* ptr)
{
    if (ptr == NULL)
    {
        printf("Unable to Allocate Heap Memory\n");
        exit(1);
    }
}

unsigned int hash(char* key)
{
    unsigned int hash_value = 1;
    char* p;
    for(p=key; *p; p++)
    {
        hash_value *= *p;
    }

    return hash_value % TABLE_SIZE;
}

dict* init_dict()
{
    dict* d = (dict*) malloc(sizeof(dict));
    heap_chk(d);
    d->table = (dict_entry**) calloc(TABLE_SIZE, sizeof(dict_entry*));
    heap_chk(d->table);

    return d;
}

int insert_entry(dict* d, char* key, void* value, int value_size)
{
    dict_entry* entry = (dict_entry*) malloc(sizeof(dict_entry));
    heap_chk(entry);
    int key_len = strlen(key) + 1;
    entry->key = (char*) malloc(key_len);
    heap_chk(entry->key);
    entry->value = (void*) malloc(value_size);
    heap_chk(entry->value);

    strncpy(entry->key, key, key_len);
    memcpy(entry->value, value, value_size);

    unsigned int i = hash(entry->key);
    while (d->table[i] != NULL)
    {
        i = (i * i) % TABLE_SIZE;
    }
    d->table[i] = entry;

    return i;
}

void* get_value(dict* d, char* key)
{
    unsigned int i = hash(key);
    while (strcmp(d->table[i]->key, key))
    {
        i = (i * i) % TABLE_SIZE;
    }
    return d->table[i]->value;
}

void add_section(ini* ini, char* section)
{
    dict* key_values = init_dict();
    insert_entry(ini->sections, section, key_values, sizeof(dict*));
}

void add_data(ini* ini, char* section, char* key, char* value)
{
    dict* d = (dict*) get_value(ini->sections, section);
    insert_entry(d, key, value, strlen(value));
}

char* get_data(ini* ini, char* section, char* key)
{
    dict* d = get_value(ini->sections, section);
    return (char*) get_value(d, key);
}

void print_ini(ini* ini_data)
{
    int i;
    for(i=0; i<TABLE_SIZE; i++)
    {
        if(ini_data->sections->table[i] != NULL)
        {
            printf("[%s]\n", ini_data->sections->table[i]->key);
            dict* d = ini_data->sections->table[i]->value;

            int j;
            for(j=0;j<TABLE_SIZE; j++)
            {   
                if(d->table[j] != NULL)
                {
                    printf("%s = %s\n", d->table[j]->key, (char*) d->table[j]->value);
                }
            }
        }
    }
}

void deserialize(ini* ini, char* filepath)
{
    struct stat stat;
    int fd;
    char* buff;
    char* pos;
    char* cur;
    char* cur_section = NULL;

    fd = open(filepath, O_RDONLY);
    fstat(fd, &stat);

    // Read whole file into mem ;)
    buff = (char*) malloc(sizeof(char)*stat.st_size);
    heap_chk(buff);
    read(fd, buff, sizeof(char) * stat.st_size);
    pos = buff;

    while(pos != buff+stat.st_size)
    {
        if (*pos == ';')
        {  
            // iterate to the next newline
            for(cur = pos; *cur != '\n'; cur++){}

            unsigned int length = cur - pos;
            if (length > 0)
            {
                *cur = '\0';
                printf("Comment: %s\n", pos+1);
            }
            pos = cur + 1;
        }
        // ini section start
        else if(*pos == '[')
        {
            // iterate to next left square bracket
            for(cur = pos; *cur != ']'; cur++){}
            unsigned int length = cur - pos;
            if (length == 0)
            {
                printf("Empty Section. Exiting...\n");
                exit(1);
            }
            *cur = '\0';
            if(cur_section != NULL)
            {
                free(cur_section);
            }
            cur_section = (char*) malloc(sizeof(char) * length);
            heap_chk(cur_section); 
            strncpy(cur_section, pos+1, length);
            
            add_section(ini, pos+1);
            pos = cur+1;

        }
        // whitespace. do nothing
        else if(*pos == '\n' || *pos == ' ')
        {
            pos++;
        }
        // start of a new key/value pair. Assumes a section has been declared
        else
        {
            // TODO read until first space -> key
            // should be followed by = thne another space
            // read until newline -> value
        }
    }
    

    close(fd);
}

int main()
{
    ini ini_data;
    ini_data.sections = init_dict();
    deserialize(&ini_data, "test_config.ini");
    // add_section(&ini_data, "test");
    // add_data(&ini_data, "test", "harry", "potter");
    // print_ini(&ini_data);
    return 0;
}
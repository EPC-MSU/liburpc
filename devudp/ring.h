#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include <stdint.h>
#include <stdlib.h>

#define BUFFER_SIZE 65536

#define BUFFER_OK 0
#define BUFFER_OVERFLOW -1


typedef struct 
{
    char buffer[BUFFER_SIZE];
    uint16_t begin;
    uint16_t end;
} buffer_t;


void buffer_init(buffer_t *buf);
size_t buffer_size(const buffer_t *buf);
int buffer_push(buffer_t *buffer, const char *data, size_t size);
int buffer_pop(buffer_t *buffer, char *data, size_t *size);
void buffer_clear(buffer_t *buffer);

#endif // RING_BUFFER_H  
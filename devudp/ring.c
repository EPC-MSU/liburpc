
#include <string.h>
#include "ring.h"


void buffer_init(buffer_t *buf)
{
    memset(buf->buffer, 0, BUFFER_SIZE);
    buf->begin = BUFFER_SIZE / 2;
    buf->end = BUFFER_SIZE / 2;
}

size_t buffer_size(const buffer_t *buf)
{
    return abs(buf->end - buf->begin);
}

int buffer_push(buffer_t *buffer, const char *data, size_t size)
{
    if (size > BUFFER_SIZE - buffer_size(buffer)) // free space available
    {
        return BUFFER_OVERFLOW;
    }

    if (buffer->end + size < BUFFER_SIZE) // just put to the end
    {
        memcpy(buffer->buffer + buffer->end, data, size);
    } 
    else // buffer end reached
    {
        int tail = BUFFER_SIZE - buffer->end;
        memcpy(buffer->buffer + buffer->end, data, tail);
        memcpy(buffer->buffer, data + tail, size - tail);
    }
    buffer->end += size;

    return BUFFER_OK;
}

int buffer_pop(buffer_t *buffer, char *data, size_t *size)
{
    if (*size > buffer_size(buffer))
    {
        *size = buffer_size(buffer);
    }

    if (*size < BUFFER_SIZE - buffer->begin) // just pop from the front
    {
        memcpy(data, buffer->buffer + buffer->begin, *size);
    }
    else
    {
        int tail = BUFFER_SIZE - buffer->begin;
        memcpy(data, buffer->buffer + buffer->begin, tail);
        memcpy(data + tail, buffer->buffer, *size - tail);
    }
    buffer->begin += *size;
    return BUFFER_OK;
}

void buffer_clear(buffer_t *buffer)
{
    buffer->begin = BUFFER_SIZE / 2;
    buffer->end = BUFFER_SIZE / 2;
}
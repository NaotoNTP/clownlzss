#include "memory_stream.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct MemoryStream
{
	unsigned char *buffer;
	size_t index;
	size_t size;
	size_t growth;
	bool free_buffer_when_destroyed;
} MemoryStream;

MemoryStream* MemoryStream_Create(size_t growth, bool free_buffer_when_destroyed)
{
	MemoryStream *memory_stream = (MemoryStream*)malloc(sizeof(MemoryStream));
	memory_stream->buffer = NULL;
	memory_stream->index = 0;
	memory_stream->size = 0;
	memory_stream->growth = growth;
	memory_stream->free_buffer_when_destroyed = free_buffer_when_destroyed;
	return memory_stream;
}

void MemoryStream_Destroy(MemoryStream *memory_stream)
{
	if (memory_stream->free_buffer_when_destroyed)
		free(memory_stream->buffer);

	free(memory_stream);
}

void MemoryStream_WriteByte(MemoryStream *memory_stream, unsigned char byte)
{
	if (memory_stream->index + 1 > memory_stream->size)
	{
		memory_stream->size += memory_stream->growth;
		memory_stream->buffer = (unsigned char*)realloc(memory_stream->buffer, memory_stream->size);
	}

	memory_stream->buffer[memory_stream->index++] = byte;
}

void MemoryStream_WriteBytes(MemoryStream *memory_stream, unsigned char *bytes, unsigned int byte_count)
{
	const size_t needed_size = memory_stream->index + byte_count;

	if (needed_size > memory_stream->size)
	{
		memory_stream->size = needed_size + memory_stream->growth - (needed_size % memory_stream->growth);
		memory_stream->buffer = (unsigned char*)realloc(memory_stream->buffer, memory_stream->size);
	}

	memcpy(&memory_stream->buffer[memory_stream->index], bytes, byte_count);

	memory_stream->index += byte_count;
}

unsigned char* MemoryStream_GetBuffer(MemoryStream *memory_stream)
{
	return memory_stream->buffer;
}

size_t MemoryStream_GetIndex(MemoryStream *memory_stream)
{
	return memory_stream->index;
}

void MemoryStream_Reset(MemoryStream *memory_stream)
{
	memory_stream->index = 0;
}

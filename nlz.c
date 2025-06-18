/*
Copyright (c) 2018-2023 Clownacy

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
*/

#include "nlz.h"

#include <assert.h>
#include <stddef.h>

#include "clowncommon/clowncommon.h"

#include "clownlzss.h"
#include "common.h"

#define TOTAL_DESCRIPTOR_BITS 8

size_t window_size;
size_t boundary_mask;
size_t max_packed_len;
size_t shift_count;
size_t bytes_remaining;

typedef struct NLZInstance
{
	const ClownLZSS_Callbacks *callbacks;

	size_t descriptor_position;

	unsigned int descriptor;
	unsigned int descriptor_bits_remaining;
} NLZInstance;

static size_t GetMatchCost(size_t distance, size_t length, void *user)
{
	(void)user;

		if (length >= 2 && length <= 4 && distance <= 0x40)
			return 2 + 8;				/* Descriptor bits, offset/length bytes. */
		else if (length >= 5 && distance <= 0x40)
			return 2 + 8 + 8;		/* Descriptor bits, offset byte, length byte. */
		else if (length >= 3 && length <= max_packed_len)
			return 2 + 16;			/* Descriptor bits, offset/length bytes. */
		else if (length >= (max_packed_len + 1))
			return 2 + 16 + 8;	/* Descriptor bits, offset bytes, length byte. */
		else
			return 0;           /* In the event a match cannot be compressed. */
}

static void BeginDescriptorField(NLZInstance *instance)
{
	const ClownLZSS_Callbacks* const callbacks = instance->callbacks;

	/* Log the placement of the descriptor field. */
	instance->descriptor_position = callbacks->tell(callbacks->user_data);

	/* Insert a placeholder. */
	callbacks->write(callbacks->user_data, 0);
}

static void FinishDescriptorField(NLZInstance *instance)
{
	const ClownLZSS_Callbacks* const callbacks = instance->callbacks;

	/* Back up current position. */
	const size_t current_position = callbacks->tell(callbacks->user_data);

	/* Go back to the descriptor field. */
	callbacks->seek(callbacks->user_data, instance->descriptor_position);

	/* Write the complete descriptor field. */
	callbacks->write(callbacks->user_data, instance->descriptor & 0xFF);

	/* Seek back to where we were before. */
	callbacks->seek(callbacks->user_data, current_position);
}

static void PutDescriptorBit(NLZInstance *instance, cc_bool bit)
{
	assert(bit == 0 || bit == 1);

	if (instance->descriptor_bits_remaining == 0)
	{
		instance->descriptor_bits_remaining = TOTAL_DESCRIPTOR_BITS;

		FinishDescriptorField(instance);
		BeginDescriptorField(instance);
	}

	--instance->descriptor_bits_remaining;

	instance->descriptor <<= 1;

	instance->descriptor |= bit;
}

static void SplitModule(NLZInstance *instance)
{
	const ClownLZSS_Callbacks* const callbacks = instance->callbacks;

	/* Add a terminator packet for this module. */
	PutDescriptorBit(instance, 1);
	PutDescriptorBit(instance, 0);
	callbacks->write(callbacks->user_data, 0x00);
	callbacks->write(callbacks->user_data, 0x00);

	/* Finish the previous descriptor field and begin a new one. */
	instance->descriptor <<= instance->descriptor_bits_remaining;
	instance->descriptor_bits_remaining = TOTAL_DESCRIPTOR_BITS;
	FinishDescriptorField(instance);
	BeginDescriptorField(instance);

	/* Reset the number of bytes left in this module. */
	bytes_remaining = window_size;
}

static void EncodeMatch(NLZInstance *instance, size_t distance, size_t length)
{
	const ClownLZSS_Callbacks* const callbacks = instance->callbacks;

	/* Check if the length of this match is larger than the number of bytes left for the current module and split if necessary. */
	if (length > bytes_remaining)
	{
		length = length - bytes_remaining;
		EncodeMatch(instance,distance,bytes_remaining);
	}

	if (length >= 2 && length <= 4 && distance <= 0x40)
	{
		PutDescriptorBit(instance, 1);
		PutDescriptorBit(instance, 0);
		callbacks->write(callbacks->user_data, (((distance - 1) & 0x3F) << 2) | (length - 1));
	}
	else if (length >= 5 && distance <= 0x40)
	{
		PutDescriptorBit(instance, 1);
		PutDescriptorBit(instance, 0);
		callbacks->write(callbacks->user_data, (((distance - 1) & 0x3F) << 2));
		callbacks->write(callbacks->user_data, length - 1);
	}
	else if (length >= 3 && length <= max_packed_len)
	{
		PutDescriptorBit(instance, 1);
		PutDescriptorBit(instance, 1);
		callbacks->write(callbacks->user_data, (((distance - 1) & 0xFF00) >> shift_count) | (length - 2));
		callbacks->write(callbacks->user_data, (distance - 1) & 0xFF);
	}
	else /*if (length >= 10)*/
	{
		PutDescriptorBit(instance, 1);
		PutDescriptorBit(instance, 1);
		callbacks->write(callbacks->user_data, (((distance - 1) & 0xFF00) >> shift_count));
		callbacks->write(callbacks->user_data, (distance - 1) & 0xFF);
		callbacks->write(callbacks->user_data, length - 1);
	}

	/* Decrease the byte counter for the current module and invoke a module split if necessary. */
	bytes_remaining = bytes_remaining - length;
	if (bytes_remaining == 0)
		SplitModule(instance);

}

cc_bool ClownLZSS_NLZCompress(const unsigned char *data, size_t data_size, const ClownLZSS_Callbacks *callbacks, int module_config)
{
	NLZInstance instance;
	ClownLZSS_Match *matches, *match;
	size_t total_matches;

	/* Configure the sliding window size, boundary mask, and maximum packed copy length. */
	window_size = (0x100 << module_config);
	boundary_mask = (-0x100 << module_config);
	max_packed_len = (0xFF >> module_config) + 2;
	shift_count = module_config;

	/* Set up the state. */
	instance.callbacks = callbacks;
	instance.descriptor = 0;
	instance.descriptor_bits_remaining = TOTAL_DESCRIPTOR_BITS;

	/* Produce a series of LZSS compression matches. */
	if (!ClownLZSS_Compress(0x100, window_size, NULL, 1 + 8, GetMatchCost, data, 1, data_size, &matches, &total_matches, &instance))
		return cc_false;

	/* Write the number of full modules and the size of the last module to the header. */
	if ((data_size % window_size) != 0)
	{
		callbacks->write(callbacks->user_data, ((((data_size + 1) % window_size) & 0xFE00) >> 9));
		callbacks->write(callbacks->user_data, ((((data_size + 1) % window_size) & 0x1FE) >> 1));
		callbacks->write(callbacks->user_data, (((data_size + 1) / window_size) & 0xFF));
	}
	else	/* Special case for when the uncompressed data size perfectly splits into fully-sized modules. */
	{
		callbacks->write(callbacks->user_data, ((window_size & 0xFE00) >> 9));
		callbacks->write(callbacks->user_data, ((window_size & 0x1FE) >> 1));
		callbacks->write(callbacks->user_data, (((data_size / window_size) - 1) & 0xFF));
	}

	/* Write the module configuration to the header. */
	callbacks->write(callbacks->user_data, ((module_config << 2) & 0xFF));

	/* Begin first descriptor field. */
	BeginDescriptorField(&instance);

	/* Initialize the bytes remaining counter for the first module. */
	bytes_remaining = window_size;

	/* Produce NLZ-formatted data. */
	for (match = matches; match != &matches[total_matches]; ++match)
	{
		if (CLOWNLZSS_MATCH_IS_LITERAL(match))
		{
			PutDescriptorBit(&instance, 0);
			callbacks->write(callbacks->user_data, data[match->destination]);

			/* Decrement the byte counter for the current module and invoke a module split if necessary. */
			bytes_remaining--;
			if (bytes_remaining == 0)
				SplitModule(&instance);
		}
		else
		{
			size_t distance = match->destination - match->source;

			/* Check if this match occurrs along a buffer boundary and split it into two matches if necessary. */
			if ((match->source & boundary_mask) == ((match->source + match->length) & boundary_mask))
				EncodeMatch(&instance, distance, match->length);
			else
			{
				size_t length = ((match->source + match->length) & boundary_mask) - match->source;
				EncodeMatch(&instance, distance, length);

				/* distance = (match->destination + length) - buffer_boundary;*/
				length = match->length - length;
				EncodeMatch(&instance, distance, length);
			}
		}
	}

	/* We don't need the matches anymore. */
	free(matches);

	/* Add the terminator match. */
	PutDescriptorBit(&instance, 1);
	PutDescriptorBit(&instance, 0);
	callbacks->write(callbacks->user_data, 0x00);
	callbacks->write(callbacks->user_data, 0x00);

	/* The descriptor field may be incomplete, so move the bits into their proper place. */
	instance.descriptor <<= instance.descriptor_bits_remaining;

	/* Finish last descriptor field. */
	FinishDescriptorField(&instance);

	return cc_true;
}

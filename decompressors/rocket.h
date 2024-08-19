/*
Copyright (c) 2018-2022 Clownacy

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

#ifndef CLOWNLZSS_DECOMPRESSORS_ROCKET_H
#define CLOWNLZSS_DECOMPRESSORS_ROCKET_H

#include "common.h"

namespace ClownLZSS
{
	namespace Internal
	{
		namespace Rocket
		{
			template<typename T>
			using DecompressorOutput = DecompressorOutput<T, 0x400, 0x40>;

			template<typename T1, typename T2>
			void Decompress(T1 &&input, T2 &&output)
			{
				const unsigned int uncompressed_size = input.ReadBE16();
				const unsigned int compressed_size = input.ReadBE16();

				const auto input_start_position = input.Tell();
				const auto output_start_position = output.Tell();

				BitField<1, ReadWhen::BeforePop, PopWhere::Low, Endian::Big, T1> descriptor_bits(input);

				while (input.Distance(input_start_position, input.Tell()) < compressed_size && output.Distance(output_start_position, output.Tell()) < uncompressed_size)
				{
					if (descriptor_bits.Pop())
					{
						// Uncompressed.
						output.Write(input.Read());
					}
					else
					{
						// Dictionary match.
						const unsigned int word = input.ReadBE16();
						const unsigned int dictionary_index = (word + 0x40) % 0x400;
						const unsigned int count = (word >> 10) + 1;
						const unsigned int distance = ((0x400 + static_cast<unsigned int>(output.Tell()) - dictionary_index - 1) % 0x400) + 1;

						output.Copy(distance, count);
					}
				}
			}
		}
	}

	template<typename T1, typename T2>
	void RocketDecompress(T1 &&input, T2 &&output)
	{
		using namespace Internal;

		Rocket::Decompress(DecompressorInput(input), Rocket::DecompressorOutput(output, 0x20));
	}

	template<std::random_access_iterator T1, std::random_access_iterator T2>
	void RocketDecompress(T1 input, T1 input_end, T2 output)
	{
		RocketDecompress(input, output, input_end - input);
	}
}

#endif // CLOWNLZSS_DECOMPRESSORS_ROCKET_H

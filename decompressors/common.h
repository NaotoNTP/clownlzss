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

#ifndef CLOWNLZSS_DECOMPRESSORS_COMMON_H
#define CLOWNLZSS_DECOMPRESSORS_COMMON_H

#include <algorithm>
#include <array>
#include <iterator>
#if __STDC_HOSTED__ == 1
	#include <istream>
	#include <ostream>
#endif
#include <type_traits>

#include "../common.h"

#include "bitfield.h"

namespace ClownLZSS
{
	// DecompressorInput

	template<typename T>
	class DecompressorInput
	{
	public:
		DecompressorInput(T input) = delete;
	};

	template<typename T>
	class DecompressorInputWithLength : public DecompressorInput<T>
	{
	public:
		DecompressorInputWithLength(T input, unsigned int length) = delete;
	};

	template<typename T>
	requires std::input_iterator<std::decay_t<T>>
	class DecompressorInput<T>
	{
	protected:
		std::decay_t<T> input_iterator;

	public:
		using pos_type = std::decay_t<T>;
		using difference_type = std::iterator_traits<std::decay_t<T>>::difference_type;

		DecompressorInput(std::decay_t<T> input_iterator)
			: input_iterator(input_iterator)
		{}

		unsigned char Read()
		{
			const auto value = *input_iterator;
			++input_iterator;
			return value;
		}

		// TODO: Deduplicate these, dammit.
		unsigned int ReadBE16()
		{
			const unsigned int upper = Read();
			const unsigned int lower = Read();
			return upper << 8 | lower;
		}

		unsigned int ReadLE16()
		{
			const unsigned int lower = Read();
			const unsigned int upper = Read();
			return upper << 8 | lower;
		}

		DecompressorInput& operator+=(const unsigned int value)
		{
			input_iterator += value;
			return *this;
		}

		pos_type Tell() const
		{
			return input_iterator;
		};

		void Seek(const pos_type &position)
		{
			input_iterator = position;
		};

		difference_type Distance(const pos_type &first) const
		{
			return Distance(first, Tell());
		}

		static difference_type Distance(const pos_type &first, const pos_type &last)
		{
			return std::distance(first, last);
		}
	};

	#if __STDC_HOSTED__ == 1
	template<typename T>
	requires std::is_convertible_v<T&, std::istream&>
	class DecompressorInput<T>
	{
	protected:
		std::istream &input;

	public:
		using pos_type = std::istream::pos_type;
		using difference_type = std::istream::off_type;

		DecompressorInput(std::istream &input)
			: input(input)
		{}

		unsigned char Read()
		{
			return input.get();
		}

		// TODO: Deduplicate these, dammit.
		unsigned int ReadBE16()
		{
			const unsigned int upper = Read();
			const unsigned int lower = Read();
			return upper << 8 | lower;
		}

		unsigned int ReadLE16()
		{
			const unsigned int lower = Read();
			const unsigned int upper = Read();
			return upper << 8 | lower;
		}

		DecompressorInput& operator+=(const unsigned int value)
		{
			input.seekg(value, input.cur);
			return *this;
		}

		pos_type Tell() const
		{
			return input.tellg();
		};

		void Seek(const pos_type &position)
		{
			input.seekg(position);
		};

		difference_type Distance(const pos_type &first) const
		{
			return Distance(first, Tell());
		}

		static difference_type Distance(const pos_type &first, const pos_type &last)
		{
			return last - first;
		}
	};

	template<typename T>
	requires std::is_convertible_v<T&, std::istream&>
	class DecompressorInputWithLength<T> : public DecompressorInput<T>
	{
	protected:
		std::istream::off_type end;

	public:
		DecompressorInputWithLength(std::istream &input, unsigned int length)
			: DecompressorInput<T>(input)
			, end(input.tellg() + static_cast<std::istream::off_type>(length))
		{}

		bool AtEnd() const
		{
			return DecompressorInput<T>::input.tellg() >= end;
		}
	};
	#endif

	template<typename T>
	class DecompressorInputSeparate : public DecompressorInput<T>
	{
	public:
		DecompressorInputSeparate(T input) = delete;
	};

	template<typename T>
	requires std::random_access_iterator<std::decay_t<T>>
	class DecompressorInputSeparate<T> : public DecompressorInput<T>
	{
	public:
		using DecompressorInput<T>::DecompressorInput;
	};

	#if __STDC_HOSTED__ == 1
	template<typename T>
	requires std::is_convertible_v<T&, std::istream&>
	class DecompressorInputSeparate<T> : public DecompressorInput<T>
	{
	protected:
		std::istream::pos_type position;

	public:
		DecompressorInputSeparate(std::istream &input)
			: DecompressorInput<T>::DecompressorInput(input)
			, position(input.tellg())
		{}

		unsigned char Read()
		{
			const auto previous_position = DecompressorInput<T>::input.tellg();
			DecompressorInput<T>::input.seekg(position);
			const auto value = DecompressorInput<T>::Read();
			position = DecompressorInput<T>::input.tellg();
			DecompressorInput<T>::input.seekg(previous_position);
			return value;
		}

		DecompressorInputSeparate& operator+=(const unsigned int value)
		{
			const auto previous_position = DecompressorInput<T>::input.tellg();
			DecompressorInput<T>::input.seekg(position);
			DecompressorInput<T>::operator+=(value);
			position = DecompressorInput<T>::input.tellg();
			DecompressorInput<T>::input.seekg(previous_position);
			return *this;
		}
	};
	#endif

	// DecompressorOutput

	template<typename T, unsigned int dictionary_size, unsigned int maximum_copy_length>
	class DecompressorOutput
	{
	public:
		DecompressorOutput(T output) = delete;
		DecompressorOutput(T output, unsigned char filler_value) = delete;
	};

	template<typename T, unsigned int dictionary_size, unsigned int maximum_copy_length>
	requires Internal::random_access_input_output_iterator<std::decay_t<T>>
	class DecompressorOutput<T, dictionary_size, maximum_copy_length> : public Internal::OutputCommon<T>
	{
	public:

		using Internal::OutputCommon<T>::output_iterator;
		using Internal::OutputCommon<T>::OutputCommon;

		void Copy(const unsigned int distance, const unsigned int count)
		{
			std::copy(output_iterator - distance, output_iterator - distance + count, output_iterator);
			output_iterator += count;
		}
	};

	#if __STDC_HOSTED__ == 1
	template<typename T, unsigned int dictionary_size, unsigned int maximum_copy_length>
	requires std::is_convertible_v<T&, std::ostream&>
	class DecompressorOutput<T, dictionary_size, maximum_copy_length> : public Internal::OutputCommon<T>
	{
	protected:
		std::array<char, dictionary_size + maximum_copy_length - 1> buffer;
		unsigned int index = 0;

		void WriteToBuffer(const unsigned char value)
		{
			buffer[index] = value;

			// A lovely little trick that is borrowed from Okumura's LZSS decompressor...
			if (index < maximum_copy_length)
				buffer[dictionary_size + index] = value;

			index = (index + 1) % dictionary_size;
		}

	public:
		using Internal::OutputCommon<T>::output;
		using Internal::OutputCommon<T>::OutputCommon;

		DecompressorOutput(std::ostream &output, const int filler_value)
			: Internal::OutputCommon<T>::OutputCommon(output)
		{
			buffer.fill(filler_value);
		}

		void Write(const unsigned char value)
		{
			WriteToBuffer(value);
			Internal::OutputCommon<T>::Write(value);
		}

		void Copy(const unsigned int distance, const unsigned int count)
		{
			const unsigned int source_index = (index - distance + dictionary_size) % dictionary_size;
			const unsigned int destination_index = index;

			for (unsigned int i = 0; i < count; ++i)
				WriteToBuffer(buffer[source_index + i]);

			output.write(&buffer[destination_index], count);
		}

		void Fill(const unsigned char value, const unsigned int count)
		{
			for (unsigned int i = 0; i < count; ++i)
				Write(value);
		}
	};
	#endif
}

#endif // CLOWNLZSS_DECOMPRESSORS_COMMON_H

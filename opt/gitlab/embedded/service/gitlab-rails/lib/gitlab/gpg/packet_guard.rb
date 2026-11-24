# frozen_string_literal: true

require 'base64'
require 'stringio'

module Gitlab
  module Gpg
    class PacketGuard
      MAX_SIGNATURE_SIZE = 64 * 1024
      MAX_KEY_SIZE = 1024 * 1024
      MAX_SUBPACKET_BODY_SIZE = 128
      MAX_USER_ID_SIZE = 160
      BOUNDED_SUBPACKET_TYPES = [20, 24, 26, 28].freeze
      SIGNATURE_PACKET_TAGS = [2].freeze
      KEY_PACKET_TAGS = [2, 6, 10, 12, 13, 14, 17].freeze
      INVISIBLE_CHARACTERS = /\xC2\xA0|\xE2\x80[\x8B-\x8D]|\xE2\x81\xA0|\xEF\xBB\xBF/n
      CRC24_TABLE = Array.new(256) do |byte|
        crc = byte << 16
        8.times { crc = (crc << 1) ^ ((crc & 0x800000) == 0 ? 0 : 0x1864CFB) }
        crc & 0xFFFFFF
      end.freeze

      InvalidInput = Class.new(StandardError)

      class << self
        def dearmor_signature(text)
          dearmor(text, 'signature', 'SIGNATURE', MAX_SIGNATURE_SIZE,
            allowed_tags: SIGNATURE_PACKET_TAGS, check_signatures: true).first
        end

        def dearmor_key(text)
          dearmor_key_result(text).first
        end

        def key_rejection_reason(text)
          dearmor_key_result(text).last
        end

        private

        def dearmor_key_result(text)
          dearmor(text, 'key', 'PUBLIC KEY BLOCK', MAX_KEY_SIZE,
            allowed_tags: KEY_PACKET_TAGS, check_signatures: false)
        end

        def dearmor(text, input_type, label, max_size, packet_options)
          raise InvalidInput, 'invalid_armor' unless text.is_a?(String)
          raise InvalidInput, 'oversized_input' if text.bytesize > max_size

          binary = decode_armor(text, label)
          packets = StringIO.new(binary)

          validate_packet(packets, **packet_options) until packets.eof?

          [binary, nil]
        rescue InvalidInput => e
          Gitlab::AppJsonLogger.info(input_type: input_type, rejection_reason: e.message,
            Labkit::Fields::CLASS_NAME => name, Labkit::Fields::LOG_MESSAGE => 'Rejected OpenPGP input')

          [nil, e.message]
        end

        def decode_armor(text, label)
          text = text.b.gsub(/\A[\t\n\v\f\r ]+|[\t\n\v\f\r ]+\z/, '')
          prefix = "-----BEGIN PGP #{label}-----"
          suffix = "-----END PGP #{label}-----"
          raise InvalidInput, 'invalid_armor' unless text.start_with?(prefix) && text.end_with?(suffix)

          lines = text.delete_prefix(prefix).delete_suffix(suffix).split("\n", -1)
          raise InvalidInput, 'invalid_armor' unless lines.shift&.match?(/\A[\t\v\f\r ]*\z/)

          lines.map! { |line| line.sub(/[\t\n\v\f\r ]+\z/, '') }
          lines.shift while lines.first&.match?(/\A[A-Za-z0-9-]+:(?: [^\r\n]*)?\z/n)

          decode_body(lines.join.delete("\t\n\v\f\r ").gsub(INVISIBLE_CHARACTERS, ''))
        end

        def decode_body(body)
          checksum = body.slice!(-5..) if body.match?(%r{=[A-Za-z0-9+/]{4}\z})
          body = body.sub(/=+\z/, '')
          raise InvalidInput, 'invalid_armor' if body.empty?

          body += '=' * (-body.bytesize % 4)
          binary = Base64.strict_decode64(body)
          if checksum && checksum != "=#{Base64.strict_encode64([crc24(binary)].pack('N').byteslice(1, 3))}"
            raise InvalidInput, 'invalid_armor'
          end

          binary
        rescue ArgumentError
          raise InvalidInput, 'invalid_armor'
        end

        def crc24(binary)
          binary.each_byte.reduce(0xB704CE) do |crc, byte|
            ((crc << 8) ^ CRC24_TABLE[(crc >> 16) ^ byte]) & 0xFFFFFF
          end
        end

        def validate_packet(packets, allowed_tags:, check_signatures:)
          header = read_number(packets, 1)
          raise InvalidInput, 'invalid_packet' if header < 128

          if header & 0x40 == 0
            length_type = header & 3
            raise InvalidInput, 'invalid_packet' if length_type == 3

            tag = (header >> 2) & 15
            length = read_number(packets, 1 << length_type)
          else
            tag = header & 63
            length = read_length(packets)
          end

          body = read_bytes(packets, length)
          raise InvalidInput, 'disallowed_packet' unless allowed_tags.include?(tag)
          raise InvalidInput, 'oversized_user_id' if tag == 13 && body.bytesize > MAX_USER_ID_SIZE

          validate_signature(StringIO.new(body)) if check_signatures
        end

        def validate_signature(signature)
          version = read_number(signature, 1)
          return if version == 3

          raise InvalidInput, 'unsupported_version' unless version == 4

          read_bytes(signature, 3)
          2.times do
            area = StringIO.new(read_bytes(signature, read_number(signature, 2)))
            validate_subpacket(area) until area.eof?
          end
        end

        def validate_subpacket(area)
          length = read_length(area, subpacket: true)
          raise InvalidInput, 'invalid_packet' if length == 0

          body = read_bytes(area, length)
          type = body.getbyte(0) & 0x7F
          return unless BOUNDED_SUBPACKET_TYPES.include?(type) && length - 1 > MAX_SUBPACKET_BODY_SIZE

          raise InvalidInput, 'oversized_subpacket'
        end

        def read_length(buffer, subpacket: false)
          first = read_number(buffer, 1)
          return first if first < 192
          return read_number(buffer, 4) if first == 255
          raise InvalidInput, 'invalid_packet' if first >= 224 && !subpacket

          ((first - 192) << 8) + read_number(buffer, 1) + 192
        end

        def read_number(buffer, size)
          read_bytes(buffer, size).each_byte.reduce(0) { |value, byte| (value << 8) + byte }
        end

        def read_bytes(buffer, size)
          raise InvalidInput, 'invalid_packet' if size > buffer.size - buffer.pos

          buffer.read(size)
        end
      end
    end
  end
end

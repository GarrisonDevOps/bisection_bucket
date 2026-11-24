# frozen_string_literal: true

module Gitlab
  module SecretDetection
    module Utils
      class Masker
        DEFAULT_VISIBLE_CHAR_COUNT = 3
        DEFAULT_MASK_CHAR_COUNT = 5
        DEFAULT_MASK_CHAR = '*'

        class << self
          def mask_secret(
            raw_secret_value,
            mask_char: DEFAULT_MASK_CHAR,
            visible_chars_count: DEFAULT_VISIBLE_CHAR_COUNT,
            mask_chars_count: DEFAULT_MASK_CHAR_COUNT
          )
            return '' if raw_secret_value.nil? || raw_secret_value.empty?
            return raw_secret_value if raw_secret_value.length <= visible_chars_count # Too short to mask

            chars = raw_secret_value.chars
            position = 0

            while position < chars.length
              # Show 'visible_chars_count' characters
              position += visible_chars_count

              # Mask next 'mask_chars' characters if available
              mask_chars_count.times do
                break if position >= chars.length

                chars[position] = mask_char
                position += 1
              end
            end

            chars.join
          end
        end
      end
    end
  end
end

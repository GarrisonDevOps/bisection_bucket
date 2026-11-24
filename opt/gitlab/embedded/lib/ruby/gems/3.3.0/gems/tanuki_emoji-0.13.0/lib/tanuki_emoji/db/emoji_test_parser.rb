# frozen_string_literal: true

require 'strscan'
require 'date'
require 'pathname'
require 'i18n'
require_relative 'emoji_data'

module TanukiEmoji
  module Db
    # Reads and extract content from emoji-test.txt
    class EmojiTestParser
      DATA_FILE = "#{::TanukiEmoji::Db::UNICODE_DATA_DIR}/emoji-test.txt".freeze

      # https://www.unicode.org/reports/tr51/#Versioning
      EMOJI_UNICODE_VERSION = {
        '0.6' => '6.0',
        '0.7' => '7.0',
        '1.0' => '8.0',
        '2.0' => '8.0',
        '3.0' => '9.0',
        '4.0' => '9.0',
        '5.0' => '10.0'
      }.freeze

      # Return the path to the default data file (emoji-data.txt)
      #
      # @return [Pathname] path to the default data file
      def self.data_file
        ::Pathname.new(File.expand_path(File.join(__dir__, '../../../', DATA_FILE)))
      end

      attr_reader :data_file
      attr_accessor :group_category

      def initialize(index:, data_file: self.class.data_file)
        @data_file = data_file
        @index = index
        @group_category = nil

        return if I18n.available_locales.include?(:en)

        I18n.available_locales = I18n.available_locales + [:en]
      end

      # Return the parsed data from the data file
      #
      # @return [Array<EmojiData>] collection of EmojiData
      def data
        parsed = []

        load do |line|
          parse_line(line).tap do |result|
            parsed << result unless result.nil?
          end
        end

        parsed
      end

      def raw_data
        lines = []
        load do |line|
          lines << line
        end

        lines
      end

      def load!
        alpha_code = nil

        data.each do |emoji_data|
          I18n.with_locale(:en) do
            alpha_code = I18n.transliterate(emoji_data.description)
              .gsub(/[^a-zA-Z#*\d]+/, '_')
              .downcase
              .chomp('_')
          end

          alpha_code = 'keycap_asterisk' if alpha_code == 'keycap_*'
          alpha_code = 'keycap_hash' if alpha_code == 'keycap_#'

          # This might be a different qualified version, basically same emoji but slightly different
          # code point. Search on the alpha code and pull that. If found, add as alternate code point.
          # "smiling face" is one example.
          emoji = @index.find_by_alpha_code(alpha_code)

          if emoji
            emoji.add_codepoints(emoji_data.codepoints)

            @index.update(emoji)
          else
            # not found, add a new emoji
            emoji = Character.new(alpha_code,
              codepoints: emoji_data.codepoints,
              alpha_code: alpha_code,
              description: emoji_data.description,
              category: emoji_data.group_category)

            emoji.unicode_version = emoji_data.version

            @index.add(emoji)
          end
        end
      end

      private

      # Parse a line extracting data and ignoring comments and metadata
      #
      # @param [String] line a line from the data file
      # @return [EmojiData] emoji data parsed from the line
      def parse_line(line)
        @scanner = StringScanner.new(line)
        data = {}

        skip_line_breaks

        return if empty_line?

        if comment_token?
          @scanner.scan(/# group: (?<group_category>[^\n]+)/)
          @group_category = fetch_first_capture.strip if @scanner.matched?

          return
        end

        @scanner.scan(/(?<codepoints>.+) ;/)
        data[:codepoints] = unicode_hex_to_codepoint(fetch_first_capture)

        skip_spaces

        # match `<qualification>`
        @scanner.scan(/(?<qualification>[a-zA-Z\- ]+) #/)
        data[:qualification] = fetch_first_capture.strip

        skip_spaces

        # emoji character
        @scanner.scan(/(?<emoji>.+?)\sE/)
        data[:emoji] = fetch_first_capture.strip

        skip_spaces

        # Version in which codepoint was introduced
        @scanner.scan(/(?<version>\d+\.\d+)/)
        data[:version] = map_emoji_to_unicode_version(fetch_first_capture)

        skip_spaces

        # description text
        @scanner.scan(/(?<description>[^\n]+)/)
        data[:description] = fetch_first_capture

        # Group
        data[:group_category] = group_category

        EmojiTestData.new(*data.values)
      end

      def skip_line_breaks
        @scanner.skip(/\n/)
      end

      def skip_spaces
        @scanner.skip(/\s+/)
      end

      def comment_token?
        @scanner.peek(1) == '#'
      end

      def empty_line?
        @scanner.peek(1) == ''
      end

      def fetch_first_capture
        @scanner.captures&.dig(0)
      end

      def load(&block)
        File.open(data_file).each(&block)
      end

      def unicode_hex_to_codepoint(unicode)
        unicode.strip.split.map(&:hex).pack("U*")
      end

      # anything after E5.0 maps to same unicode version
      def map_emoji_to_unicode_version(emoji_version)
        EMOJI_UNICODE_VERSION[emoji_version] || emoji_version
      end
    end
  end
end

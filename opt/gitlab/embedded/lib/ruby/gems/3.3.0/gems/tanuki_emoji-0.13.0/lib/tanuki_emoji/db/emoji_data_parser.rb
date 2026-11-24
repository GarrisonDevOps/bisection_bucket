# frozen_string_literal: true

require 'strscan'
require 'date'
require_relative 'emoji_data'

module TanukiEmoji
  module Db
    # Reads and extract content from emoji-data.txt and its metadata
    class EmojiDataParser
      DATA_FILE = "#{::TanukiEmoji::Db::UNICODE_DATA_DIR}/emoji-data.txt".freeze
      PROPERTIES = {
        'Emoji' => :emoji,
        'Emoji_Presentation' => :emoji_presentation,
        'Emoji_Modifier' => :emoji_modifier,
        'Emoji_Modifier_Base' => :emoji_modifier_base,
        'Emoji_Component' => :emoji_component,
        'Extended_Pictographic' => :extended_pictographic
      }.freeze

      # Return the path to the default data file (emoji-data.txt)
      #
      # @return [Pathname] path to the default data file
      def self.data_file
        Pathname.new(File.expand_path(File.join(__dir__, '../../../', DATA_FILE)))
      end

      attr_reader :data_file

      def initialize(data_file = self.class.data_file)
        @data_file = data_file
      end

      # Return the parsed data from the data file
      #
      # @return [Array<EmojiData>] collection of EmojiData
      def data
        parsed = []
        load do |line|
          parse_data(line).tap do |result|
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

      def metadata
        parsed = []

        load do |line|
          parse_metadata(line).tap do |result|
            parsed << result unless result.nil?
          end
        end

        meta = {}

        # Extract date
        raw_datetime = parsed.detect { |data| data[:key] == "Date" }&.fetch(:value)
        meta[:date] = DateTime.parse(raw_datetime)

        # Extract version
        meta[:version] = parsed.detect { |data| data[:key] == "Version" }&.fetch(:value)

        # Extract total elements
        meta[:total_elements] = parsed.select { |data| data[:key] == "Total elements" }.sum { |data| data[:value].to_i }

        meta
      end

      private

      # Parse a line extracting data and ignoring comments and metadata
      #
      # @param [String] line a line from the data file
      # @return [EmojiData] emoji data parsed from the line
      def parse_data(line)
        @scanner = StringScanner.new(line)

        data = {}

        skip_line_breaks

        # Ignore comment lines
        return if comment_token? || empty_line?

        data[:codepoints] = @scanner.scan(/[0-9A-F]+(?:\.\.[0-9A-F]+)?/)

        skip_spaces

        # match `; <property>`
        @scanner.scan(/; (?<property>[a-zA-Z_]+)/)
        data[:property] = convert_property(fetch_first_capture)

        skip_spaces

        # Version in which codepoint was introduced
        @scanner.scan(/# E(?<version>[0-9]+\.[0-9]+)/)
        data[:version] = fetch_first_capture

        skip_spaces

        # size of the range being described (1 when single codepoint)
        @scanner.scan(/\[(?<range_size>[0-9]+)\]/)
        data[:range_size] = fetch_first_capture&.to_i

        skip_spaces

        # example emojis for described codepoint or range
        @scanner.scan(/\((?<examples>[^)]+)\)/)
        data[:examples] = fetch_first_capture.to_s

        skip_spaces

        # description text
        @scanner.scan(/(?<description>[^\n]+)/)
        data[:description] = fetch_first_capture

        EmojiData.new(*data.values)
      end

      # Parse a line extracting metadata from comments only
      #
      # @param [String] line a line from the data file
      # @return [Hash] containing :date, :version and :total_elements
      def parse_metadata(line)
        @scanner = StringScanner.new(line)

        data = {}

        skip_line_breaks

        # process only when it's a comment line
        return unless comment_token?

        @scanner.scan(/# (?<key>[a-zA-Z\s]+): (?<data>[^\n]+)/)
        data[:key] = fetch_first_capture
        data[:value] = fetch_second_capture

        return unless data[:key] && data[:value]

        data
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

      def fetch_second_capture
        @scanner.captures&.dig(1)
      end

      def convert_property(property)
        PROPERTIES[property] || property
      end

      def load(&block)
        File.open(data_file).each(&block)
      end
    end
  end
end

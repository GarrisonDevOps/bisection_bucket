# frozen_string_literal: true

require_relative 'emoji_data'

module TanukiEmoji
  module Db
    # Emoji Unicode Ordering database
    class UnicodeOrdering
      DATA_FILE = "#{::TanukiEmoji::Db::UNICODE_DATA_DIR}/emoji-ordering.txt".freeze

      def self.data_file
        File.expand_path(File.join(__dir__, '../../../', DATA_FILE))
      end

      attr_reader :data_file

      def initialize(index:, data_file: nil)
        @data_file = data_file || self.class.data_file
        @index = index
      end

      def load!
        db = {}
        File.readlines(data_file, mode: 'r:UTF-8').each_with_index do |line, line_number|
          next if line.start_with?('#')

          tokens = line.split
          semicolon_offset = tokens.index(';')
          next if semicolon_offset.nil?

          codepoints_array = tokens[0...semicolon_offset].map do |token|
            token[2...token.length].hex
          end
          codepoints = codepoints_array.pack('U*')

          db[codepoints] = line_number
        end

        db.each do |codepoints, sort_key|
          emoji = @index.find_by_codepoints(codepoints)

          next unless emoji

          emoji.sort_key = sort_key
        end
      end
    end
  end
end

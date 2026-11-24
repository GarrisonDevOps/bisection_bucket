# frozen_string_literal: true

require 'json'

module TanukiEmoji
  module Db
    # Reads and adds aliases from additional_aliases.json
    class AdditionalAliases
      DATA_FILE = 'vendor/additional_aliases.json'

      def self.data_file
        File.expand_path(File.join(__dir__, '../../../', DATA_FILE))
      end

      attr_reader :data_file

      def initialize(index:, data_file: self.class.data_file)
        @data_file = data_file
        @index = index
      end

      def load!
        db = File.open(data_file, 'r:UTF-8') do |file|
          JSON.parse(file.read, symbolize_names: true)
        end

        db.each_value do |emoji_data|
          emoji = @index.find_by_codepoints(emoji_data[:emoji])

          next unless emoji

          emoji_data[:aliases].each do |code|
            emoji.add_alias(code)
          end

          emoji.noto_image = emoji_data[:noto_image] if emoji_data[:noto_image]

          @index.update(emoji)
        end
      end
    end
  end
end

# frozen_string_literal: true

require 'json'

module TanukiEmoji
  module Db
    # Gemojione Emoji database
    # In order to maintain compatibility with alpha_codes that have been
    # stored in a DB originally using the gemojione codes, we change the original
    # gemojione code to be the primary and make the unicode version to be an alias.
    # So instead of the alpha code being `thumbs_up` based on the unicode naming,
    # it's `thumbsup`, with an alias of `thumbs_up`
    class Gemojione
      DATA_FILE = 'vendor/gemojione/index-3.3.0.json'

      # rubocop:disable Style/AsciiComments
      # These are specific gemojione whos alpha codes map slightly differently.
      # For example, :cow: in gemojione is 🐮, while in Unicode it is 🐄,
      # which is :cow2: in gemojione. Now :cow_face: will give 🐮.
      # See https://gitlab.com/gitlab-org/ruby/gems/tanuki_emoji/-/merge_requests/65#note_2113986561
      EMOJI_DIFFERENCES =
        {
          unicode: %w[📅 🐪 🐈 🐄 🐕 🐎 🐁 ✏️ 🐖 🐇 🛰️ ☃️ 🐅 🚆 ☂️ 🐋],
          gemojione: %w[📆 🐫 🐱 🐮 🐶 🐴 🐭 📝 🐷 🐰 📡 ⛄ 🐯 🚋 ☔ 🐳]
        }.freeze
      # rubocop:enable Style/AsciiComments

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
          emoji = @index.find_by_codepoints(emoji_data[:moji])

          # if it's not found, don't try to add something that isn't in the
          # Unicode set.
          next unless emoji

          if emoji.alpha_code != emoji_data[:shortname]
            org_alpha_code = emoji.alpha_code
            org_alpha_code_sym = TanukiEmoji::Character.format_name(org_alpha_code).to_sym
            emoji.replace_alpha_code(emoji_data[:shortname])

            # rubocop:disable Style/AsciiComments
            # Ensure that we're not adding an alias that is part of the gemonione data.
            # For example, Unicode uses `sunglasses` for 🕶️, which is `dark_sunglasses` in gemojione.
            # `sunglasses` is 😎 which is `smiling_face_with_sunglasses` in Unicode.
            # We don't want `sunglasses` to be added as an alias of `dark_sunglasses`, because that
            # would interfere with `sunglasses` being the primary code for `smiling_face_with_sunglasses`
            # rubocop:enable Style/AsciiComments
            emoji.add_alias(org_alpha_code) unless db.key?(org_alpha_code_sym) || EMOJI_DIFFERENCES[:unicode].include?(emoji.codepoints)
          end

          add_emoji_data(emoji, emoji_data)

          @index.update(emoji)
        end
      end

      private

      def unicode_hex_to_codepoint(unicode)
        unicode.split('-').map { |i| i.to_i(16) }.pack('U*')
      end

      def add_emoji_data(emoji, emoji_data)
        emoji_data[:unicode_alternates].each do |unicode_alternates|
          codepoints = unicode_hex_to_codepoint(unicode_alternates)

          emoji.add_codepoints(codepoints)
        end

        emoji_data[:aliases].each do |alpha_code|
          emoji.add_alias(alpha_code)
        end

        emoji_data[:aliases_ascii].each do |ascii_string|
          emoji.add_ascii_alias(ascii_string)
        end
      end
    end
  end
end

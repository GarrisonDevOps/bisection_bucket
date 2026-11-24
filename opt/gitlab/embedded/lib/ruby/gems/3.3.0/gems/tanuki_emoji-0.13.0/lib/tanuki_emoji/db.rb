# frozen_string_literal: true

module TanukiEmoji
  module Db
    autoload :Gemojione, 'tanuki_emoji/db/gemojione'
    autoload :UnicodeOrdering, 'tanuki_emoji/db/unicode_ordering'
    autoload :UnicodeVersion, 'tanuki_emoji/db/unicode_version'
    autoload :EmojiData, 'tanuki_emoji/db/emoji_data'
    autoload :EmojiDataParser, 'tanuki_emoji/db/emoji_data_parser'
    autoload :EmojiTestParser, 'tanuki_emoji/db/emoji_test_parser'
    autoload :AdditionalAliases, 'tanuki_emoji/db/additional_aliases'
  end
end

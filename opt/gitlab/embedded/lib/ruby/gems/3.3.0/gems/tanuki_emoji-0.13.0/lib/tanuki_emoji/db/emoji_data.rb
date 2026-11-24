# frozen_string_literal: true

module TanukiEmoji
  module Db
    UNICODE_VERSION = '15.1'
    UNICODE_DATA_DIR = "vendor/unicode/#{UNICODE_VERSION}".freeze

    EmojiData = Struct.new(:codepoints, :property, :version, :range_size, :examples, :description)
    EmojiTestData = Struct.new(:codepoints, :qualification, :emoji, :version, :description, :group_category)
  end
end

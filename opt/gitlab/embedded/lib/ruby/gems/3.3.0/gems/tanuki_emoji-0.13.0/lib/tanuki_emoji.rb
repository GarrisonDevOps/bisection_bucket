# frozen_string_literal: true

# Tanuki Emoji
module TanukiEmoji
  autoload :VERSION, 'tanuki_emoji/version'
  autoload :Error, 'tanuki_emoji/errors'
  autoload :AlphaCodeAlreadyIndexedError, 'tanuki_emoji/errors'
  autoload :CodepointAlreadyIndexedError, 'tanuki_emoji/errors'
  autoload :Index, 'tanuki_emoji/index'
  autoload :Character, 'tanuki_emoji/character'
  autoload :Db, 'tanuki_emoji/db'

  # Find an Emoji by its :alpha_code:
  #
  # @param [String] alpha_code
  # @return [TanukiEmoji::Character]
  def self.find_by_alpha_code(alpha_code)
    index.find_by_alpha_code(alpha_code)
  end

  # Find an Emoji by its Unicode representation
  #
  # @param [String] unicode_codepoints
  # @return [TanukiEmoji::Character]
  def self.find_by_codepoints(unicode_codepoints)
    index.find_by_codepoints(unicode_codepoints)
  end

  # Index contains all known emojis
  #
  # @return [Array<TanukiEmoji::Character>]
  def self.index
    TanukiEmoji::Index.instance
  end

  # Add a new Emoji to the index
  #
  # @param [String] name
  # @param [String] codepoints
  # @param [String] alpha_code
  # @param [String] description
  # @param [String] category
  # @return [TanukiEmoji::Character]
  def self.add(name, codepoints:, alpha_code:, description:, category:)
    emoji = Character.new(name,
      codepoints: codepoints,
      alpha_code: alpha_code,
      description: description,
      category: category)

    index.add(emoji)
  end

  def self.images_path
    File.expand_path(File.join(__dir__, "../app/assets/images/tanuki_emoji"))
  end
end

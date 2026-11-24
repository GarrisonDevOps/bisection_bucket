# frozen_string_literal: true

require 'singleton'

module TanukiEmoji
  # Index of known Emoji Characters
  class Index
    include Singleton
    include Enumerable

    # @return [Array<TanukiEmoji::Character>] a collection of TanukiEmoji::Character
    attr_reader :all

    # Add a new Emoji to the index
    #
    # @param [TanukiEmoji::Character] emoji
    # @return [TanukiEmoji::Character]
    def add(emoji)
      @name_index ||= {}
      @alpha_code_index ||= {}
      @codepoints_index ||= {}

      # Check if exists and index otherwise
      insertion_mutex.synchronize do
        raise ::TanukiEmoji::AlphaCodeAlreadyIndexedError.new emoji.name, emoji.alpha_code if @alpha_code_index.key? emoji.alpha_code
        raise ::TanukiEmoji::CodepointAlreadyIndexedError.new emoji.name, emoji.codepoints if @codepoints_index.key? emoji.codepoints

        emoji.codepoints_alternates.each do |codepoints|
          raise ::TanukiEmoji::CodepointAlreadyIndexedError.new emoji.name, codepoints if @codepoints_index.key? codepoints
        end

        add_to_index(emoji)
      end

      all << emoji

      emoji
    end

    def update(emoji)
      insertion_mutex.synchronize do
        add_to_index(emoji)
      end
    end

    # Find an Emoji by its :alpha_code:
    #
    # @param [String] alpha_code
    # @return [TanukiEmoji::Character]
    def find_by_alpha_code(alpha_code)
      return unless @alpha_code_index

      @alpha_code_index[Character.format_alpha_code(alpha_code)]
    end

    # Find an Emoji by its Unicode representation
    #
    # @param [String] unicode_codepoints
    # @return [TanukiEmoji::Character]
    def find_by_codepoints(unicode_codepoints)
      return unless @codepoints_index

      @codepoints_index[unicode_codepoints]
    end

    # Clears the index to start from scratch
    #
    # @note This is intended to be used in test and development only
    # @param [Boolean] reload whether to reload emoji database or leave it empty
    def reset!(reload: true)
      @all = []

      remove_instance_variable :@name_index if defined? @name_index
      remove_instance_variable :@alpha_code_index if defined? @alpha_code_index
      remove_instance_variable :@codepoints_index if defined? @codepoints_index

      load_data_files if reload
    end

    # Return a regular expression that can be used to search for indexed `:alpha_codes:`
    #
    # @return [Regexp] regular expression that matches indexed `:alpha_code:`
    def alpha_code_pattern
      /(?<=[^[:alnum:]:]|\n|^)
       :(#{@name_index.keys.map { |name| Regexp.escape(name) }.join("|")}):
       (?=[^[:alnum:]:]|$)/x
    end

    # Return a regular expression that can be used to search for emoji codepoints
    #
    # @param [Boolean] exclude_text_presentation exclude codepoints and sequences with text presentation selector
    # @return [Regexp] regular expression that matches indexed emoji codepoints
    def codepoints_pattern(exclude_text_presentation: false)
      possible_codepoints = sorted_codepoints.map { |moji, _| Regexp.escape(moji) }.join('|')
      variation_selector = ""
      variation_selector = /(?!#{TanukiEmoji::Character::PLAIN_VARIATION_SELECTOR_STRING})/o if exclude_text_presentation

      /(#{possible_codepoints})#{variation_selector}/
    end

    private

    # rubocop:disable Layout/ClassStructure
    def initialize
      @all = []

      load_data_files
    end
    # rubocop:enable Layout/ClassStructure

    def insertion_mutex
      @insertion_mutex ||= Mutex.new
    end

    def load_data_files
      Db::EmojiTestParser.new(index: self).load!
      Db::Gemojione.new(index: self).load!
      Db::UnicodeOrdering.new(index: self).load!
      Db::AdditionalAliases.new(index: self).load!
    end

    # Order the codepoints to match the most specific (longest) sequences first,
    # so #gsub doesn't unintentionally split an emoji from its modifier(s).
    def sorted_codepoints
      @sorted_codepoints ||= @codepoints_index.dup.sort_by { |k, v| -v.hex(k).length }
    end

    def add_to_index(emoji)
      @name_index[emoji.name] = emoji
      @alpha_code_index[emoji.alpha_code] = emoji
      @codepoints_index[emoji.codepoints] = emoji

      emoji.codepoints_alternates.each do |codepoints|
        @codepoints_index[codepoints] = emoji
      end

      emoji.aliases.each do |alpha_code|
        @name_index[::TanukiEmoji::Character.format_name(alpha_code)] = emoji
        @alpha_code_index[::TanukiEmoji::Character.format_alpha_code(alpha_code)] = emoji
      end
    end
  end
end

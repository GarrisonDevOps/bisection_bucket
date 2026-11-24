# frozen_string_literal: true

module TanukiEmoji
  # Character represents an Emoji character or sequence which can be formed by one or more Unicode code points
  # respectively which combined form a unique pictographic representation (known as Emoji)
  #
  # @see https://www.unicode.org/reports/tr51/
  class Character
    IMAGE_PREFIX = 'emoji_u'
    IMAGE_EXTENSION = '.png'
    FLAG_REGEXP = /[🇦-🇿]{2}|(\u{1F3F4}.+\u{E007F})/u
    ALPHA_CODE_REGEXP = /:(?<alpha_text>[_+\-a-z0-9]+):/

    # This denotes a "color" or "emoji" version
    EMOJI_VARIATION_SELECTOR = 0xFE0F

    # This denotes a "plain" (black/white) or "textual" version
    PLAIN_VARIATION_SELECTOR = 0xFE0E
    PLAIN_VARIATION_SELECTOR_STRING = PLAIN_VARIATION_SELECTOR.chr(Encoding::UTF_8)

    # Zero Width Joiner is used in sequences to indicate they should all be evaluated and displayed as a single thing
    ZWJ_TAG = 0x200D

    attr_reader :name, :codepoints, :codepoints_alternates, :alpha_code, :aliases, :ascii_aliases, :description, :category

    attr_accessor :unicode_version, :sort_key, :noto_image

    # Ensure alpha code is formatted with colons
    #
    # @param [String] alpha_code
    # @return [String] formatted alpha code
    def self.format_alpha_code(alpha_code)
      alpha_code.to_s.match?(ALPHA_CODE_REGEXP) ? alpha_code.to_s : ":#{alpha_code}:"
    end

    def self.format_name(raw_name)
      matched = raw_name.match(ALPHA_CODE_REGEXP)

      matched ? matched['alpha_text'] : raw_name
    end

    # @param [String] name
    # @param [String] codepoints
    # @param [String] alpha_code
    # @param [String] description
    # @param [String] category
    def initialize(name, codepoints:, alpha_code:, description:, category:)
      @name = self.class.format_name(name)
      @codepoints = codepoints
      @codepoints_alternates = []
      @alpha_code = self.class.format_alpha_code(alpha_code)
      @aliases = []
      @ascii_aliases = []
      @description = description
      @category = category
    end

    # Add alternative codepoints to this character
    #
    # @param [String] codepoints
    def add_codepoints(codepoints)
      return if @codepoints == codepoints
      return if codepoints_alternates.include?(codepoints)

      codepoints_alternates << codepoints
    end

    # Add alternative alpha_codes to this character
    #
    # @param [String] alpha_code
    def add_alias(alpha_code)
      formatted_code = self.class.format_alpha_code(alpha_code)

      return if @alpha_code == alpha_code
      return if aliases.include?(formatted_code)

      aliases << formatted_code
    end

    # Add alternative ASCII aliases to this character
    #
    # @param [String] ascii_string
    def add_ascii_alias(ascii_string)
      return if ascii_aliases.include?(ascii_string)

      ascii_aliases << ascii_string
    end

    # Replace the current alpha_code
    #
    # @param [String] alpha_code
    def replace_alpha_code(alpha_code)
      formatted_code = self.class.format_alpha_code(alpha_code)

      aliases.delete(formatted_code)

      @name = self.class.format_name(alpha_code)
      @alpha_code = formatted_code
    end

    # Return a Hex formatted version of the Unicode code points
    #
    # @return [String] Hex formatted version of the unicode
    def hex(codepoint = nil)
      codepoint ? unicode_to_hex(codepoint).join('-') : unicode_to_hex(codepoints).join('-')
    end

    # Generate the image name to be used as fallback for this character
    #
    # @return [String] image name with extension
    def image_name
      # Noto doesn't ship flags as part of regular hex-named files
      # Flags are stored in a separate third-party folder and follow ISO-3166-1 codes
      # @see http://en.wikipedia.org/wiki/ISO_3166-1
      # also see https://www.unicode.org/reports/tr51/#flag-emoji-tag-sequences for
      # regional flags.
      if flag?
        name = noto_image

        unless name
          ([alpha_code] + aliases).each do |item|
            name = item.tr(':', '').sub('flag_', '')
            break if name.length == 2
          end
        end

        return name.upcase + IMAGE_EXTENSION
      end

      # Noto omits Emoji Variation Selector on their resources file names
      IMAGE_PREFIX + unicode_to_hex(codepoints).reject { |i| i == EMOJI_VARIATION_SELECTOR.to_s(16) }.join('_') + IMAGE_EXTENSION
    end

    # Return whether current character represents a flag or not
    #
    # @return [Boolean] whether character represents a flag or not
    def flag?
      codepoints.match?(FLAG_REGEXP)
    end

    def to_s
      codepoints
    end

    def inspect
      # rubocop:disable Layout/LineLength
      %(#<#{self.class.name}: #{codepoints} (#{hex}), alpha_code: "#{alpha_code}", aliases: #{aliases}, name: "#{name}", description: "#{description}">)
      # rubocop:enable Layout/LineLength
    end

    def ==(other)
      name == other.name &&
        codepoints == other.codepoints &&
        codepoints_alternates == other.codepoints_alternates &&
        alpha_code == other.alpha_code &&
        aliases == other.aliases &&
        ascii_aliases == other.ascii_aliases &&
        description == other.description
    end

    private

    # Return each codepoint converted to its hex value as string
    #
    # @param [String] value
    # @return [Array<String>] hex value as string
    def unicode_to_hex(value)
      value.unpack('U*').map { |i| i.to_s(16).rjust(4, '0') }
    end
  end
end

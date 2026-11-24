# frozen_string_literal: true

module TanukiEmoji
  Error = Class.new(StandardError)

  # Error: An Emoji with the same alpha code has been previously indexed
  class AlphaCodeAlreadyIndexedError < Error
    attr_reader :name, :alpha_code

    # @param [String] name
    # @param [String] alpha_code
    def initialize(name, alpha_code)
      @name = name
      @alpha_code = alpha_code

      message = "Cannot index Emoji '#{name}' with alpha code '#{alpha_code}'. " \
        "An Emoji with that alpha code has already been indexed."

      super(message)
    end
  end

  # Error: An Emoji with the same codepoints has been previously indexed
  class CodepointAlreadyIndexedError < Error
    attr_reader :name, :codepoints

    # @param [String] name
    # @param [String] codepoint
    def initialize(name, codepoint)
      @name = name
      @codepoint = codepoint

      message = "Cannot index '#{name}' Emoji with codepoint: '#{codepoint}'. " \
        "An Emoji with that codepoint has already been indexed."

      super(message)
    end
  end
end

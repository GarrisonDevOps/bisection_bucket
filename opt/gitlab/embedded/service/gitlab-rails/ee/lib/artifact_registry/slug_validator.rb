# frozen_string_literal: true

module ArtifactRegistry
  # Validates an artifact registry namespace slug against the contract's
  # syntactic rules, collecting every violated rule into a single message so a
  # caller can surface them together.
  class SlugValidator
    MIN_LENGTH = 3
    MAX_LENGTH = 63

    SLUG_CHARS = /\A[a-z0-9-]+\z/
    ALNUM_START = /\A[a-z0-9]/
    ALNUM_END = /[a-z0-9]\z/
    CONSECUTIVE_HYPHENS = /--/

    def initialize(slug)
      @slug = slug.to_s
    end

    def valid?
      result.success?
    end

    def result
      @result ||= validate
    end

    private

    attr_reader :slug

    def validate
      messages = [
        validate_length,
        validate_chars,
        validate_boundary,
        validate_consecutive
      ].compact

      return ServiceResponse.success if messages.empty?

      # Each message is a full sentence, so a space joins them.
      ServiceResponse.error(message: messages.join(' '), reason: :invalid_slug)
    end

    def validate_length
      return if slug.length >= MIN_LENGTH && slug.length <= MAX_LENGTH

      format(s_('ArtifactRegistry|Must be between %{min} and %{max} characters.'), min: MIN_LENGTH, max: MAX_LENGTH)
    end

    def validate_chars
      return if slug.match?(SLUG_CHARS)

      s_('ArtifactRegistry|Only lowercase letters, digits and hyphens (-) are allowed. ' \
        'Remove any spaces or special characters.')
    end

    def validate_boundary
      return if slug.match?(ALNUM_START) && slug.match?(ALNUM_END)

      s_('ArtifactRegistry|Must start and end with an alphanumeric character.')
    end

    def validate_consecutive
      return unless slug.match?(CONSECUTIVE_HYPHENS)

      s_('ArtifactRegistry|Must not contain consecutive hyphens (--).')
    end
  end
end

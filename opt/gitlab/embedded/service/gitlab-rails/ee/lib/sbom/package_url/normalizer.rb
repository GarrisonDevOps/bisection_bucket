# frozen_string_literal: true

module Sbom
  class PackageUrl
    class Normalizer
      # Based on https://peps.python.org/pep-0503/#normalized-names
      PYPI_REGEX = /[-_\.]+/

      # Purl types whose names are compared case-insensitively, so they are downcased.
      DOWNCASED_TYPES = %w[bitbucket github golang].freeze
      # Purl types normalized following PEP 503.
      PEP503_TYPES = %w[pypi].freeze
      # Every purl type that normalize changes. Any other type is returned as given.
      NORMALIZED_TYPES = (DOWNCASED_TYPES + PEP503_TYPES).freeze

      def self.normalize_name(type:, text:)
        return text unless text.is_a?(String)

        new(type: type.to_s, text: text).normalize_name
      end

      def initialize(type:, text:)
        @type = type
        @text = text
      end

      def normalize_namespace
        return if text.nil?

        normalize
      end

      def normalize_name
        raise ArgumentError, 'Name is required' if text.nil?

        normalize
      end

      private

      def normalize
        case type
        when *DOWNCASED_TYPES then downcase
        when *PEP503_TYPES then normalize_pypi
        else text
        end
      end

      attr_reader :type, :text

      def downcase
        text.downcase
      end

      def normalize_pypi
        downcase.gsub(PYPI_REGEX, '-')
      end
    end
  end
end

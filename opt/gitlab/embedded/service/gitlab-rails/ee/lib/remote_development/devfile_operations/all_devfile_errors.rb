# frozen_string_literal: true

module RemoteDevelopment
  module DevfileOperations
    class AllDevfileErrors
      include Messages

      ERRORS = [
        DevfileYamlParseFailed,
        DevfileRestrictionsFailed,
        DevfileFlattenFailed
      ].freeze

      # NOTE: The `.===` method is how Ruby handles comparison in pattern matching.
      # @param [Class] other
      # @return [Boolean]
      def self.===(other)
        ERRORS.any? { |klass| other.is_a?(klass) }
      end
    end
  end
end

# frozen_string_literal: true

module RemoteDevelopment
  module DevfileOperations
    class DevfileProcessor
      include RemoteDevelopmentConstants
      include Messages

      # NOTE: This class exists to provide a wrapper for all the devfile validation logic so that it can be called
      #       from other classes. e.g. workspace creation.

      # @param [Hash] context
      # @return [Gitlab::Fp::Result]
      def self.validate(context)
        initial_result = Gitlab::Fp::Result.ok(context)

        initial_result
          .and_then(YamlParser.method(:parse))
          # NOTE: RestrictionsEnforcer is called first to ensure a sanitized devfile is flattened.
          .and_then(RestrictionsEnforcer.method(:enforce))
          .and_then(Flattener.method(:flatten))
          # NOTE: RestrictionsEnforcer is called again to validate the flattened devfile.
          .and_then(RestrictionsEnforcer.method(:enforce))
      end
    end
  end
end

# frozen_string_literal: true

require "hashdiff"

module RemoteDevelopment
  module WorkspaceOperations
    class DesiredConfig
      include ActiveModel::Model
      include ActiveModel::Attributes
      include ActiveModel::Validations
      include ActiveModel::Serialization
      include ActiveModel::Serializers::JSON

      # @!attribute [rw] desired_config_array
      #   @return [Array]
      attribute :desired_config_array

      validates :desired_config_array, presence: true, json_schema: {
        filename: 'workspaces_kubernetes',
        detail_errors: true,
        size_limit: 64.kilobytes
      }
      validates :desired_config_array, 'remote_development/desired_config_array': true

      # @param [DesiredConfig] other
      # @return [Boolean]
      def ==(other)
        return false unless other.is_a?(self.class)
        return true if equal?(other)

        desired_config_array == other.desired_config_array
      end

      # @param [DesiredConfig] other
      # @return [Array]
      def diff(other)
        raise ArgumentError, "Expected #{self.class}, got #{other.class}" unless other.is_a?(self.class)

        # we do not want to calculate diff using the longest common subsequence
        # because we want to catch changes at the index of self rather than find
        # the common elements between the two arrays. This example should help explain
        # the difference https://github.com/liufengyun/hashdiff/issues/43#issuecomment-485497196
        # noinspection RubyMismatchedArgumentType -- hashdiff also supports arrays
        Hashdiff.diff(desired_config_array, other.desired_config_array, use_lcs: false)
      end

      # @return [Array]
      def symbolized_desired_config_array
        as_json.fetch("desired_config_array").map(&:deep_symbolize_keys)
      end
    end
  end
end

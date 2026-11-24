# frozen_string_literal: true

module RemoteDevelopment
  class WorkspaceContainerResourcesValidator < ActiveModel::EachValidator
    # @param [RemoteDevelopment::WorkspacesAgentConfig] record
    # @param [Symbol] attribute
    # @param [Hash] value
    # @return [void]
    def validate_each(record, attribute, value)
      return true if value == {}

      unless value.is_a?(Hash)
        record.errors.add(attribute, _("must be a hash"))
        return
      end

      # noinspection RubyMismatchedArgumentType,RubyArgCount - RubyMine getting wrong #fetch type, thinks it's on Array
      limits = value.deep_symbolize_keys.fetch(:limits, nil)
      unless limits.is_a?(Hash)
        record.errors.add(attribute, _("must be a hash containing 'limits' attribute of type hash"))
        return
      end

      # noinspection RubyMismatchedArgumentType,RubyArgCount - RubyMine getting wrong #fetch type, thinks it's on Array
      requests = value.deep_symbolize_keys.fetch(:requests, nil)
      unless requests.is_a?(Hash)
        record.errors.add(attribute, _("must be a hash containing 'requests' attribute of type hash"))
        return
      end

      resources_validator = KubernetesContainerResourcesValidator.new(attributes: attribute)
      resources_validator.validate_each(record, "#{attribute}_limits", limits)
      resources_validator.validate_each(record, "#{attribute}_requests", requests)

      nil
    end
  end
end

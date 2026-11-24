# frozen_string_literal: true

module Ai
  module ModelSelection
    class BaseUpdateAllowlistService
      def initialize(feature:, enabled:, model_refs:)
        @feature = feature
        @enabled = enabled
        @model_refs = model_refs
      end

      def execute
        return feature_not_supported_error(feature_setting) unless feature_setting.model_allowlist_supported?

        catalog = ::Ai::ModelSelection::ModelDefinitions.fetch

        return ServiceResponse.error(message: catalog.error_message) unless catalog.success?

        normalized_refs = feature_setting.normalize_allowlist_model_refs(
          model_refs,
          enabled: enabled,
          model_definition_parser: catalog.parser
        )

        update_params = {
          model_allowlist_enabled: enabled,
          model_allowlist_gitlab_model_refs: normalized_refs,
          model_definitions: catalog.payload
        }

        if feature_setting.update(update_params)
          ServiceResponse.success(payload: feature_setting)
        else
          ServiceResponse.error(payload: feature_setting, message: feature_setting.errors.full_messages.join(", "))
        end
      end

      private

      attr_reader :feature, :enabled, :model_refs

      def feature_setting
        raise ::Gitlab::AbstractMethodError
      end

      def feature_not_supported_error(setting)
        ServiceResponse.error(
          payload: setting,
          message: format(
            _("Model allowlists are not supported for the feature '%{feature}'."),
            feature: feature
          )
        )
      end
    end
  end
end

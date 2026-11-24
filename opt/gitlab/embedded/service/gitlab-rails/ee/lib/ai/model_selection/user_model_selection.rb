# frozen_string_literal: true

module Ai
  module ModelSelection
    class UserModelSelection
      include ::Gitlab::Utils::StrongMemoize

      def self.for(current_user, feature_setting:)
        if feature_setting&.self_hosted? && feature_setting.self_hosted_model.present?
          return SelfHostedModelSelection.new(feature_setting)
        end

        new(current_user, feature_setting: feature_setting)
      end

      def initialize(current_user, feature_setting:)
        @current_user = current_user
        @feature_setting = feature_setting
      end

      def default_model
        return unless user_selection_available?

        preferred_default_model
      end

      def selectable_models
        return [] unless user_selection_available?

        # Credit-gated models stay in the list so that the picker can badge them and
        # offer a purchase path, rather than hiding a model the namespace could buy.
        allowed_selectable_models
      end
      strong_memoize_attr :selectable_models

      def pinned_model
        return unless user_selection_available?
        return unless effectively_pinned?

        model_for(feature_setting.offered_model_ref)
      end

      # Refs that model requests outside the picker must stay within, or nil when unrestricted.
      # Without model definitions the default ref is unknown, so only stored refs remain (possibly none).
      def enforced_model_refs
        return unless feature_setting
        return unless allowlist_feature_enabled?

        feature_setting.effective_allowed_model_refs(model_definition_parser)
      end

      def do_not_consider_user_selected_model?(user_selected_model_identifier)
        !user_selected_model_eligible?(user_selected_model_identifier) ||
          credit_gated?(user_selected_model_identifier)
      end

      def credit_gated?(model_ref)
        credit_gate.gated?(model_ref) { model_definition_parser }
      end

      def user_selected_model_credit_gated?(model_ref)
        user_selected_model_eligible?(model_ref) && credit_gated?(model_ref)
      end

      private

      attr_reader :current_user, :feature_setting

      def user_selected_model_eligible?(model_ref)
        return false unless feature_setting && agentic_chat_feature?
        return false if effectively_pinned?

        user_selected_model_allowed?(model_ref)
      end

      # The admin's chosen model is a hard pin (disabling user selection) only when
      # the allowlist is not active. With the allowlist on it is just a default, so
      # user selection stays enabled and the pick is validated against the allowlist.
      def effectively_pinned?
        return false if credit_gated?(feature_setting.try(:offered_model_ref))

        feature_setting.pinned_model? && !allowlist_feature_enabled?
      end

      def preferred_default_model
        model = chosen_default_model
        return model unless credit_gated?(model&.dig(:ref))

        catalog_default_ref = decorator.default_model.to_h[:ref]
        offered = allowed_selectable_models.reject { |offered_model| credit_gated?(offered_model[:ref]) }

        offered.find { |offered_model| offered_model[:ref] == catalog_default_ref } || offered.first
      end

      def chosen_default_model
        return decorator.default_model unless allowlist_feature_enabled?

        chosen_ref = feature_setting.currently_chosen_model_ref(model_definition_parser)
        model_for(chosen_ref)
      end

      def allowed_selectable_models
        return decorator.selectable_models unless allowlist_feature_enabled?

        allowed_refs = feature_setting.effective_allowed_model_refs(model_definition_parser)
        decorator.selectable_models.select { |model| allowed_refs.include?(model[:ref]) }
      end

      def credit_gate
        ::Ai::ModelSelection::CreditGate.new(feature_setting.try(:namespace))
      end
      strong_memoize_attr :credit_gate

      def allowlist_feature_available?
        feature_setting.model_allowlist_supported?
      end

      def allowlist_feature_enabled?
        return false unless allowlist_feature_available?

        feature_setting.model_allowlist_enabled
      end
      strong_memoize_attr :allowlist_feature_enabled?

      def agentic_chat_feature?
        return false unless feature_setting

        feature_setting.feature.to_sym == ::Ai::ModelSelection::FeaturesConfigurable.agentic_chat_feature_name
      end

      def user_selected_model_allowed?(ref)
        ref.present? && selectable_models.any? { |model| model[:ref] == ref }
      end

      def user_selection_available?
        feature_setting.present? &&
          decorator.present? &&
          feature_setting.user_model_selection_available?
      end
      strong_memoize_attr :user_selection_available?

      def model_for(ref)
        return if ref.blank?

        decorator.selectable_models.find { |model| model[:ref] == ref }
      end

      def decorator
        return unless feature_setting
        return unless model_definitions

        ::Gitlab::Graphql::Representation::ModelSelection::FeatureSetting
          .decorate([feature_setting],
            model_definitions: model_definitions, current_user: current_user, credit_gate: credit_gate)
          .find { |object| object.feature_setting&.feature&.to_sym == feature_setting.feature.to_sym }
      end
      strong_memoize_attr :decorator

      def model_definitions
        model_definitions_catalog.payload
      end

      def model_definition_parser
        model_definitions_catalog.parser
      end
      strong_memoize_attr :model_definition_parser

      def model_definitions_catalog
        ::Ai::ModelSelection::ModelDefinitions.fetch(current_user)
      end
      strong_memoize_attr :model_definitions_catalog
    end
  end
end

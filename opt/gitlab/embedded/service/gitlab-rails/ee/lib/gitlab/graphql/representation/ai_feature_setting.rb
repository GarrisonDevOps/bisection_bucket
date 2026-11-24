# frozen_string_literal: true

module Gitlab
  module Graphql
    module Representation
      class AiFeatureSetting < SimpleDelegator
        class << self
          include Gitlab::Utils::StrongMemoize

          def decorate(
            feature_settings, with_self_hosted_models: false, with_gitlab_models: false,
            model_definitions: nil)
            return [] unless feature_settings.present?

            # Hoisted out of the per-model path: CreditGate only memoizes per instance, and the
            # instance surface has no namespace to vary on.
            credit_gate = ::Ai::ModelSelection::CreditGate.new(nil) if model_definitions

            feature_settings.map do |feature_setting|
              new(
                feature_setting,
                **valid_model_params(feature_setting, with_self_hosted_models),
                **gitlab_managed_models_params(
                  feature_setting, model_definitions, with_gitlab_models, credit_gate
                )
              )
            end
          end

          private

          def valid_model_params(feature_setting, with_valid_models)
            return {} unless with_valid_models

            compatible_llms = feature_setting.compatible_llms || []

            indexed_self_hosted_models = ::Ai::SelfHostedModel.all.group_by(&:model)

            valid_models = compatible_llms.flat_map do |model|
              indexed_self_hosted_models[model] || []
            end

            valid_models = valid_models.filter(&:ga?) unless beta_models_enabled?

            {
              valid_models: valid_models.sort_by(&:name)
            }
          end

          def gitlab_managed_models_params(feature_setting, model_definitions, with_valid_models, credit_gate)
            return {} unless model_definitions

            feature_name = feature_setting.feature

            instance_model_selection_setting = nil
            model_ref = nil

            if feature_setting.vendored?
              instance_model_selection_setting = ::Ai::ModelSelection::InstanceModelSelectionFeatureSetting
                .find_or_initialize_by_feature(feature_name)
              model_ref = instance_model_selection_setting.offered_model_ref
            end

            definition = model_definitions.definition_for_feature(feature_name)

            return {} unless definition

            valid_models = []

            if with_valid_models
              valid_models = model_definitions.selectable_model_refs_for_feature(feature_name).map do |ref|
                gitlab_model_with_credit_gate(model_definitions, ref, credit_gate)
              end
            end

            {
              gitlab_model: gitlab_model_with_credit_gate(model_definitions, model_ref, credit_gate),
              default_gitlab_model: gitlab_model_with_credit_gate(
                model_definitions, model_definitions.default_model_ref_for_feature(feature_name), credit_gate
              ),
              valid_gitlab_models: valid_models,
              allow_list: build_allow_list(
                instance_model_selection_setting, model_definitions, feature_name, credit_gate
              )
            }
          end

          def gitlab_model_with_credit_gate(model_definitions, model_ref, credit_gate)
            model = model_definitions.model_with_ref(model_ref)
            return model unless model

            model.merge(requires_paid_credits: credit_gate.gated?(model_ref) { model_definitions })
          end

          def build_allow_list(instance_model_selection_setting, model_definitions, feature_name, credit_gate)
            return unless instance_model_selection_setting&.model_allowlist_supported?

            offered_models = model_definitions.selectable_model_refs_for_feature(feature_name).map do |ref|
              gitlab_model_with_credit_gate(model_definitions, ref, credit_gate)
            end

            ::Gitlab::Graphql::Representation::ModelSelection::AllowListPayload.build(
              feature_setting: instance_model_selection_setting,
              model_definition_parser: model_definitions,
              offered_models: offered_models
            )
          end

          def beta_models_enabled?
            ::Ai::TestingTermsAcceptance.has_accepted?
          end
        end

        attr_accessor :feature_setting, :valid_models, :valid_gitlab_models, :gitlab_model, :default_gitlab_model,
          :allow_list

        def initialize(
          feature_setting, valid_models: [], valid_gitlab_models: [], gitlab_model: nil,
          default_gitlab_model: nil, allow_list: nil)
          @feature_setting = feature_setting
          @valid_models = valid_models
          @valid_gitlab_models = valid_gitlab_models
          @default_gitlab_model = default_gitlab_model
          @gitlab_model = gitlab_model
          @allow_list = allow_list

          super(feature_setting)
        end
      end
    end
  end
end

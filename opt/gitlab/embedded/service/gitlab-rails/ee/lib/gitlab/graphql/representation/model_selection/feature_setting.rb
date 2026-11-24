# frozen_string_literal: true

module Gitlab
  module Graphql
    module Representation
      module ModelSelection
        class FeatureSetting < SimpleDelegator
          class << self
            def decorate(feature_settings, model_definitions: nil, current_user: nil, credit_gate: nil)
              return [] unless feature_settings.present?

              credit_gates = credit_gate ? { credit_gate.namespace => credit_gate } : {}

              feature_settings.filter_map do |feature_setting|
                namespace = feature_setting.try(:namespace)
                credit_gates[namespace] ||= ::Ai::ModelSelection::CreditGate.new(namespace)

                decorator = new(feature_setting,
                  model_definitions: model_definitions,
                  current_user: current_user,
                  credit_gate: credit_gates[namespace]
                )

                next if decorator.feature_data.nil?

                if model_definitions.present? || feature_setting.try(:model_definitions).present?
                  decorator.decorate_default_model

                  decorator.decorate_selectable_models

                  decorator.decorate_allow_list
                end

                next decorator
              end
            end
          end

          attr_accessor :feature_setting, :default_model, :selectable_models, :allow_list, :model_definitions
          attr_reader :current_user

          def initialize(feature_setting, credit_gate:, model_definitions: nil, current_user: nil)
            @feature_setting = feature_setting
            @model_definitions = model_definitions || feature_setting.try(:model_definitions)
            @current_user = current_user
            @credit_gate = credit_gate
            super(feature_setting)
          end

          def feature_data
            return if model_definitions.blank?

            @feature_data ||= model_definition_parser.definition_for_feature(feature_setting.feature)
          end

          def decorate_default_model
            model_ref = model_definition_parser.default_model_ref_for_feature(feature_setting.feature)
            model_data = find_single_model_data(model_ref)
            @default_model = model_data.presence
          end

          def decorate_selectable_models
            model_refs = model_definition_parser.selectable_model_refs_for_feature(
              feature_setting.feature,
              include_dev: use_dev_overrides?
            )
            @selectable_models = model_refs.filter_map do |model_ref|
              next unless namespace_eligible_for?(model_ref)

              find_single_model_data(model_ref)
            end
          end

          def decorate_allow_list
            return unless feature_setting.model_allowlist_supported?

            @allow_list = ::Gitlab::Graphql::Representation::ModelSelection::AllowListPayload.build(
              feature_setting: feature_setting,
              model_definition_parser: model_definition_parser,
              offered_models: selectable_models,
              group: feature_setting.try(:namespace)
            )
          end

          private

          attr_reader :credit_gate

          def namespace_eligible_for?(model_ref)
            ::Gitlab::Ai::ModelSelection::RestrictedNamespaceModels.namespace_eligible?(
              feature_setting.try(:namespace), model_ref
            )
          end

          def use_dev_overrides?
            return false unless Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
            return false unless current_user&.gitlab_team_member?

            dev_config.present?
          end

          def find_single_model_data(model_ref)
            model_definition_parser.model_with_ref!(model_ref)
              .merge(requires_paid_credits: credit_gate.gated?(model_ref) { model_definition_parser })
          end

          def model_definition_parser
            @model_definition_parser ||= ::Gitlab::Ai::ModelSelection::ModelDefinitionResponseParser.new(
              model_definitions
            )
          end

          def dev_config
            @dev_config ||= feature_data['dev']
          end
        end
      end
    end
  end
end

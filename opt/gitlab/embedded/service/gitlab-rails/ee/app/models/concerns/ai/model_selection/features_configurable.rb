# frozen_string_literal: true

module Ai
  module ModelSelection
    module FeaturesConfigurable
      extend ActiveSupport::Concern
      include Ai::FeatureConfigurable

      MODEL_PROVIDER = "gitlab"

      FEATURES = {
        code_generations: 0,
        code_completions: 1,
        duo_chat: 2,
        duo_chat_explain_code: 3,
        duo_chat_write_tests: 4,
        duo_chat_refactor_code: 5,
        duo_chat_fix_code: 6,
        duo_chat_troubleshoot_job: 7,
        generate_commit_message: 8,
        summarize_new_merge_request: 9,
        duo_chat_explain_vulnerability: 10,
        resolve_vulnerability: 11,
        summarize_review: 12,
        glab_ask_git_command: 13,
        duo_chat_summarize_comments: 14,
        review_merge_request: 15,
        duo_agent_platform: 16,
        duo_agent_platform_agentic_chat: 17,
        sast_vulnerability_fp_detection: 18,
        secret_vulnerability_fp_detection: 19,
        sast_vulnerability_resolution: 20,
        review_merge_request_dap: 21,
        security_review: 22,
        embeddings_code: 23,
        feature_discovery_search: 24,
        resolve_dependency_bump: 25,
        duo_developer: 26,
        bl_security: 27,
        recommend_reviewers_assign: 28,
        risk_classification: 29,
        review_merge_request_dap_standard: 30
      }.freeze
      # See full feature list at ee/app/models/ai/feature_setting.rb

      FEATURES_UNDER_FLAGS = {
        summarize_review: :summarize_my_code_review,
        summarize_new_merge_request: :add_ai_summary_for_new_mr,
        feature_discovery_search: :feature_discovery_gemini_search,
        bl_security: :bl_security_analyzer,
        risk_classification: :duo_mr_risk_classification,
        review_merge_request_dap_standard: :duo_code_review_standard_flow
      }.freeze
      # Keys are :feature enum values
      # Values are the names of the Feature Flags used to enable the features
      # See https://gitlab.com/gitlab-org/gitlab/-/issues/543087 for more context

      DUO_CHAT_FEATURES = [
        :duo_chat,
        :duo_chat_explain_code,
        :duo_chat_write_tests,
        :duo_chat_refactor_code,
        :duo_chat_fix_code,
        :duo_chat_troubleshoot_job,
        :duo_chat_explain_vulnerability,
        :duo_chat_summarize_comments
      ].freeze

      DUO_CHAT_TOOLS = [
        :duo_chat_build_reader,
        :duo_chat_epic_reader,
        :duo_chat_issue_reader,
        :duo_chat_merge_request_reader,
        :duo_chat_commit_reader,
        :duo_chat_gitlab_documentation,
        :duo_chat_work_item_reader
      ].freeze
      # Duo chat tools need to be mapped to the base 'duo_chat' feature
      # to ensure proper model selection when these tools are used.
      # This prevents bugs when tool-specific features are passed to
      # Gitlab::Llm::Chain::Requests::AiGateway#namespace_feature_setting
      # See https://gitlab.com/gitlab-org/gitlab/-/issues/551318

      # Override in subclasses to exclude features that are not applicable at that level.
      # Keys should match FEATURES keys, values are enum integers
      # See .enabled_features_for(feature_flag_scope)
      LEVEL_EXCLUDED_FEATURES = {}.freeze

      def self.agentic_chat_feature_name
        :duo_agent_platform_agentic_chat
      end

      def self.workflow_feature_name
        :duo_agent_platform
      end

      included do
        enum :feature, FEATURES, validate: true

        validates :feature, presence: true
        validate :validate_model_ref_with_definition

        scope :non_default, -> { where.not(offered_model_ref: [nil, ""]) }

        delegate :title, :main_feature, to: :metadata, allow_nil: true

        attribute :model_definitions, default: {}

        after_validation :set_model_name, if: -> { offered_model_ref_changed? }

        def self.find_or_initialize_by_feature
          raise NotImplementedError,
            '.find_or_initialize_by_feature method must be implemented for Model Selection logic'
        end

        # rubocop: disable Gitlab/FeatureFlagKeyDynamic -- The whole goal of this method is to dynamically filter out disabled features
        def self.enabled_features_for(feature_flag_scope)
          excluded = LEVEL_EXCLUDED_FEATURES.keys

          excluded += if feature_flag_scope.experiment_features_enabled
                        FEATURES_UNDER_FLAGS.filter_map do |feature, flag|
                          feature if ::Feature.disabled?(flag, feature_flag_scope)
                        end
                      else
                        FEATURES_UNDER_FLAGS.keys
                      end

          FEATURES.except(*excluded)
        end
        # rubocop: enable Gitlab/FeatureFlagKeyDynamic

        def self.get_feature_name(feature_name)
          return "duo_chat" if DUO_CHAT_TOOLS.include?(feature_name.to_sym)

          feature_name
        end

        def self_hosted?
          false
        end

        def disabled?
          false
        end

        def vendored?
          false
        end

        def provider
          MODEL_PROVIDER
        end

        def base_url
          Gitlab::AiGateway.url
        end

        def model_metadata_params
          {
            provider: provider,
            feature_setting: feature,
            identifier: offered_model_ref
          }
        end

        def model_request_params
          model_metadata_params
        end

        def set_to_gitlab_default?
          offered_model_ref.blank?
        end

        def pinned_model?
          !set_to_gitlab_default?
        end

        private

        def validate_model_ref_with_definition
          return if offered_model_ref.blank?

          return unless model_definition_present?

          unless model_definition_parser.definition_for_feature(feature).present?
            errors.add(:offered_model_ref, 'Feature not found in model definitions')
            return
          end

          if model_definition_parser.selectable_model_refs_for_feature(feature).exclude?(offered_model_ref)
            add_model_not_compatible_error
            return
          end

          add_model_requires_credits_error if newly_selected_credit_gated_model?
        end

        def newly_selected_credit_gated_model?
          return false unless will_save_change_to_offered_model_ref?

          ::Ai::ModelSelection::CreditGate.new(try(:namespace)).applies? &&
            model_definition_parser.model_requires_paid_credits?(offered_model_ref)
        end

        def set_model_name
          if offered_model_ref.blank?
            self.offered_model_name = offered_model_ref
            return
          end

          return unless model_definition_present?

          model_data = model_definition_parser.model_with_ref(offered_model_ref)

          unless model_data
            errors.add(:offered_model_ref, 'Model reference not found in definitions')
            return
          end

          model_name = model_data[:name]

          if model_name.blank?
            errors.add(:offered_model_ref, 'No model name found in model data')
            return
          end

          self.offered_model_name = model_name
        end

        def model_definition_present?
          return true if model_definitions.present?

          errors.add(:feature, "No model definition given for validation")
          false
        end

        def model_definition_parser
          ::Gitlab::Ai::ModelSelection::ModelDefinitionResponseParser.new(model_definitions)
        end

        def add_model_not_compatible_error
          errors.add(:offered_model_ref,
            "Selected model '#{offered_model_ref}' is not compatible with the feature '#{feature}'")
        end

        def add_model_requires_credits_error
          errors.add(:offered_model_ref,
            "Selected model '#{offered_model_ref}' requires purchased GitLab Credits")
        end
      end
    end
  end
end

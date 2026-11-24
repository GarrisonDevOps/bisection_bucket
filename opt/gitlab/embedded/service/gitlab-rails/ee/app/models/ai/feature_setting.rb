# frozen_string_literal: true

module Ai
  class FeatureSetting < ApplicationRecord
    include ::Ai::FeatureConfigurable
    include ::Ai::ModelSelection::Concerns::GitlabDefaultModelParams

    self.table_name = "ai_feature_settings"

    STABLE_FEATURES = {
      code_generations: 0,
      code_completions: 1,
      duo_chat: 2,
      duo_chat_explain_code: 3,
      duo_chat_write_tests: 4,
      duo_chat_refactor_code: 5,
      duo_chat_fix_code: 6,
      review_merge_request: 15,
      duo_agent_platform: 16,
      duo_agent_platform_agentic_chat: 17,
      review_merge_request_dap: 21,
      secret_vulnerability_fp_detection: 19,
      duo_developer: 26,
      recommend_reviewers_assign: 28
    }.freeze

    FLAGGED_FEATURES = {
      duo_chat_troubleshoot_job: 7,
      generate_commit_message: 8,
      summarize_new_merge_request: 9,
      duo_chat_explain_vulnerability: 10,
      resolve_vulnerability: 11,
      summarize_review: 12,
      glab_ask_git_command: 13,
      duo_chat_summarize_comments: 14,
      sast_vulnerability_fp_detection: 18,
      sast_vulnerability_resolution: 20,
      security_review: 22,
      embeddings_code: 23,
      feature_discovery_search: 24,
      resolve_dependency_bump: 25,
      bl_security: 27,
      risk_classification: 29,
      review_merge_request_dap_standard: 30
    }.freeze

    FEATURES = STABLE_FEATURES.merge(FLAGGED_FEATURES)

    FEATURES_UNDER_FLAGS = {
      bl_security: :bl_security_analyzer,
      risk_classification: :duo_mr_risk_classification,
      review_merge_request_dap_standard: :duo_code_review_standard_flow
    }.freeze

    # Features gated by a foundational flow's own enablement check instead of their flag.
    FEATURES_UNDER_FOUNDATIONAL_FLOWS = {
      bl_security: -> { ::Ai::Catalog::FoundationalFlow.bl_security_experimental }
    }.freeze

    belongs_to :self_hosted_model, foreign_key: :ai_self_hosted_model_id, inverse_of: :feature_settings

    validates :self_hosted_model, presence: true, if: :self_hosted?
    validates :feature, presence: true, uniqueness: true
    validates :provider, presence: true

    validate :validate_model, if: :self_hosted?

    scope :find_or_initialize_by_feature, ->(feature) { find_or_initialize_by(feature: feature) }
    scope :for_self_hosted_model, ->(self_hosted_model_id) { where(ai_self_hosted_model_id: self_hosted_model_id) }

    enum :provider, {
      disabled: 0,
      vendored: 1,
      self_hosted: 2,
      unassigned: 3
    }, default: :unassigned

    enum :feature, STABLE_FEATURES.merge(FLAGGED_FEATURES)

    delegate :title, :main_feature, :compatible_llms, :release_state, to: :metadata, allow_nil: true

    class << self
      include Gitlab::Utils::StrongMemoize

      def provider_titles
        {
          disabled: s_('AdminAiPoweredFeatures|Disabled'),
          vendored: s_('AdminAiPoweredFeatures|GitLab AI vendor model'),
          self_hosted: s_('AdminAiPoweredFeatures|Self-hosted model')
        }.with_indifferent_access.freeze
      end

      def select_allowed(feature_settings)
        allowed = allowed_features

        feature_settings.select { |feature_setting| allowed.key?(feature_setting.feature) }
      end

      def allowed_features
        allowed_features = STABLE_FEATURES.dup

        if ::Ai::TestingTermsAcceptance.has_accepted?
          # FLAGGED_FEATURES are in beta status. We must ensure the GitLab Testing Terms
          # have been accepted by the user in order for them to be used.
          # https://handbook.gitlab.com/handbook/legal/testing-agreement/
          allowed_features = allowed_features.merge(FLAGGED_FEATURES)
        elsif ::Gitlab::CurrentSettings.instance_level_ai_beta_features_enabled?
          # Turning on the instance-level AI beta setting accepts the beta terms, so flows
          # GitLab has enabled for this instance need no separate acceptance.
          allowed_features = allowed_features.merge(FLAGGED_FEATURES.slice(*features_enabled_per_instance))
        end

        if ::License.current&.premium?
          allowed_features = allowed_features.except(
            :duo_chat_explain_vulnerability,
            :resolve_vulnerability
          )
        end

        # rubocop: disable Gitlab/FeatureFlagKeyDynamic -- The whole goal of this method is to dynamically filter out disabled features
        disabled_features = FEATURES_UNDER_FLAGS.filter_map do |feature, flag|
          # The flow's own check also covers its per-instance gate (see FoundationalFlow#enabled_for?).
          flow = foundational_flow_for(feature)
          enabled = flow ? flow.enabled_for?(:instance) : ::Feature.enabled?(flag, :instance)

          feature unless enabled
        end
        # rubocop: enable Gitlab/FeatureFlagKeyDynamic

        allowed_features = allowed_features.except(*disabled_features)

        allowed_features.stringify_keys
      end

      def feature_for_unit_primitive(unit_primitive)
        feature_name = feature_name_for_unit_primitive(unit_primitive)
        return unless feature_name

        find_by_feature(feature_name)
      end

      def feature_name_for_unit_primitive(unit_primitive)
        return unless unit_primitive

        unit_primitive_to_feature_name_map[unit_primitive.to_s]
      end

      def unit_primitive_to_feature_name_map
        ::Ai::FeatureConfigurable::FEATURE_METADATA.each_with_object({}) do |(feature_name, metadata), result|
          metadata['unit_primitives'].each do |unit_primitive|
            result[unit_primitive] = feature_name
          end
        end
      end
      strong_memoize_attr(:unit_primitive_to_feature_name_map)

      private

      def foundational_flow_for(feature)
        FEATURES_UNDER_FOUNDATIONAL_FLOWS[feature]&.call
      end

      # Flow-backed features GitLab has enabled for this instance.
      def features_enabled_per_instance
        FEATURES_UNDER_FOUNDATIONAL_FLOWS.keys.select do |feature|
          flow = foundational_flow_for(feature)
          flow.per_instance_gate_applies? && flow.enabled_for?(:instance)
        end
      end
    end

    def provider_title
      title = self.class.provider_titles[provider]
      return title unless self_hosted?

      "#{title} (#{self_hosted_model.name})"
    end

    def base_url
      return Gitlab::AiGateway.cloud_connector_url if vendored?

      Gitlab::AiGateway.url if self_hosted?
    end

    def validate_model
      return unless compatible_llms.present?
      return unless self_hosted_model.present?

      selected_model = self_hosted_model.model

      return if compatible_llms.include?(selected_model)

      message = format(s_('AdminAiPoweredFeatures|%{selected_model} is incompatible with the %{title} feature'),
        selected_model: selected_model.capitalize,
        title: title)
      errors.add(:base, message)
    end

    def ready_for_request?
      self_hosted? && self_hosted_model
    end

    def model_metadata_params
      return params_as_if_gitlab_default_model(feature) if vendored?
      return unless ready_for_request?

      {
        provider: :openai,
        name: self_hosted_model.model,
        endpoint: self_hosted_model.endpoint,
        api_key: self_hosted_model.api_token,
        identifier: self_hosted_model.identifier
      }.merge(self_hosted_model.iam_role_metadata)
    end

    def model_request_params
      return params_as_if_gitlab_default_model(feature) if vendored?
      return unless ready_for_request?

      {
        provider: :litellm,
        model: self_hosted_model.model,
        model_endpoint: self_hosted_model.endpoint,
        model_api_key: self_hosted_model.api_token,
        model_identifier: self_hosted_model.identifier
      }
    end

    def user_model_selection_available?
      false
    end

    # `Ai::FeatureSetting` does not back the model allowlist columns; the
    # admin allowlist lives on `Ai::ModelSelection::InstanceModelSelectionFeatureSetting`.
    # The companion predicate in `Ai::ModelSelection::ModelAllowlist` returns
    # true only for Agentic Chat.
    def model_allowlist_supported?
      false
    end
  end
end

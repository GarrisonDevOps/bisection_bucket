# frozen_string_literal: true

module Gitlab
  module Dedicated
    MissingFeatureError = Class.new(StandardError)

    FEATURES =
      %i[
        elasticsearch_on_dedicated
        skip_ultimate_trial_experience
        group_project_permanent_deletion_confirmation
        skip_runner_registration_token_disabling
        hosted_runners
        self_hosted_models
        vac_on_dedicated
        restricted_flow_proof_tokens
        read_dedicated_hosted_runner_usage
        cloud_connector_on_dedicated
        skip_self_managed_onboarding
        restrict_self_hosted_ai_gateway
        ai_flow_enablement
        snowplow_dedicated_app_id
        usage_quotas_admin_menu_on_dedicated
        enforce_language_server_version_on_dedicated
      ].freeze

    CONFIG_FILE_ROOT = 'ee/config/dedicated_features'

    class << self
      def feature_available?(feature)
        raise MissingFeatureError, 'Feature does not exist' unless FEATURES.include?(feature)

        dedicated_instance?
      end

      def dedicated_instance?
        ::Gitlab::CurrentSettings.gitlab_dedicated_instance?
      end

      def feature_file_path(feature)
        Rails.root.join(CONFIG_FILE_ROOT, "#{feature}.yml")
      end
    end
  end
end

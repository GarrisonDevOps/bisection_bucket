# frozen_string_literal: true

module Gitlab
  module Saas
    MissingFeatureError = Class.new(StandardError)

    FEATURES =
      %i[
        ai_catalog
        cloud_connector_static_catalog
        experimentation
        marketing_google_tag_manager
        marketing_site_language
        namespaces_storage_limit
        onboarding
        purchases_additional_minutes
        subscriptions_trials
        gitlab_com_subscriptions
        duo_chat_categorize_question
        gitlab_terms
        google_cloud_support
        duo_chat_on_saas
        exact_code_search
        overage_members_modal
        advanced_search
        group_credentials_inventory
        identity_verification
        gitlab_duo_saas_only
        pipl_compliance
        disable_personal_access_tokens
        disable_ssh_keys
        ci_runners_allowed_plans
        secret_detection_service
        ci_component_usages_in_projects
        redirect_sign_in_when_login_not_found
        deduplicate_ci_tags
        targeted_messages
        instance_push_limit
        hide_project_instance_tab
        cloud_connector_self_signed_tokens
        group_disable_invite_members
        service_accounts_invite_restrictions
        notify_compromised_passwords
        repositories_web_based_commit_signing
        security_scans_api
        scheduled_scan_default_time_window
        admin_homepage
        allow_personal_snippets
        prevent_enterprise_user_account_deletion
        cdot_requests
        cdot_graphql_proxy
        designated_account_beneficiaries
        enforce_top_level_group_limits
        group_project_permanent_deletion_confirmation
        disable_partial_email_search
        namespace_scoped_work_item_types
        mcp_server_saas_only
        observability_hosted_service
        skip_dynamic_oauth_app_user_stamp
        dependency_firewall
        siphon_clickhouse_analytics
        policy_store_default_organization_isolation
      ].freeze

    CONFIG_FILE_ROOT = 'ee/config/saas_features'

    class << self
      def feature_available?(feature)
        # Do not shim or create this method in FOSS
        # see: https://gitlab.com/gitlab-org/gitlab/-/issues/575615
        raise MissingFeatureError, 'Feature does not exist' unless FEATURES.include?(feature)

        enabled?
      end

      def enabled?
        # Use existing checks initially. We can allow it only in this place and remove it anywhere else.
        # eventually we can change its implementation like using an ENV variable for each instance
        # or any other method that people can't mess with.
        ::Gitlab.com? # rubocop:disable Gitlab/AvoidGitlabInstanceChecks  -- See above comment
      end

      def feature_file_path(feature)
        Rails.root.join(CONFIG_FILE_ROOT, "#{feature}.yml")
      end

      def gitlab_com_status_url
        'https://status.gitlab.com'
      end

      def customer_support_url
        'https://support.gitlab.com'
      end
    end
  end
end

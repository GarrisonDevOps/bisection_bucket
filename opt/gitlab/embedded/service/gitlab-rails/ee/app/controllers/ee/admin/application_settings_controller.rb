# frozen_string_literal: true

module EE
  module Admin
    module ApplicationSettingsController
      extend ::Gitlab::Utils::Override
      extend ActiveSupport::Concern
      include ::GitlabSubscriptions::MemberManagement::PromotionManagementUtils
      include SafeFormatHelper

      UNINDEXED_PROJECT_DISPLAY_LIMIT = 50

      prepended do
        include ::WorkItems::SettingsPermissions
        # check es_helper.ping? if before_action reaches out to Elasticsearch
        before_action :elasticsearch_reindexing_task, only: [:search]
        before_action :elasticsearch_reindexing_state, only: [:search]
        before_action :elasticsearch_index_settings, only: [:search]
        before_action :elasticsearch_warn_if_not_using_aliases, only: [:search], if: -> { es_helper.ping? }
        before_action :elasticsearch_warn_if_obsolete_migrations, only: [:search], if: -> { es_helper.ping? }
        before_action :elasticsearch_pending_obsolete_migrations, only: [:search], if: -> { es_helper.ping? }
        before_action :indexing_status, only: [:search]
        before_action :search_error_if_version_incompatible, only: [:search], if: -> { es_helper.ping? }
        before_action :search_outdated_code_analyzer_detected, only: [:search], if: -> { es_helper.ping? }
        before_action :semantic_search_available, only: [:search]
        before_action :semantic_search_settings, only: [:search]
        before_action :check_work_item_settings_availability, only: [:work_item]
        before_action :set_hide_search_settings, only: [:work_item, :security_and_compliance]

        before_action :new_license, only: [:general]
        before_action :scim_token, only: [:general]
        before_action :push_frontend_license_features, only: [:general]

        before_action :check_microsoft_group_sync_available, only: [:update_microsoft_application]
        before_action :find_or_initialize_microsoft_application, only: [:general, :update_microsoft_application]

        before_action :verify_subscriptions_available!, only: [:namespace_storage]

        feature_category :plan_provisioning, [:seat_link_payload]
        feature_category :source_code_management, [:templates]
        feature_category :global_search, [:search]
        feature_category :software_composition_analysis, [:security_and_compliance]
        feature_category :consumables_cost_management, [:namespace_storage]
        feature_category :system_access, [:update_microsoft_application]
        feature_category :team_planning, [:work_item]
        urgency :low, [:search, :seat_link_payload]

        def elasticsearch_reindexing_task
          @last_elasticsearch_reindexing_task = ::Search::Elastic::ReindexingTask.last
          @elasticsearch_reindexing_task = ::Search::Elastic::ReindexingTask.new
        end

        def elasticsearch_index_settings
          @elasticsearch_index_settings = Elastic::IndexSetting.order_by_name
        end

        def elasticsearch_reindexing_state
          normalized_status = @last_elasticsearch_reindexing_task&.state || 'initial'
          state_data = ::Search::Elastic::ReindexingTask::HUMAN_STATES[normalized_status]

          @elasticsearch_reindexing_human_state = state_data[:message]
          @elasticsearch_reindexing_human_state_color = state_data[:color]
        end

        def elasticsearch_warn_if_not_using_aliases
          @elasticsearch_warn_if_not_using_aliases = es_helper.alias_missing? && es_helper.index_exists?
        rescue StandardError => e
          log_exception(e)
        end

        def elasticsearch_warn_if_obsolete_migrations
          @elasticsearch_warn_if_obsolete_migrations = elasticsearch_pending_obsolete_migrations.any?
        end

        def elasticsearch_pending_obsolete_migrations
          @elasticsearch_pending_obsolete_migrations =
            Elastic::DataMigrationService.pending_migrations.select(&:obsolete?)
        end

        def search_error_if_version_incompatible
          @search_error_if_version_incompatible = !es_helper.supported_version?
        end

        def search_outdated_code_analyzer_detected
          @search_outdated_code_analyzer_detected = begin
            current_index_version = es_helper.get_meta&.dig('created_by')
            version_info = ::Gitlab::VersionInfo.parse(current_index_version)

            if version_info.valid?
              version_info < ::Gitlab::VersionInfo.new(15, 5)
            else
              true # a very outdated version of GitLab
            end
          end
        rescue StandardError => e
          log_exception(e)
        end

        def semantic_search_available
          @semantic_search_available = ::Ai::ActiveContext.semantic_search_available?
        end

        def semantic_search_settings
          return unless @semantic_search_available

          @active_context_connection = Ai::ActiveContext::Connection.active

          @semantic_search_embedding_models = {
            code: active_context_collection_embedding_models(Ai::ActiveContext::Collections::Code)
          }

          @user_can_update_semantic_search_model = @active_context_connection.present? &&
            ::Ai::ActiveContext.user_selects_embedding_model? &&
            Ability.allowed?(current_user, :manage_instance_model_selection)
        end

        def active_context_collection_embedding_models(collection_class)
          return unless @active_context_connection.present?

          collection_record = collection_class.collection_record
          return unless collection_record.present?

          {
            current_model: ::Ai::ActiveContext::Embedding.attach_model_name(
              collection_record.current_indexing_embedding_model
            ),
            next_model: ::Ai::ActiveContext::Embedding.attach_model_name(
              collection_record.next_indexing_embedding_model
            ),
            feature_setting_allowed: collection_class.feature_setting_allowed?
          }
        end

        def check_work_item_settings_availability
          render_404 unless work_item_settings_available_for_self_managed?
        end

        def scim_token
          scim_token = ScimOauthAccessToken.first

          @scim_token_url = scim_token.as_entity_json[:scim_api_url] if scim_token
          @saml_provider_enabled = ::Gitlab::Auth::Saml::Config.enabled?
        end

        def update_microsoft_application
          params = microsoft_application_params.dup
          params.delete(:client_secret) if params[:client_secret].blank?

          if @microsoft_application.update(params)
            flash[:notice] = s_('Microsoft|Microsoft Azure integration settings were successfully updated.')
          else
            flash[:alert] = safe_format(
              s_('Microsoft|Microsoft Azure integration settings failed to save. %{errors}'),
              errors: @microsoft_application.errors.full_messages.to_sentence
            )
          end

          redirect_to general_admin_application_settings_path
        end

        def indexing_status
          @initial_queue_size = ::Elastic::ProcessInitialBookkeepingService.queue_size
          @incremental_queue_size = ::Elastic::ProcessBookkeepingService.queue_size
          @dead_queue_size = ::Search::Elastic::DeadQueue.queue_size

          # This code cannot be run on GitLab.com due to performance issues
          return if ::Gitlab::Saas.feature_available?(:advanced_search)

          @projects_not_indexed_count = ::Search::ElasticProjectsNotIndexedFinder.execute.count
          @projects_not_indexed = ::Search::ElasticProjectsNotIndexedFinder
            .execute.limit(UNINDEXED_PROJECT_DISPLAY_LIMIT)
        end
      end

      EE_VALID_SETTING_PANELS = %w[search templates security_and_compliance namespace_storage work_item].freeze

      EE_VALID_SETTING_PANELS.each do |action|
        define_method(action) { perform_update if submitted? }
      end

      # rubocop:disable Metrics/CyclomaticComplexity
      # rubocop:disable Metrics/PerceivedComplexity
      def visible_application_setting_attributes
        attrs = super

        if License.feature_available?(:repository_mirrors)
          attrs += EE::ApplicationSettingsHelper.repository_mirror_attributes
        end

        # License feature => attribute name
        {
          admin_audit_log: :audit_events_api_limit,
          audit_events: [:project_audit_events_api_limit, :group_audit_events_api_limit],
          custom_project_templates: :custom_project_templates_group_id,
          email_additional_text: :email_additional_text,
          custom_file_templates: :file_template_project_id,
          default_project_deletion_protection: :default_project_deletion_protection,
          required_ci_templates: :required_instance_ci_template,
          disable_name_update_for_users: :updating_name_disabled_for_users,
          package_forwarding: [:npm_package_requests_forwarding,
            :lock_npm_package_requests_forwarding,
            :pypi_package_requests_forwarding,
            :lock_pypi_package_requests_forwarding,
            :maven_package_requests_forwarding,
            :lock_maven_package_requests_forwarding],
          default_branch_protection_restriction_in_groups: :group_owners_can_manage_default_branch_protection,
          group_ip_restriction: :globally_allowed_ips,
          security_orchestration_policies: [
            :scan_execution_policies_action_limit,
            :pipeline_execution_policies_per_configuration_limit,
            :scan_execution_policies_per_configuration_limit,
            :security_approval_policies_limit,
            :vulnerability_management_policies_per_configuration_limit,
            :dependency_firewall_policies_per_configuration_limit,
            :policy_store_experiment_enabled
          ],
          dependency_scanning: [
            :dependency_scanning_sbom_scan_api_upload_limit,
            :dependency_scanning_sbom_scan_api_download_limit
          ],
          disable_personal_access_tokens: :disable_personal_access_tokens,
          integrations_allow_list: :allowed_integrations_raw,
          packages_virtual_registry: :virtual_registries_endpoints_api_limit,
          disable_invite_members: :disable_invite_members
        }.each do |license_feature, attribute_names|
          attrs += Array.wrap(attribute_names) if License.feature_available?(license_feature)
        end

        attrs += [:service_access_tokens_expiration_enforced,
          :allow_top_level_group_owners_to_create_service_accounts]

        if License.feature_available?(:git_two_factor_enforcement) && ::Feature.enabled?(:two_factor_for_cli)
          attrs << :git_two_factor_session_expiry
        end

        # Remove the inline rubocop disablement of Metrics/PerceivedComplexity when we can move
        # secret_push_protection_available to the simple License feature => attribute name
        # hash above.
        if License.feature_available?(:secret_push_protection)
          attrs.push(:secret_push_protection_available, :secret_push_protection_mode)
        end

        if License.feature_available?(:admin_merge_request_approvers_rules)
          attrs += EE::ApplicationSettingsHelper.merge_request_appovers_rules_attributes
        end

        if ::License.feature_available?(:password_complexity)
          attrs += EE::ApplicationSettingsHelper.password_complexity_attributes
        end

        if License.feature_available?(:elastic_search)
          attrs += [
            elasticsearch_shards: {},
            elasticsearch_replicas: {}
          ]
        end

        if RegistrationFeatures::MaintenanceMode.feature_available?
          attrs << :maintenance_mode
          attrs << :maintenance_mode_message
        end

        attrs << :make_profile_private if License.feature_available?(:disable_private_profiles)

        attrs << :new_user_signups_cap
        attrs << :seat_control
        attrs << :namespace_storage_forks_cost_factor

        if License.feature_available?(:code_owner_approval_required)
          defaults = attrs.find do |item|
            item.is_a?(Hash) && item.key?(:default_branch_protection_defaults)
          end

          defaults[:default_branch_protection_defaults] << :code_owner_approval_required
        end

        if ::GitlabSubscriptions::AddOnPurchase.exists_for_unit_primitive?(:complete_code, :instance)
          attrs << :disabled_direct_code_suggestions
        end

        setting = ::ApplicationSetting.current

        if ::Gitlab::Duo::CodeReview.automatic_review_available?(setting)
          attrs += %i[auto_duo_code_review_enabled auto_duo_code_review_on_push_enabled]
        end

        attrs << :duo_code_review_decisions_enabled if ::Gitlab::Duo::CodeReview.decisions_settings_available?(setting)

        if ::Gitlab::Duo::CodeReview.depth_settings_available?(setting)
          attrs += %i[duo_code_review_depth_allowed duo_code_review_default_depth]
        end

        attrs << :duo_workflows_default_image_registry

        if setting.instance_built_in_project_templates_enabled_available?
          attrs << :built_in_project_templates_enabled
          attrs << :lock_built_in_project_templates_enabled
        end

        attrs << :duo_template_project_id if setting.duo_template_project_available?

        attrs << :dependency_firewall_enabled if setting.dependency_firewall_setting_available?

        attrs + saas_application_setting_attributes
      end
      # rubocop:enable Metrics/PerceivedComplexity
      # rubocop:enable Metrics/CyclomaticComplexity

      def seat_link_payload
        data = ::Gitlab::SeatLinkData.new

        respond_to do |format|
          format.html do
            seat_link_json = ::Gitlab::Json.pretty_generate(data.as_json)

            render html: ::Gitlab::Highlight.highlight('payload.json', seat_link_json, language: 'json')
          end
          format.json { render json: data.to_json }
        end
      end

      def set_hide_search_settings
        @hide_search_settings = true
      end

      private

      def saas_application_setting_attributes
        attrs = []
        attrs << { sms_cost_restricted_dial_codes: [] } if ::Gitlab::Saas.feature_available?(:identity_verification)
        attrs << :service_desk_paid_namespace_probation_days if ::ServiceDesk::PaidNamespaceProbation.configurable?
        attrs
      end

      override :duo_enabled_for_manifest?
      def duo_enabled_for_manifest?
        ::Ai::Catalog.user_can_access_experimental_and_beta_features?(current_user)
      end

      override :mcp_enabled_for_manifest?
      def mcp_enabled_for_manifest?
        duo_enabled_for_manifest? && ::Feature.enabled?(:slack_duo_mcp_server, current_user)
      end

      override :perform_update
      def perform_update
        super

        configure_slack_mcp_server if configure_slack_mcp_server?
      end

      def configure_slack_mcp_server?
        params.permit(application_setting: [:slack_app_id])[:application_setting].key?(:slack_app_id) &&
          @application_setting.errors.empty? &&
          @application_setting.slack_app_id.present? &&
          @application_setting.slack_app_secret.present? &&
          helpers.slack_mcp_server_configurable?
      end

      def configure_slack_mcp_server
        result = ::Ai::Catalog::McpServers::ConfigureSlackService.new(
          organization: admin_current_organization,
          current_user: current_user,
          client_id: @application_setting.slack_app_id
        ).execute
        return if result.success?

        flash[:alert] = safe_format(
          s_('SlackIntegration|Could not configure the Slack MCP server. %{errors}'),
          errors: result.message.to_sentence
        )
      end

      def verify_subscriptions_available!
        render_404 unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      end

      override :valid_setting_panels
      def valid_setting_panels
        super + EE_VALID_SETTING_PANELS
      end

      def push_frontend_license_features
        push_licensed_feature(:password_complexity)
        push_licensed_feature(:seat_control)
        push_licensed_feature(:disable_private_profiles)
      end

      def new_license
        @new_license ||= License.new(data: params.permit(:trial_key)[:trial_key])
      end

      # rubocop:disable CodeReuse/ActiveRecord -- splitting out legacy code
      def find_or_initialize_microsoft_application
        return unless microsoft_group_sync_enabled?

        @microsoft_application = ::SystemAccess::MicrosoftApplication.find_or_initialize_by(namespace: nil)
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def microsoft_application_params
        params.require(:system_access_microsoft_application)
              .permit(:enabled, :tenant_xid, :client_xid, :client_secret, :login_endpoint, :graph_endpoint)
      end

      def check_microsoft_group_sync_available
        render_404 unless microsoft_group_sync_enabled?
      end

      def microsoft_group_sync_enabled?
        ::Gitlab::Auth::Saml::Config.microsoft_group_sync_enabled?
      end

      def es_helper
        @es_helper ||= ::Search::Elastic::Helper.default
      end
    end
  end
end

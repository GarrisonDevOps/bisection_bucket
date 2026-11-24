# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module Runtimes
      # Runs one Duo session on the CI runtime. Owns everything that exists
      # because CI runs as a service account: the composite identity link,
      # minting the OAuth and workflow tokens, service-account membership,
      # source-branch defaulting, and the Start/Resume pick.
      #
      # A run adds the service account's membership only with provision_membership: true.
      # Interim until step 4 of https://gitlab.com/gitlab-org/gitlab/-/work_items/629005
      #
      # Flow config and report artifacts are facts about the session, so they are
      # read from the workflow. Callers supply only what belongs to this turn:
      #   - params_overrides: allowlisted keys (OVERRIDABLE_PARAMS) that may
      #     replace a base param, e.g. a resume's fresh goal.
      #   - context: the turn's context inputs (ExecuteRunService::CONTEXT_KEYS).
      #     Additive only: they cannot clobber base keys.
      class Ci
        include ::Gitlab::Utils::StrongMemoize

        OAUTH_TOKEN_ERROR = 'Could not obtain authentication token'
        WORKFLOW_TOKEN_ERROR = 'Could not obtain Duo Workflow token'
        CUSTOM_FLOW_CONFIG_SCHEMA_VERSION = 'v1'

        # Caller-supplied params that may override the base start params (e.g. a
        # resume's fresh goal or approval). Allowlisted so an override cannot
        # silently clobber tokens, branch, or other base keys.
        OVERRIDABLE_PARAMS = %i[goal human_approval human_message].freeze

        # source_branch defaults to the workflow's own (MR source branch, else the
        # project default); callers like code review that resolve a branch up front
        # pass it explicitly.
        def initialize(workflow, params_overrides: {}, context: {}, source_branch: nil, provision_membership: false)
          @workflow = workflow
          @params_overrides = params_overrides.slice(*OVERRIDABLE_PARAMS)
          @run_context = context.compact
          @source_branch = source_branch
          @provision_membership = provision_membership
        end

        def execute
          return invalid_ci_session('Only project-level workflow is supported') unless workflow.project
          return invalid_ci_session('Service account is required for CI execution') unless workflow.service_account

          provisioning_error = provision_service_account
          return provisioning_error if provisioning_error

          params = build_params
          return params if params.is_a?(ServiceResponse) && params.error?

          service_class.new(workflow: workflow, params: params).execute
        end

        private

        attr_reader :workflow, :params_overrides, :run_context, :provision_membership

        def provision_service_account
          link_composite_identity!
          return unless provision_membership

          result = ::Ai::ServiceAccountMemberAddService.new(workflow.project, workflow.service_account).execute
          return if result.success?

          ServiceResponse.error(message: result.message, reason: :service_account_error)
        end

        # Web-request-scoped link, distinct from the permission_check link
        # StartWorkflowService also performs. Only one should survive; tracked by
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/629005.
        def link_composite_identity!
          return unless workflow.service_account.composite_identity_enforced?
          return if ai_settings.duo_workflow_oauth_application.nil?

          ::Gitlab::Auth::Identity.link_from_web_request(
            service_account: workflow.service_account,
            scoped_user: workflow.user
          )
        end

        def ai_settings
          ::Ai::Setting.for_organization_read_only(workflow.project.organization)
        end

        def build_params
          oauth_token_result = mint_token(:invalid_oauth_token, OAUTH_TOKEN_ERROR) do
            context_service.generate_oauth_token_with_composite_identity_support(
              expires_in: ::Ai::DuoWorkflows::WorkloadCredential::EXPIRES_IN
            )
          end
          return oauth_token_result if oauth_token_result.error?

          flow_config = flow_config_params
          workflow_token_result = mint_token(:invalid_duo_workflow_token, WORKFLOW_TOKEN_ERROR) do
            context_service.generate_workflow_token(
              flow_config_id: flow_config[:flow_config_id],
              flow_version: flow_config[:flow_version],
              # Inline (custom) flows must stay without a schema claim: DWS rejects an inline config under one.
              flow_config_schema_version: (flow_config[:flow_config_schema_version] unless flow_config[:flow_config]),
              flow_config: flow_config[:flow_config],
              workflow_id: workflow.id
            )
          end
          return workflow_token_result if workflow_token_result.error?

          flow_config = inline_unless_dws_fetches(flow_config, workflow_token_result.payload[:capabilities])

          run_context
            .merge(base_params(oauth_token_result, workflow_token_result, flow_config))
            .merge(params_overrides)
        end

        def mint_token(reason, error_message)
          result = yield
          return result unless result.error?

          ::Gitlab::AppLogger.warn(
            Labkit::Fields::LOG_MESSAGE => 'Duo CI runtime could not mint a token',
            Labkit::Fields::ERROR_MESSAGE => result.message,
            workflow_id: workflow.id,
            token_error_reason: reason
          )
          ServiceResponse.error(message: error_message, reason: reason)
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
          ServiceResponse.error(message: error_message, reason: reason)
        end

        def base_params(oauth_token_result, workflow_token_result, flow_config)
          {
            goal: workflow.goal,
            workflow_id: workflow.id,
            workflow_oauth_token: oauth_token_result.payload[:oauth_access_token].plaintext_token,
            workflow_service_token: workflow_token_result.payload[:token],
            service_account: workflow.service_account,
            source_branch: source_branch,
            workflow_metadata: Gitlab::DuoWorkflow::Client.metadata(
              workflow.user, namespace: workflow.project.root_ancestor, project: workflow.project
            ).to_json,
            duo_agent_platform_feature_setting: context_service.duo_agent_platform_feature_setting,
            flow_definition: workflow.workflow_definition,
            report_artifacts: workflow.foundational_flow&.report_artifacts.presence,
            **flow_config
          }
        end

        def flow_config_params
          custom_flow_config_params || workflow.foundational_flow_params
        end

        # A custom catalog flow carries its config on the item version the
        # session was created with, so a resume runs the version it started on.
        def custom_flow_config_params
          version = workflow.ai_catalog_item_version
          return unless version&.item&.custom_flow?

          {
            flow_config: version.flow_config,
            flow_config_schema_version: CUSTOM_FLOW_CONFIG_SCHEMA_VERSION,
            fetch_flow_config: ::Ai::DuoWorkflows::Workflow.fetch_catalog_flow_config?(version, workflow.project)
          }
        end

        # The token response lists what DWS can do. When DWS cannot fetch the flow,
        # the job sends it inline, the same as with the feature flag off.
        def inline_unless_dws_fetches(flow_config, capabilities)
          return flow_config unless flow_config[:fetch_flow_config]

          feature_setting = context_service.duo_agent_platform_feature_setting
          return flow_config if ::Gitlab::DuoWorkflow::Client.fetches_flow_config?(feature_setting, capabilities)

          flow_config.merge(fetch_flow_config: false)
        end

        def context_service
          ::Ai::DuoWorkflows::WorkflowContextGenerationService.new(
            current_user: workflow.user,
            organization: workflow.project.organization,
            container: workflow.project,
            service_account: workflow.service_account,
            workflow_definition: workflow.workflow_definition,
            surface: ::Ai::ToolRules::GovernanceSurface.from_environment(
              workflow.environment, container: workflow.project, workflow_definition: workflow.workflow_definition
            ),
            additional_context: run_context[:additional_context],
            # Scheduled and system runs act as the service account alone, so they need the autonomous token.
            trigger_source: workflow.trigger_source,
            workflow_id: workflow.id
          )
        end
        strong_memoize_attr :context_service

        def service_class
          workflow.created? ? ::Ai::DuoWorkflows::StartWorkflowService : ::Ai::DuoWorkflows::ResumeWorkflowService
        end

        def source_branch
          @source_branch || default_source_branch
        end

        def default_source_branch
          workflow.merge_request&.source_branch || workflow.project.default_branch_or_main
        end

        def invalid_ci_session(message)
          ServiceResponse.error(message: message, reason: :invalid_ci_session)
        end
      end
    end
  end
end

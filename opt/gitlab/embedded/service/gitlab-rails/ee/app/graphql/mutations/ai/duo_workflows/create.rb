# frozen_string_literal: true

module Mutations
  module Ai
    module DuoWorkflows
      class Create < BaseMutation
        graphql_name 'AiDuoWorkflowCreate'

        include ::Mutations::Ai::DuoWorkflows::RequiresIdentityVerification

        # Auth is checked in allowed? depending on the container type
        # Further checks are performed by CreateWorkflowService based on the workflow definition

        def self.authorization_scopes
          super + [:ai_features]
        end

        argument :project_id, ::Types::GlobalIDType[::Project],
          required: false,
          description: "Global ID of the project the user is acting on."

        argument :namespace_id, ::Types::GlobalIDType[::Namespace],
          required: false,
          description: "Global ID of the namespace the user is acting on."

        argument :goal, GraphQL::Types::String,
          required: false,
          description: 'Goal of the workflow.'

        argument :agent_privileges, [GraphQL::Types::Int],
          required: false,
          description: 'Actions the agent is allowed to perform.'

        argument :pre_approved_agent_privileges, [GraphQL::Types::Int],
          required: false,
          description: 'Actions the agent can perform without asking for approval.'

        argument :workflow_definition, GraphQL::Types::String,
          required: false,
          description: 'Workflow type based on its capability.'

        argument :allow_agent_to_request_user, GraphQL::Types::Boolean,
          required: false,
          description: 'When enabled, Duo Agent Platform may stop to ask the user questions before proceeding.'

        argument :environment, Types::Ai::DuoWorkflows::WorkflowEnvironmentEnum,
          required: false,
          description: 'Environment for the workflow.'

        argument :ai_catalog_item_version_id, ::Types::GlobalIDType[::Ai::Catalog::ItemVersion],
          required: false,
          description: 'ID of the catalog item the workflow is triggered from.'

        argument :issue_id, GraphQL::Types::BigInt,
          required: false,
          description: 'IID of the noteable (Issue) that the workflow is associated with.'

        argument :merge_request_id, GraphQL::Types::BigInt,
          required: false,
          description: 'IID of the noteable (MergeRequest) that the workflow is associated with.'

        argument :web_search_enabled, GraphQL::Types::Boolean,
          required: false,
          description: 'Enable web search for the session.'

        argument :source, Types::Ai::DuoWorkflows::WorkflowSourceTypeEnum,
          required: false,
          description: 'Where the session was triggered from. Only client-surface values are accepted.'

        field :workflow, Types::Ai::DuoWorkflows::WorkflowType,
          null: true,
          description: 'Created workflow.'

        field :errors, [GraphQL::Types::String],
          null: false,
          description: 'Errors encountered during the creation process.'

        # The workflow record is created in the container it is given (`duo_workflows_workflows`
        # requires exactly one of `project_id`/`namespace_id`), so the concrete container boundary is
        # preferred when it resolves. Without either argument the container defaults to the user's
        # default Duo namespace, which the user boundary covers.
        authorize_granular_token permissions: :create_duo_workflow,
          boundaries: [
            { boundary_argument: :project_id, boundary_type: :project },
            { boundary_argument: :namespace_id, boundary_type: :group },
            { boundary: :user, boundary_type: :user }
          ]

        def resolve(**args)
          verify_rate_limit!

          container = container_for(args)

          item_version = GitlabSchema.find_by_gid(args[:ai_catalog_item_version_id])&.sync

          unless allowed?(container)
            raise_resource_not_available_error!(RESOURCE_ACCESS_ERROR, { code: 'NO_RESOURCE_PERMISSIONS' })
          end

          raise_if_identity_verification_required!(container)

          raise_resource_not_available_error! 'User is not authorized to use agent catalog item.' unless
            item_version.nil? || Ability.allowed?(current_user, :read_ai_catalog_item, item_version)

          authorization = authorize_flow_execution!(args[:workflow_definition], container)
          validate_source!(args[:source])

          workflow_params = build_workflow_params(args, item_version, authorization[:workflow_definition])
          privileges_error = apply_declared_privileges(workflow_params)
          return { errors: [privileges_error], workflow: nil } if privileges_error

          service = ::Ai::DuoWorkflows::CreateWorkflowService.new(
            container: container,
            current_user: current_user,
            params: workflow_params,
            execution: authorization[:execution],
            privileges_from_client: true
          )

          result = service.execute

          raise_resource_not_available_error!(result.message) if result.error? && result.http_status == :forbidden
          return { errors: [result[:message]], workflow: nil } if result[:status] == :error

          {
            workflow: result[:workflow],
            errors: errors_on_object(result[:workflow])
          }
        end

        private

        def container_for(args)
          if args[:project_id]
            GitlabSchema.find_by_gid(args[:project_id]).sync
          elsif args[:namespace_id]
            GitlabSchema.find_by_gid(args[:namespace_id]).sync
          else
            ::Ai::UserAuthorizer.for(current_user).default_duo_namespace
          end
        end

        def build_workflow_params(args, item_version, workflow_definition)
          {
            goal: args[:goal],
            agent_privileges: args[:agent_privileges],
            pre_approved_agent_privileges: args[:pre_approved_agent_privileges],
            workflow_definition: workflow_definition,
            allow_agent_to_request_user: args[:allow_agent_to_request_user],
            environment: args[:environment],
            ai_catalog_item_version_id: item_version&.id,
            issue_id: args[:issue_id],
            merge_request_id: args[:merge_request_id],
            web_search_enabled: Feature.enabled?(:dap_web_search, current_user) && args[:web_search_enabled],
            source_type: args[:source]
          }.compact
        end

        def verify_rate_limit!
          # GraphQL over ActionCable has no request in the context, so use the connection's.
          request = context[:request] || context[:channel]&.connection&.request

          return unless ::Ai::UsersPerIpLimit.new(user: current_user, request: request).throttled?

          raise_resource_not_available_error! ::Gitlab::ApplicationRateLimiter.throttled_error_message
        end

        def apply_declared_privileges(workflow_params)
          flow = ::Ai::DuoWorkflows::DeclaredPrivileges.foundational_flow(workflow_params[:workflow_definition])
          return unless flow

          if workflow_params[:environment] == 'external'
            return 'Foundational flows do not support the external environment'
          end

          ::Ai::DuoWorkflows::DeclaredPrivileges.apply!(workflow_params, flow)
          nil
        end

        # Server-derived sources (slack, mcp, flow_trigger) must never be claimed by a client.
        def validate_source!(source)
          return if source.nil? || ::Ai::DuoWorkflows::Workflow::CLIENT_SOURCE_TYPES.key?(source.to_sym)

          raise ::Gitlab::Graphql::Errors::ArgumentError, "#{source} is not a client source type"
        end

        def allowed?(container)
          return Ability.allowed?(current_user, :read_project, container) if container.is_a?(Project)

          Ability.allowed?(current_user, :read_group, container)
        end

        # A service account is not part of this mutation's contract, so none is resolved.
        def authorize_flow_execution!(workflow_definition, container)
          result = ::Ai::DuoWorkflows::FlowExecutionAuthorizer.for_background_caller(
            current_user: current_user,
            container: container,
            workflow_definition: workflow_definition,
            resolve_service_account: false
          ).execute

          raise_resource_not_available_error!(RESOURCE_ACCESS_ERROR, { code: 'NO_RESOURCE_PERMISSIONS' }) if
            result.error?

          { **result.payload, workflow_definition: result.payload[:workflow_definition] || workflow_definition }
        end
      end
    end
  end
end

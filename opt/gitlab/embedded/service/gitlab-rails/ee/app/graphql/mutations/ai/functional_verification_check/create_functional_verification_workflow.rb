# frozen_string_literal: true

module Mutations
  module Ai
    module FunctionalVerificationCheck
      class CreateFunctionalVerificationWorkflow < BaseMutation
        graphql_name 'CreateFunctionalVerificationWorkflow'

        # The check itself is instance-wide (an admin health check); the namespace
        # argument only supplies the container the chat session runs in, so the
        # boundary is the instance rather than the passed namespace.
        authorize_granular_token permissions: :create_functional_verification_workflow, boundary: :instance,
          boundary_type: :instance

        GOALS = {
          agentic_chat: 'How do I create a project in GitLab?'
        }.freeze

        WORKFLOW_DEFINITIONS = {
          agentic_chat: 'chat'
        }.freeze

        argument :check_type, Types::Ai::FunctionalVerificationCheck::CheckTypeEnum,
          required: true,
          description: 'Type of functional verification check to run.'

        argument :full_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the namespace to run the verification check against.'

        field :workflow_id, ::Types::GlobalIDType[::Ai::DuoWorkflows::Workflow],
          null: true,
          description: 'Global ID of the workflow created for the run.'

        def ready?(**args)
          raise_resource_not_available_error! unless args[:check_type] == :agentic_chat

          unless ::Ai::DuoAgentPlatformVerificationCheck.agentic_chat_verification_check_enabled?(current_user)
            raise_resource_not_available_error!
          end

          super
        end

        def resolve(check_type:, full_path:)
          namespace = authorized_namespace!(full_path)

          result = ::Ai::DuoWorkflows::CreateWorkflowService.new(
            container: namespace,
            current_user: current_user,
            params: {
              goal: GOALS.fetch(check_type),
              workflow_definition: WORKFLOW_DEFINITIONS.fetch(check_type),
              trigger_source: :verification
            }
          ).execute

          raise_resource_not_available_error!(result.message) if result.error?

          workflow = result[:workflow]
          ::Ai::DuoAgentPlatform::FunctionalVerificationRunService.new(check_type: check_type)
            .mark_running(workflow_id: workflow.id)

          { workflow_id: workflow.to_global_id, errors: [] }
        end

        private

        def authorized_namespace!(full_path)
          namespace = ::Namespace.find_by_full_path(full_path)

          raise_resource_not_available_error! unless namespace
          raise_resource_not_available_error! unless ::Ability.allowed?(current_user, :read_namespace, namespace)

          unless duo_enabled?(namespace)
            raise_resource_not_available_error!(s_('DuoAgentPlatform|Duo not enabled for namespace'))
          end

          namespace
        end

        def duo_enabled?(namespace)
          namespace.namespace_settings&.duo_features_enabled
        end
      end
    end
  end
end

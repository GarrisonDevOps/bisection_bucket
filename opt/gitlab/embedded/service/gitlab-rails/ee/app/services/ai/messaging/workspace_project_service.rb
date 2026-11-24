# frozen_string_literal: true

module Ai
  module Messaging
    class WorkspaceProjectService
      PROJECT_PATH = 'duo-workspace'
      PROJECT_NAME = 'Duo Workspace'
      PROJECT_DESCRIPTION = 'Duo Agent workspace — customizable agent environment for messaging-triggered flows.'

      def initialize(namespace:, current_user:)
        @namespace = namespace
        @current_user = current_user
      end

      def execute
        return ServiceResponse.error(message: 'Namespace is required.') unless namespace
        return ServiceResponse.error(message: 'User is required.') unless current_user

        unless Ability.allowed?(current_user, :read_namespace_via_membership, namespace)
          return ServiceResponse.error(message: 'You do not have access to this namespace.')
        end

        unless Ability.allowed?(current_user, :duo_workflow, namespace)
          return ServiceResponse.error(message: 'Duo Agent Platform is not available for this namespace.')
        end

        existing = find_existing_project
        return ServiceResponse.success(payload: { project: existing }) if existing

        create_workspace_project
      rescue ActiveRecord::RecordNotUnique
        # Another concurrent request created the project -- retry the lookup
        project = find_existing_project
        if project
          ServiceResponse.success(payload: { project: project })
        else
          ServiceResponse.error(message: 'Failed to create workspace project due to a conflict. Please try again.')
        end
      end

      private

      attr_reader :namespace, :current_user

      def find_existing_project
        namespace.projects.find_by_path(PROJECT_PATH)
      end

      def create_workspace_project
        unless Ability.allowed?(current_user, :create_projects, namespace)
          return ServiceResponse.error(
            message: 'You do not have permission to create projects in this namespace.'
          )
        end

        project = ::Projects::CreateService.new(current_user, create_params).execute

        unless project.persisted?
          return ServiceResponse.error(
            message: "Failed to create workspace project: #{project.errors.full_messages.join(', ')}"
          )
        end

        ServiceResponse.success(payload: { project: project })
      end

      def create_params
        {
          name: PROJECT_NAME,
          path: PROJECT_PATH,
          namespace_id: namespace.id,
          organization_id: namespace.organization_id,
          visibility_level: Gitlab::VisibilityLevel::PRIVATE,
          description: PROJECT_DESCRIPTION,
          initialize_with_readme: true,
          readme_template: readme_content,
          container_registry_enabled: false,
          packages_enabled: false,
          wiki_enabled: false,
          snippets_enabled: false,
          builds_enabled: true
        }
      end

      def readme_content
        docs = Rails.application.routes.url_helpers

        <<~MARKDOWN
          # Duo Workspace

          This project is the default execution environment for Duo Agent flows in this namespace.
          It is used when a flow is not triggered from a specific project.

          ## Customization

          You can customize how the agent behaves:

          - **[AGENTS.md](#{docs.help_page_url('user/duo_agent_platform/customize/agents_md.md')})** —
            Add an `AGENTS.md` file to document project conventions and guide the agent's behavior.
          - **[agent-config.yml](#{docs.help_page_url('user/duo_agent_platform/flows/execution/_index.md')})** —
            Configure the Docker image, tooling, and scripts used during flow execution.

          ## Learn more

          - [Duo Agent Platform documentation](#{docs.help_page_url('user/duo_agent_platform/_index.md')})
        MARKDOWN
      end
    end
  end
end

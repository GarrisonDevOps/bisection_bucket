# frozen_string_literal: true

module Resolvers
  module Ai
    module Chat
      class ContextPresetsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        type ::Types::Ai::Chat::ContextPresetsType, null: true

        argument :question_count,
          GraphQL::Types::Int,
          required: false,
          description: 'Number of questions for the default screen.'

        argument :url,
          GraphQL::Types::String,
          required: false,
          description: 'URL of the page the user is currently on.'

        argument :resource_id,
          ::Types::GlobalIDType[::Ai::Model],
          required: false,
          description: "Global ID of the resource from the current page."

        argument :project_id, ::Types::GlobalIDType[::Project],
          required: false,
          description: "Global ID of the project the user is acting on."

        argument :namespace_id, ::Types::GlobalIDType[::Namespace],
          required: false,
          description: "Global ID of the namespace the user is acting on."

        argument :foundational_agent_reference,
          GraphQL::Types::String,
          required: false,
          description: 'Reference of the selected foundational chat agent.'

        def resolve(
          url: nil, resource_id: nil, project_id: nil, namespace_id: nil, question_count: 4,
          foundational_agent_reference: nil)
          ai_resource = find_ai_resource(resource_id, project_id)
          default_questions = ::Gitlab::Duo::Chat::DefaultQuestions.new(
            current_user,
            url: url,
            resource: ai_resource,
            foundational_agent: find_selectable_agent(foundational_agent_reference, project_id, namespace_id)
          )

          {
            questions: default_questions.execute.sample(question_count),
            question_categories: default_questions.categories,
            ai_resource_data: ai_resource&.serialize_for_ai&.to_json
          }
        end

        private

        # Only honour a reference the user could have selected, so the presets endpoint
        # cannot surface an agent that the agent picker withholds.
        def find_selectable_agent(reference, project_id, namespace_id)
          return if reference.blank?

          selectable_agents = ::Ai::FoundationalChatAgentsFinder
            .new(current_user, project_id: project_id, namespace_id: namespace_id)
            .execute

          selectable_agents.find { |agent| agent.reference == reference }
        end

        def find_ai_resource(resource_id, project_id)
          resource = find_resource(resource_id, project_id)
          return unless resource

          ::Ai::AiResource::Wrapper.new(current_user, resource).wrap
        rescue ArgumentError
          nil
        end

        def find_resource(resource_id, project_id)
          return unless resource_id
          return find_commit_in_project(resource_id, project_id) if resource_id.model_class == Commit

          authorized_find!(id: resource_id)
        end

        def find_commit_in_project(resource_id, project_id)
          project = authorized_find!(id: project_id)
          return unless project

          project.commit_by(oid: resource_id.model_id)
        end

        def authorized_resource?(object)
          return unless object

          Ability.allowed?(current_user, "read_#{object.to_ability_name}", object)
        end
      end
    end
  end
end

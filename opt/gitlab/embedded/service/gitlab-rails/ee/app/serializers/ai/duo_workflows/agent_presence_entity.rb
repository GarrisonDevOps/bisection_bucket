# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # REST counterpart of Types::Ai::DuoWorkflows::AgentPresenceType. Served to anyone who can read
    # the parent object; user_permissions.read_duo_workflow says whether the viewer may open the session.
    class AgentPresenceEntity < Grape::Entity
      include RequestAwareEntity
      include ::Gitlab::Utils::StrongMemoize

      expose :session_id
      expose :agent_name
      expose :agent_catalog_web_path

      # Uppercased to match the DuoWorkflowSourceType GraphQL enum.
      expose :source_type do |presence|
        presence.source_type&.upcase
      end

      expose :source_link do |presence|
        presence.source_link if can_read_session?
      end

      # Uppercased to match the DuoWorkflowTriggerSource GraphQL enum.
      expose :trigger_source do |presence|
        presence.trigger_source.upcase
      end

      expose :user, using: AgentPresenceUserEntity

      expose :user_permissions do
        expose :read_duo_workflow do |_presence|
          can_read_session?
        end
      end

      private

      def can_read_session?
        can?(request.current_user, :read_duo_workflow, object.workflow)
      end
      strong_memoize_attr :can_read_session?
    end
  end
end

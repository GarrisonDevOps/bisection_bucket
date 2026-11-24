# frozen_string_literal: true

module Ai
  module ExternalAgents
    # Agent identities registered in a project, or in the projects of a group and its subgroups,
    # most recently synced first. Callers authorize `read_agent_artifacts` on the parent.
    class AgentIdentitiesFinder
      STATUS_SCOPES = {
        active: :recently_active,
        inactive: :not_recently_active,
        revoked: :revoked
      }.freeze

      def initialize(parent, params = {})
        @parent = parent
        @params = params
      end

      def execute
        identities = parent_identities
        identities = identities.with_agent_types(params[:agent_types]) if params[:agent_types].present?
        identities = identities.for_user(params[:user_id]) if params[:user_id]
        identities = identities.public_send(STATUS_SCOPES.fetch(params[:status])) if params[:status] # rubocop:disable GitlabSecurity/PublicSend -- limited to STATUS_SCOPES
        identities.order_by_last_synced_desc
      end

      private

      attr_reader :parent, :params

      def parent_identities
        if parent.is_a?(::Project)
          AgentIdentity.for_project(parent)
        else
          AgentIdentity.in_namespace_hierarchy(parent)
        end
      end
    end
  end
end

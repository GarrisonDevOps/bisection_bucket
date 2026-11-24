# frozen_string_literal: true

module RemoteDevelopment
  class WorkspacesFinder
    # NOTE: We implement .execute as a class method instead of an instance method, in order to be consistent with the
    #       functional patterns found elsewhere in the Remote Development domain code. For more context, see:
    #       https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/lib/remote_development/README.md?plain=0#functional-patterns
    #
    # @param [User] current_user
    # @param [Array] ids
    # @param [Array] user_ids
    # @param [Array] project_ids
    # @param [Array] agent_ids
    # @param [Array] actual_states
    # @return [ActiveRecord::Relation]
    def self.execute(current_user:, ids: [], user_ids: [], project_ids: [], agent_ids: [], actual_states: [])
      # NOTE: This check is included in the :read_workspace ability, but we do it here to short
      #       circuit for performance if the user can't access the feature, because otherwise
      #       there is an N+1 call for each workspace via `authorize :read_workspace` in
      #       the graphql resolver.
      return Workspace.none unless Ability.allowed?(current_user, :access_workspaces_feature)

      filter_arguments = {
        ids: ids,
        user_ids: user_ids,
        project_ids: project_ids,
        agent_ids: agent_ids,
        actual_states: actual_states
      }

      filter_argument_types = {
        ids: Integer,
        user_ids: Integer,
        project_ids: Integer,
        agent_ids: Integer,
        actual_states: String
      }.freeze

      FilterArgumentValidator.validate_filter_argument_types!(filter_argument_types, filter_arguments)
      FilterArgumentValidator.validate_at_least_one_filter_argument_provided!(**filter_arguments)
      validate_actual_state_values!(actual_states)

      collection_proxy = Workspace.all
      collection_proxy = collection_proxy.id_in(ids) if ids.present?
      collection_proxy = collection_proxy.by_user_ids(user_ids) if user_ids.present?
      collection_proxy = collection_proxy.by_project_ids(project_ids) if project_ids.present?
      collection_proxy = collection_proxy.by_agent_ids(agent_ids) if agent_ids.present?
      collection_proxy = collection_proxy.by_actual_states(actual_states) if actual_states.present?

      collection_proxy.order_id_desc
    end

    # @param [Array] actual_states
    # @return [void]
    def self.validate_actual_state_values!(actual_states)
      invalid_actual_state = actual_states.find do |actual_state|
        WorkspaceOperations::States::VALID_ACTUAL_STATES.exclude?(actual_state)
      end

      raise ArgumentError, "Invalid actual state value provided: '#{invalid_actual_state}'" if invalid_actual_state
    end
  end
end

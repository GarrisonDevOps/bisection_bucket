# frozen_string_literal: true

module Ai
  class EnabledFoundationalFlowsAuditor
    def initialize(current_user:, group:, previous_flow_refs:, new_flow_refs:)
      @current_user = current_user
      @group = group
      @previous_flow_refs = previous_flow_refs
      @new_flow_refs = new_flow_refs
    end

    def execute
      return if normalized_previous == normalized_new

      ::Gitlab::Audit::Auditor.audit(
        name: 'enabled_foundational_flows_updated',
        author: current_user,
        scope: group,
        target: group,
        message: message
      )
    end

    private

    attr_reader :current_user, :group, :previous_flow_refs, :new_flow_refs

    def normalized_previous
      @normalized_previous ||= Array(previous_flow_refs).sort
    end

    def normalized_new
      @normalized_new ||= Array(new_flow_refs).sort
    end

    def message
      from = normalized_previous.empty? ? 'none' : normalized_previous.join(', ')
      to = normalized_new.empty? ? 'none' : normalized_new.join(', ')

      "Changed enabled foundational flows from #{from} to #{to}"
    end
  end
end

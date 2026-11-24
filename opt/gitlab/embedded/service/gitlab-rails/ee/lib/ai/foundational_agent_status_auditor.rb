# frozen_string_literal: true

module Ai
  class FoundationalAgentStatusAuditor
    def initialize(current_user:, scope:, previous_statuses:, new_statuses:, default_enabled: nil)
      @current_user = current_user
      @scope = scope
      @default_enabled = default_enabled
      @previous_statuses = normalize(previous_statuses)
      @new_statuses = normalize(new_statuses)
    end

    def execute
      changed_entries.each do |reference, (from, to)|
        ::Gitlab::Audit::Auditor.audit(
          name: 'foundational_agent_status_updated',
          author: current_user,
          scope: scope,
          target: scope,
          message: "Changed foundational agent '#{reference}' status from #{from.inspect} to #{to.inspect}",
          additional_details: { reference: reference, from: from, to: to }
        )
      end
    end

    private

    attr_reader :current_user, :scope, :default_enabled, :previous_statuses, :new_statuses

    # Returns a hash of reference => enabled for records that changed
    def changed_entries
      all_references = (previous_statuses.keys | new_statuses.keys)

      all_references.each_with_object({}) do |reference, changes|
        from = previous_statuses[reference]
        to   = new_statuses[reference]

        changes[reference] = [from, to] if from != to
      end
    end

    # Converts an array of status hashes [{ reference:, enabled:, ... }]
    # into a flat hash of reference => enabled.
    # nil means "no explicit record"(/use the default) -> resolved to
    # the effective default so no-op saves don't emit extra events
    # and nil does not appear in messages.
    def normalize(statuses)
      Array(statuses).each_with_object({}) do |status, hash|
        ref     = status[:reference] || status['reference']
        enabled = status.key?(:enabled) ? status[:enabled] : status['enabled']
        hash[ref] = enabled.nil? ? resolve_default : enabled
      end
    end

    def resolve_default
      return default_enabled unless default_enabled.nil?

      scope.respond_to?(:foundational_agents_default_enabled) ? scope.foundational_agents_default_enabled : nil
    end
  end
end

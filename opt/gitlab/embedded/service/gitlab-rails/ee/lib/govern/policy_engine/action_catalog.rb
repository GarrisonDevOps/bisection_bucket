# frozen_string_literal: true

module Govern
  module PolicyEngine
    # Which executor handles an authored action, and whether it needs enforce
    # mode. Which actions a trigger accepts is the policy store's save-time
    # check (GOVERN-016), so a decision's actions are legal for its trigger
    # by construction and dispatch makes no second ruling.
    #
    # An observing action runs in every mode, because an audit-mode policy
    # exists to produce its trail. Only the state-changing actions carry
    # enforce_only; the first of those, set_setting, arrives with its
    # executor in https://gitlab.com/gitlab-org/gitlab/-/work_items/630155.
    #
    # block has an entry without an executor. SettingsChangeGate consumes its
    # decisions at the save point, so it dispatches nowhere, but the engine
    # knows it: a block decision is not an unhandled action.
    class ActionCatalog
      ENTRIES = {
        ::Gitlab::PolicyStore::Actions::LOG_AUDIT_TRAIL => {
          enforce_only: false,
          executor: 'Govern::PolicyEngine::LogAuditTrailExecutor'
        },
        ::Gitlab::PolicyStore::Actions::BLOCK => {
          enforce_only: true,
          executor: nil
        }
      }.freeze

      def self.known?(action_type)
        ENTRIES.key?(action_type)
      end

      def self.writes?(action_type)
        ::Gitlab::PolicyStore::Actions::WRITE_ACTIONS.include?(action_type)
      end

      # @return [String, nil] the executor class name, or nil when this action
      #   does not run in this mode.
      def self.executor_for(action_type, enforce:)
        entry = ENTRIES[action_type]
        return unless entry
        return if entry[:enforce_only] && !enforce

        entry[:executor]
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module TriggerableHooks # rubocop:disable Gitlab/BoundedContexts -- needs refactoring
    extend ActiveSupport::Concern

    class_methods do
      private

      def available_triggers
        super.merge({
          vulnerability_hooks: :vulnerability_events,
          member_approval_hooks: :member_approval_events
        })
      end
    end
  end
end # rubocop:enable Gitlab/BoundedContexts

# frozen_string_literal: true

module EE
  module SystemHook # rubocop:disable Gitlab/BoundedContexts -- need to extend SystemHook model, which needs to be refactored to a bounding context first
    extend ActiveSupport::Concern

    EE_AVAILABLE_HOOKS = [
      :member_approval_hooks
    ].freeze

    class_methods do
      extend ::Gitlab::Utils::Override

      override :available_hooks
      def available_hooks
        super + EE_AVAILABLE_HOOKS
      end
    end

    prepended do
      triggerable_hooks available_hooks

      attribute :member_approval_events, default: false
    end
  end
end # rubocop:enable Gitlab/BoundedContexts

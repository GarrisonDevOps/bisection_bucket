# frozen_string_literal: true

module EE
  module ProjectHook
    extend ActiveSupport::Concern

    EE_AVAILABLE_HOOKS = [
      :vulnerability_hooks
    ].freeze

    prepended do
      include CustomModelNaming

      self.singular_route_key = :hook

      triggerable_hooks available_hooks
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      override :available_hooks
      def available_hooks
        super + EE_AVAILABLE_HOOKS
      end
    end
  end
end

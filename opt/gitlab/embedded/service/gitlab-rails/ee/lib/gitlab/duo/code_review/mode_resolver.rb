# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      class ModeResolver
        include ::Gitlab::Utils::StrongMemoize

        delegate :mode, :enabled?, to: :active_mode

        # Modes with higher precedence comes first.
        MODES = [
          Modes::Dap,     # Duo Code Review will use Duo Agent Platform with extended context support.
          Modes::Classic, # Duo Code Review will use its non-agentic prompt mode.
          Modes::Disabled # Duo Code Review is disabled.
        ].freeze

        def initialize(user:, container:)
          @user = user
          @container = container
        end

        private

        attr_reader :user, :container

        def active_mode
          MODES.find do |resolver|
            mode = resolver.new(user: user, container: container)
            break mode if mode.active?
          end
        end
        strong_memoize_attr :active_mode
      end
    end
  end
end

# frozen_string_literal: true

module EE
  # rubocop: disable Gitlab/BoundedContexts -- overriding existing file
  module ResolvableNote
    extend ActiveSupport::Concern

    EE_RESOLVABLE_TYPES = %w[Epic].freeze

    class_methods do
      extend ::Gitlab::Utils::Override

      override :resolvable_types
      def resolvable_types
        super + EE_RESOLVABLE_TYPES
      end
    end
  end
  # rubocop: enable Gitlab/BoundedContexts
end

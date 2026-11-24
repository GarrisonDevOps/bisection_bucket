# frozen_string_literal: true

module EE
  module Types
    # rubocop:disable Gitlab/BoundedContexts -- Not a bounded context.
    module UserInterface
      extend ActiveSupport::Concern

      prepended do
        field :duo_status,
          ::Types::Users::DuoStatusType,
          null: true,
          resolver: ::Resolvers::Users::DuoStatusResolver.single,
          extras: [:parent],
          description: 'Duo status for the user.'
      end
    end
    # rubocop:enable Gitlab/BoundedContexts
  end
end

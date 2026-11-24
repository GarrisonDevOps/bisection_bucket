# frozen_string_literal: true

module EE
  module Types
    module WebHooks
      module ProjectHookType
        extend ActiveSupport::Concern

        prepended do
          field :vulnerability_events, GraphQL::Types::Boolean,
            null: false,
            description: 'Whether the webhook is triggered on vulnerability events.'
        end
      end
    end
  end
end

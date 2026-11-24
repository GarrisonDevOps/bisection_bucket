# frozen_string_literal: true

module EE
  module Types
    module Namespace # rubocop:disable Gitlab/BoundedContexts -- Existing module
      module PackageSettingsType
        extend ActiveSupport::Concern

        prepended do
          field :audit_events_enabled, GraphQL::Types::Boolean,
            null: false,
            description: 'Indicates whether audit events are created when publishing ' \
              'or deleting a package in the namespace (Premium and Ultimate only).'
        end
      end
    end
  end
end

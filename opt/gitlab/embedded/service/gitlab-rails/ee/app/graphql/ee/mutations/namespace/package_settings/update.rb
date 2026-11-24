# frozen_string_literal: true

module EE
  module Mutations
    module Namespace # rubocop:disable Gitlab/BoundedContexts -- Existing module
      module PackageSettings
        module Update
          extend ActiveSupport::Concern

          prepended do
            argument :audit_events_enabled,
              ::GraphQL::Types::Boolean,
              required: false,
              description: copy_field_description(::Types::Namespace::PackageSettingsType, :audit_events_enabled)
          end
        end
      end
    end
  end
end

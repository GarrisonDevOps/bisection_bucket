# frozen_string_literal: true

module Gitlab
  module Scim
    # SCIM resource types (RFC 7643 Section 6), per API context.
    # Group-level SCIM only exposes /Users; instance-level SCIM also exposes /Groups.
    module ResourceTypes
      SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:ResourceType'

      DEFINITIONS = {
        'User' => {
          name: 'User',
          endpoint: '/Users',
          description: 'User Account',
          schema: SchemaDefinitions::User::SCHEMA_ID
        },
        'Group' => {
          name: 'Group',
          endpoint: '/Groups',
          description: 'Group',
          schema: SchemaDefinitions::Group::SCHEMA_ID
        }
      }.freeze

      CONTEXTS = {
        group: %w[User],
        instance: %w[User Group]
      }.freeze

      class << self
        def all(context:)
          CONTEXTS.fetch(context).map { |id| build(id) }
        end

        def find(id, context:)
          build(id) if CONTEXTS.fetch(context).include?(id)
        end

        private

        def build(id)
          DEFINITIONS.fetch(id).merge(schemas: [SCHEMA], id: id)
        end
      end
    end
  end
end

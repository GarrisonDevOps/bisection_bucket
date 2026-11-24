# frozen_string_literal: true

module Gitlab
  module Scim
    # Registry of the SCIM schemas GitLab supports, per API context.
    # Group-level SCIM only manages users; instance-level SCIM also manages groups.
    module SchemaDefinitions
      CONTEXTS = {
        group: [SchemaDefinitions::User],
        instance: [SchemaDefinitions::User, SchemaDefinitions::Group]
      }.freeze

      class << self
        def all(context:)
          definitions_for(context).map { |definition| definition.to_h(context: context) }
        end

        def find(schema_id, context:)
          definitions_for(context).find { |definition| definition.schema_id == schema_id }&.to_h(context: context)
        end

        private

        def definitions_for(context)
          CONTEXTS.fetch(context)
        end
      end
    end
  end
end

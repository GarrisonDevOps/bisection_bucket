# frozen_string_literal: true

module ArtifactRegistry
  # Exposes an Artifact Registry element's own identifier. Every element type needs one and
  # none can use `BaseObject#id`, so the field and its resolver method live here rather than
  # once per type. The caller passes the noun and the milestone it ships in, both of which reach
  # the public schema:
  #
  #   exposes_element_id noun: 'image', milestone: '19.4'
  module ExposesElementId
    extend ActiveSupport::Concern

    class_methods do
      def exposes_element_id(noun:, milestone:)
        # Artifact Registry's own identifier, not a GitLab global ID.
        #
        # rubocop: disable GraphQL/FieldMethod -- `method:` leaves the resolver method named
        # after the field, so the read would still go through BaseObject#id and encode a global
        # ID this value object cannot produce
        field :id, GraphQL::Types::ID,
          null: false,
          resolver_method: :artifact_registry_id,
          experiment: { milestone: milestone },
          description: "ID of the #{noun} in Artifact Registry."
        # rubocop: enable GraphQL/FieldMethod
      end
    end

    def artifact_registry_id
      object.id
    end
  end
end

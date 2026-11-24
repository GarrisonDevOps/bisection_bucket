# frozen_string_literal: true

module Types
  module Security
    class AttributeType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization is done in resolver layer based on viewing context
      graphql_name 'SecurityAttribute'
      description 'A security attribute'

      # Exposes `count` on attribute connections so clients can show a total
      # (for example "+ N more") while loading only the first few nodes.
      connection_type_class Types::CountableConnectionType

      field :color, Types::ColorType,
        null: false,
        description: 'Color of the security attribute.'
      field :description, GraphQL::Types::String,
        null: true,
        description: 'Description of the security attribute.'
      field :editable_state, Types::Security::EditableStateEnum,
        null: false,
        description: 'Editable state of the security attribute.'
      field :id, Types::GlobalIDType[::Security::Attribute],
        null: false,
        description: 'Global ID of the security attribute.',
        resolver_method: :resolve_id
      field :name, GraphQL::Types::String,
        null: false,
        description: 'Name of the security attribute.'
      field :security_category, Types::Security::CategoryType,
        null: false,
        description: 'Security category the attribute belongs to.'

      def resolve_id
        if object.persisted?
          object.to_global_id
        else
          ::Gitlab::GlobalId.build(object, id: object.template_type)
        end
      end
    end
  end
end

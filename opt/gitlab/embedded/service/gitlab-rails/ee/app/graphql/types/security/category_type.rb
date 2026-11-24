# frozen_string_literal: true

module Types
  module Security
    class CategoryType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization is done in resolver layer based on viewing context
      graphql_name 'SecurityCategory'
      description 'A security category'

      field :description, GraphQL::Types::String,
        null: true,
        description: 'Description of the security category.'
      field :editable_state, Types::Security::EditableStateEnum,
        null: false,
        description: 'Editable state of the security category.'
      field :id, Types::GlobalIDType[::Security::Category],
        null: false,
        description: 'Global ID of the security category.',
        resolver_method: :resolve_id
      field :multiple_selection, GraphQL::Types::Boolean,
        null: false,
        description: 'Whether multiple attributes can be selected.'
      field :name, GraphQL::Types::String,
        null: false,
        description: 'Name of the security category.'
      field :security_attributes, [Types::Security::AttributeType],
        null: true,
        description: 'Security attributes belonging to the category.'
      field :template_type, Types::Security::CategoryTemplateTypeEnum,
        null: true,
        description: 'Template type for predefined categories.'

      def resolve_id
        if object.persisted?
          object.to_global_id
        else
          ::Gitlab::GlobalId.build(object, id: object.template_type)
        end
      end

      def security_attributes
        object.persisted? ? object.not_deleted_security_attributes : object.security_attributes
      end
    end
  end
end

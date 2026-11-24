# frozen_string_literal: true

module Types
  module WorkItems
    module SavedViews
      class FilterWarningType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Parent is already authorized
        graphql_name 'WorkItemSavedViewFilterWarningType'

        # read_work_item_saved_view is not a project or group policy ability, which the
        # granular validator requires here, so the type relies on the work item read permission.
        authorize_granular_token parent_authorizes: :read_work_item

        field :field,
          GraphQL::Types::String,
          null: false,
          description: 'Name of the field associated with the warning.'

        field :message,
          GraphQL::Types::String,
          null: false,
          description: 'Message associated with the warning.'
      end
    end
  end
end

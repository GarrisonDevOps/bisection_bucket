# frozen_string_literal: true

module EE
  module Mutations
    module Issues
      module Update
        extend ActiveSupport::Concern

        prepended do
          include ::Mutations::Issues::CommonEEMutationArguments

          argument :epic_id, ::Types::GlobalIDType[::Epic], # rubocop:disable Graphql/ForbiddenLoadsArgument -- pre-existing code; removing `loads:` would be a breaking change
            required: false,
            loads: ::Types::EpicType,
            description: 'ID of the parent epic. NULL when removing the association.',
            deprecated: { reason: 'This will be replaced by WorkItem hierarchyWidget', milestone: '17.5' }
        end

        def resolve(**args)
          super
        rescue ::Gitlab::Access::AccessDeniedError
          raise_resource_not_available_error!
        end
      end
    end
  end
end

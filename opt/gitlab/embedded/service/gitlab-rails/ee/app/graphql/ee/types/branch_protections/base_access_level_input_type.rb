# frozen_string_literal: true

module EE
  module Types
    module BranchProtections
      module BaseAccessLevelInputType
        extend ActiveSupport::Concern

        prepended do
          argument :user_id, ::Types::GlobalIDType[::User],
            prepare: ->(global_id, _ctx) { global_id.model_id.to_i },
            required: false,
            description: 'User associated with the access level.'

          argument :group_id, ::Types::GlobalIDType[::Group],
            prepare: ->(global_id, _ctx) { global_id.model_id.to_i },
            required: false,
            description: 'Group associated with the access level.'

          argument :member_role_id, ::Types::GlobalIDType[::MemberRole],
            prepare: ->(global_id, _ctx) { global_id.model_id.to_i },
            required: false,
            description: 'Custom member role associated with the access level.'
        end
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module API
    module Entities
      module ProtectedRefAccess
        extend ActiveSupport::Concern

        prepended do
          expose :user_id, documentation: { type: 'Integer', format: 'int64', example: 1,
                                            desc: 'ID of the user with access. Premium and Ultimate only.' }
          expose :group_id, documentation: { type: 'Integer', format: 'int64', example: 1,
                                             desc: 'ID of the group with access. Premium and Ultimate only.' }

          with_options if: ->(access, _opts) {
            access.respond_to?(:member_role) && access.custom_roles_licensed?
          } do
            expose :member_role_id,
              documentation: { type: 'Integer', format: 'int64', example: 42,
                               desc: 'ID of the custom member role with access. Ultimate only.' }

            expose :member_role_name,
              documentation: { type: 'String', example: 'Lead Developer' } do |access|
                access.member_role&.name
              end
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module API
    module Entities
      module ProtectedBranch
        extend ActiveSupport::Concern

        prepended do
          expose :unprotect_access_levels, using: ::API::Entities::ProtectedRefAccess,
            documentation: { type: '::API::Entities::ProtectedRefAccess', is_array: true,
                             desc: 'Array of unprotect access level configurations.' }
          expose :code_owner_approval_required,
            documentation: { type: 'Boolean',
                             desc: 'If `true`, code owner approval is required for pushes to the branch.' }
          expose :inherited, documentation: {
            type: 'Boolean',
            desc: 'If `true`, the protection settings are inherited from a group. Premium and Ultimate only.'
          }
        end
      end
    end
  end
end

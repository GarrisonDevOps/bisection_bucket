# frozen_string_literal: true

module EE
  module Types
    module BranchRules
      module BranchProtectionInputType
        extend ActiveSupport::Concern

        prepended do
          argument :code_owner_approval_required,
            type: GraphQL::Types::Boolean,
            required: false,
            default_value: true,
            replace_null_with_default: true,
            description: 'Enforce code owner approvals before allowing a merge.'
        end
      end
    end
  end
end

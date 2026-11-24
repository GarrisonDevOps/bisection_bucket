# frozen_string_literal: true

module EE
  module API
    module Entities
      module SharedGroupWithGroup
        extend ActiveSupport::Concern

        prepended do
          include GroupLinksHelper

          expose :member_role_id, documentation: { type: 'Integer', example: 12 }, if: ->(group_link, _) do
            group_link.shared_group.custom_roles_enabled?
          end
        end
      end
    end
  end
end

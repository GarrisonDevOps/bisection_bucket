# frozen_string_literal: true

module EE
  module API
    module Entities
      module ProjectGroupLink
        extend ActiveSupport::Concern

        prepended do
          include ProjectLinksHelper

          expose :member_role_id, documentation: { type: 'Integer', example: 12 }, if: ->(link, _) do
            custom_role_for_project_link_enabled?(link.project)
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module API
    module Entities
      module MergeRequestBasic
        extend ActiveSupport::Concern

        prepended do
          expose :approvals_before_merge,
            documentation: {
              type: 'Integer', example: 2,
              desc: 'Number of approvals required before the merge request can merge. Deprecated. To configure ' \
                'approval rules, use the merge request approvals API instead. Premium and Ultimate only.'
            }
        end
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module Mutations
    module MergeRequests
      module Update
        extend ActiveSupport::Concern

        prepended do
          argument :override_requested_changes, GraphQL::Types::Boolean,
            required: false,
            description: 'Override all requested changes. Can only be set by users who have permission' \
                         'to merge this merge request.'
        end
      end
    end
  end
end

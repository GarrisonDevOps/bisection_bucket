# frozen_string_literal: true

module EE
  module Resolvers
    module MergeRequestsResolver # rubocop:disable Gitlab/BoundedContexts -- EE extension of CE MergeRequestsResolver
      extend ActiveSupport::Concern

      class_methods do
        def project_associations
          super.push(:invited_groups)
        end
      end
    end
  end
end

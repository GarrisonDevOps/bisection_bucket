# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        # Built from Issues::RelatedBranchesService: branches whose name starts with the work item IID and a
        # hyphen, excluding branches of merge requests that reference the work item.
        class RelatedBranch < Grape::Entity
          expose :name,
            documentation: {
              type: 'String', example: '1-my-feature-branch',
              desc: 'Name of the branch. Starts with the work item IID followed by a hyphen.'
            }
          expose :compare_path,
            documentation: {
              type: 'String', example: '/group/project/-/compare/master...1-fix',
              desc: "Path to compare the branch with the project's default branch."
            }
          # rubocop:disable API/EntityFieldType -- DetailedStatusEntity is a serializer reused across the API (see Entities::Ci::Pipeline)
          expose :pipeline_status, using: ::DetailedStatusEntity,
            documentation: {
              type: 'object',
              desc: 'Status of the latest pipeline for the branch. Null if the branch has no pipeline or ' \
                'the current user cannot view it.'
            }
          # rubocop:enable API/EntityFieldType
        end
      end
    end
  end
end

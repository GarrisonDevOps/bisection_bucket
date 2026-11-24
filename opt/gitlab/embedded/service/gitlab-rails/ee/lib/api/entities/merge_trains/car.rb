# frozen_string_literal: true

module API
  module Entities
    module MergeTrains
      class Car < Grape::Entity
        expose :id, documentation: { type: 'Integer', format: 'int64', example: 38, desc: 'ID of the merge train.' }
        expose :merge_request, using: ::API::Entities::MergeRequestSimple,
          documentation: { type: '::API::Entities::MergeRequestSimple', desc: 'Merge request details.' }
        expose :user, using: ::API::Entities::UserBasic,
          documentation: {
            type: '::API::Entities::UserBasic', desc: 'User who added the merge request to the merge train.'
          }
        expose :pipeline, using: ::API::Entities::Ci::PipelineBasic,
          documentation: {
            type: '::API::Entities::Ci::PipelineBasic',
            desc: 'Pipeline details, or `null` if no pipeline is associated.'
          }
        expose :created_at, documentation: {
          type: 'DateTime', example: '2015-12-24T15:51:21.880Z', desc: 'Timestamp when the merge train was created.'
        }
        expose :updated_at, documentation: {
          type: 'DateTime', example: '2015-12-24T17:54:31.198Z',
          desc: 'Timestamp when the merge train was last updated.'
        }
        expose :target_branch, documentation: { type: 'String', example: 'develop', desc: 'Name of the target branch.' }
        expose :status_name, as: :status,
          documentation: {
            type: 'String',
            values: ::MergeTrains::Car.state_machine.states.map(&:name),
            example: 'merging',
            desc: 'Status of the merge request on the merge train. `idle`, `fresh`, and `stale` are active ' \
              'statuses. `merging`, `merged`, and `skip_merged` are complete statuses.'
          }
        expose :merged_at, documentation: {
          type: 'DateTime', example: '2015-12-24T17:54:31.198Z',
          desc: 'Timestamp when the merge request was merged, or `null` if not merged.'
        }
        expose :duration,
          documentation: {
            type: 'Integer',
            desc: 'Time spent on the merge train in seconds, or `null` if the merge request is not merged.',
            example: 127
          }
      end
    end
  end
end

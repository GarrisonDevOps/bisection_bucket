# frozen_string_literal: true

module API
  module Entities
    module Projects
      module ContainerRegistry
        module Protection
          class TagRule < Grape::Entity
            expose :id, documentation: {
              type: 'Integer', format: 'int64', example: 1, desc: 'ID of the protection tag rule.'
            }
            expose :project_id, documentation: {
              type: 'Integer', format: 'int64', example: 123, desc: 'ID of the project the rule belongs to.'
            }
            expose :tag_name_pattern, documentation: {
              type: 'String', example: 'v*-release',
              desc: 'Pattern that matches container tag names. For example, `v*-release` or `latest`.'
            }
            expose :minimum_access_level_for_push, documentation: {
              type: 'String', example: 'maintainer',
              desc: 'Minimum access level required to push container tags that match the pattern. ' \
                'One of `maintainer`, `owner`, or `admin`.'
            }
            expose :minimum_access_level_for_delete, documentation: {
              type: 'String', example: 'maintainer',
              desc: 'Minimum access level required to delete container tags that match the pattern. ' \
                'One of `maintainer`, `owner`, or `admin`.'
            }
          end
        end
      end
    end
  end
end

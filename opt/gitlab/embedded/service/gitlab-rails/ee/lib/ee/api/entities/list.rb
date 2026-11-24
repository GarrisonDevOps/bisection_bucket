# frozen_string_literal: true

module EE
  module API
    module Entities
      module List
        extend ActiveSupport::Concern

        prepended do
          expose :milestone, using: ::API::Entities::Milestone, if: ->(entity, _) { entity.milestone? }
          expose :iteration, using: ::API::Entities::Iteration, if: ->(entity, _) { entity.iteration? }
          expose :user, as: :assignee, using: ::API::Entities::UserSafe, if: ->(entity, _) { entity.assignee? }
          expose :status, using: ::API::Entities::WorkItems::Status, if: ->(entity, _) { entity.status? }
          expose :max_issue_count, documentation: { type: 'Integer', example: 0 },
            if: ->(list, _) { list.wip_limits_available? }
          expose :max_issue_weight, documentation: { type: 'Integer', example: 0 },
            if: ->(list, _) { list.wip_limits_available? }
          expose :limit_metric, documentation: { type: 'String', example: 'issue_count' },
            if: ->(list, _) { list.wip_limits_available? }
        end
      end
    end
  end
end

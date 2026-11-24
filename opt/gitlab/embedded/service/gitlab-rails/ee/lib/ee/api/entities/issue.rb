# frozen_string_literal: true

module EE
  module API
    module Entities
      module Issue
        extend ActiveSupport::Concern

        prepended do
          with_options if: ->(issue, _) { feature_available_for_issue_group?(issue, :epics) } do
            expose :epic_iid do |issue|
              authorized_epic_for(issue)&.iid
            end

            expose :epic, using: EpicBaseEntity do |issue|
              authorized_epic_for(issue)
            end

            def authorized_epic_for(issue)
              issue.epic if ::Ability.allowed?(options[:current_user], :read_epic, issue.epic)
            end
          end

          with_options if: ->(issue, _) { feature_available_for_issue_group?(issue, :iterations) } do
            expose :iteration, using: ::API::Entities::Iteration do |issue|
              issue.iteration if ::Ability.allowed?(options[:current_user], :read_iteration, issue.iteration)
            end
          end

          with_options if: ->(issue) { issue.licensed_feature_available?(:issuable_health_status) } do
            expose :health_status
          end

          def feature_available_for_issue_group?(issue, feature)
            namespace = issue.project&.namespace || issue.namespace
            return false unless namespace.group_namespace?

            namespace.licensed_feature_available?(feature)
          end
        end
      end
    end
  end
end

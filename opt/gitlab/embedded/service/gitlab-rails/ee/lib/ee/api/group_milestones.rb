# frozen_string_literal: true

module EE
  module API
    module GroupMilestones
      extend ActiveSupport::Concern

      prepended do
        include EE::API::MilestoneResponses # rubocop: disable Cop/InjectEnterpriseEditionModule

        params do
          requires :id, type: String, desc: 'ID or URL-encoded path of the group.'
        end
        resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          desc 'List all burndown chart events for a milestone' do
            detail 'Lists all burndown chart events for a specified milestone.'
            tags ['milestones']
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :read_milestone_burndown_event, boundary_type: :group
          get ':id/milestones/:milestone_id/burndown_events' do
            authorize! :read_group, user_group

            milestone_burndown_events_for(user_group)
          end
        end
      end
    end
  end
end

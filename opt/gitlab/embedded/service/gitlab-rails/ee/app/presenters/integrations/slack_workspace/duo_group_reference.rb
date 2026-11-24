# frozen_string_literal: true

module Integrations
  module SlackWorkspace
    # How a page names a group that runs or can run GitLab Duo for a Slack workspace: Owners get a link to the
    # group's GitLab for Slack page, everyone else to the list of its Owners. Nil when the viewer can't see it.
    module DuoGroupReference
      extend self

      def for(group, current_user)
        return unless group && current_user && Ability.allowed?(current_user, :read_group, group)

        if Ability.allowed?(current_user, :update_duo_in_slack, group)
          { id: group.id, name: group.full_name, link_kind: :settings,
            link_path: url_helpers.edit_group_settings_integration_path(group, :gitlab_slack_application) }
        else
          { id: group.id, name: group.full_name, link_kind: :owners,
            link_path: url_helpers.group_group_members_path(group, max_role: "static-#{::Gitlab::Access::OWNER}") }
        end
      end

      private

      def url_helpers
        ::Gitlab::Routing.url_helpers
      end
    end
  end
end

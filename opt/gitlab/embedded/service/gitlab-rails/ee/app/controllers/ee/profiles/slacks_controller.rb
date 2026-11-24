# frozen_string_literal: true

module EE
  module Profiles
    module SlacksController
      extend ::Gitlab::Utils::Override

      # The dropdown only searches the groups in the page. Users who own more install from the group's settings.
      MAX_INSTALLABLE_GROUPS = 100

      # Installing on a top-level group can also turn on GitLab Duo in Slack, so EE offers groups too.
      override :edit
      def edit
        super
        @groups = installable_groups if current_user
      end

      override :slack_link
      def slack_link
        group_id = params.permit(:group_id)[:group_id]
        return super if group_id.blank?

        link = add_to_slack_link(installable_group(group_id), ::Gitlab::CurrentSettings.slack_app_id)

        render json: { add_to_slack_link: link }
      end

      private

      # Like the group settings page, each candidate group decides whether Duo can run there.
      def installable_groups
        return [] unless ::Integrations::SlackWorkspace::Workspace.duo_group_feature_enabled_anywhere?

        groups = duo_group_candidates.order_name_asc.limit(MAX_INSTALLABLE_GROUPS)

        groups.with_route.with_namespace_settings.select do |group|
          slack_duo_group_feature_available?(group)
        end
      end

      # A group `installable_groups` could offer, without its limit, looked up by id so `slack_link` doesn't load
      # them all.
      def installable_group(id)
        group = duo_group_candidates.id_in(id).first
        raise ActiveRecord::RecordNotFound unless group && slack_duo_group_feature_available?(group)

        group
      end

      # GitLab Duo can't run in an archived group or one scheduled for deletion. A group that has the app, of its
      # own or inherited, is changed from its settings: an install here would replace that install without warning.
      def duo_group_candidates
        ::Integrations::GitlabSlackApplication.groups_without_install(
          current_user.owned_groups.top_level.self_and_ancestors_active
        )
      end
    end
  end
end

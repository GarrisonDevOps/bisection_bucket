# frozen_string_literal: true

module Integrations
  module SlackWorkspace
    # Who may make a top-level group the Duo group of a Slack workspace, and whether a claim still holds.
    class DuoGroupEligibility
      include ::Gitlab::Utils::StrongMemoize

      # GitLab.com has no instance-level integrations, like `IntegrationsHelper#instance_level_integrations?`,
      # which checks `Gitlab.com?` instead.
      def self.instance_installs?
        !::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      end

      # The `[team_id, group_id]` pairs, of `pairs` (`[team_id, top-level group]`), whose workspace is installed
      # in the group's hierarchy. One query for a page; each pair stops at its first install.
      def self.installed_in_hierarchies(pairs)
        members = pairs.uniq.flat_map do |team_id, group|
          installs = ::SlackIntegration.with_bot.by_team(team_id)
          pair = [::SlackIntegration.arel_table[:team_id], Arel.sql("#{group.id.to_i} AS namespace_id")]

          [installs.for_groups_in(group), installs.for_projects_in(group)].map { |scope| scope.select(pair).limit(1) }
        end
        return Set.new if members.empty?

        ::SlackIntegration.from_union(members, remove_duplicates: false).limit(members.size)
          .pluck(:team_id, :namespace_id).to_set
      end

      # Pages answer for many workspaces at once, so they pass what they already loaded:
      # `installed_in_hierarchy` and `instance_install` as booleans.
      def initialize(group, team_id, installed_in_hierarchy: nil, instance_install: nil)
        @group = group
        @team_id = team_id
        @preloaded_installed_in_hierarchy = installed_in_hierarchy
        @preloaded_instance_install = instance_install
      end

      # :admin for an instance install, :owner for an install in the group's hierarchy, otherwise nil.
      def decided_by
        return unless group.is_a?(::Group) && group.root? && team_id.present?
        return if inactive?
        return :admin if instance_install?

        :owner if installed_in_hierarchy?
      end
      strong_memoize_attr :decided_by

      def eligible?
        decided_by.present?
      end

      # Same rule as the `update_duo_in_slack` ability: such a group's claim is off.
      def inactive?
        group.self_or_ancestors_archived? || group.scheduled_for_deletion_in_hierarchy_chain?
      end

      def instance_install?
        return @preloaded_instance_install unless @preloaded_instance_install.nil?
        return false unless self.class.instance_installs?

        installs.instance_level_in(group.organization).exists?
      end
      strong_memoize_attr :instance_install?

      private

      attr_reader :group, :team_id

      # EXISTS stops at the first match; a workspace can have thousands of installs.
      def installed_in_hierarchy?
        return @preloaded_installed_in_hierarchy unless @preloaded_installed_in_hierarchy.nil?

        installs.for_groups_in(group).exists? || installs.for_projects_in(group).exists?
      end

      def installs
        ::SlackIntegration.with_bot.by_team(team_id)
      end
    end
  end
end

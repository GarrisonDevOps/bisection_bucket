# frozen_string_literal: true

module Integrations
  module SlackWorkspace
    # The top-level group a Slack workspace runs GitLab Duo in. No row means GitLab Duo is off for that workspace.
    # team_id is unique across organizations.
    class Workspace < ApplicationRecord
      self.table_name = 'slack_workspaces'

      attr_readonly :duo_namespace_id

      belongs_to :duo_namespace, class_name: 'Namespace', inverse_of: false, optional: false

      validates :team_id, presence: true, uniqueness: true, length: { maximum: 255 }
      validate :duo_namespace_is_top_level_group

      scope :with_duo_namespace, ->(namespace) { where(duo_namespace: namespace) }
      scope :for_teams, ->(team_ids) { where(team_id: team_ids).preload(:duo_namespace) }
      # What a page needs to name the Duo group and check `update_duo_in_slack` (archived) on it.
      scope :with_duo_namespace_details, -> { preload(duo_namespace: [:route, :namespace_settings]) }

      # Rolled out per top-level group, so it can be dogfooded on GitLab.com before it applies to every workspace.
      # A mention in a workspace without a claim has no group yet; it follows the instance.
      def self.duo_group_feature_enabled?(group)
        ::Feature.enabled?(:slack_duo_group, group&.root_ancestor || :instance)
      end

      # Lets a page skip loading groups to check one by one while the flag is off for everyone.
      def self.duo_group_feature_enabled_anywhere?
        # rubocop:disable Gitlab/AvoidFeatureGet -- no group yet; Flipper's cached state is the cheap way to skip that query
        ::Feature.enabled?(:slack_duo_group, :instance) || !::Feature.get(:slack_duo_group).off?
        # rubocop:enable Gitlab/AvoidFeatureGet
      end

      def self.for_team(team_id)
        find_by(team_id: team_id) if team_id.present?
      end

      private

      def duo_namespace_is_top_level_group
        return if duo_namespace.nil? || (duo_namespace.is_a?(::Group) && duo_namespace.root?)

        errors.add(:duo_namespace, s_('SlackIntegration|must be a top-level group'))
      end
    end
  end
end

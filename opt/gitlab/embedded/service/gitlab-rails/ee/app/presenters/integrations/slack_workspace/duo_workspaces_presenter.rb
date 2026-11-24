# frozen_string_literal: true

module Integrations
  module SlackWorkspace
    # One row per Slack workspace of a top-level group's hierarchy: where GitLab Duo runs for it, and whether
    # the viewer can change that here. A page loads what all its rows need at once, so its query count doesn't
    # grow with the rows. Read-only: an invalid claim shows as off and is deleted elsewhere (no writes on GET).
    class DuoWorkspacesPresenter
      include ::Gitlab::Utils::StrongMemoize

      PAGE_SIZE = 20

      # The install a GitLab for Slack page is connected to. An unsaved record is a copy of the instance
      # integration (`build_from_instance`), even below a group with its own install. Propagation can lag,
      # so this reads the install the page inherits.
      def self.installation_for(integration)
        return integration.slack_integration if integration.persisted?

        ::Integration.default_integration(integration.type, integration.parent)&.slack_integration
      end

      # `own_installation`: the install the page is connected to, whose workspace (`own_team_id`) comes first; it's
      # the only way an instance-installed workspace shows on a group page. `only_team_id`: just that row, for
      # subgroup and project pages and the row a change returns. `offset`: rows the page already has ("Show more").
      def initialize(
        group:, current_user:, own_installation: nil, own_team_id: own_installation&.team_id, only_team_id: nil,
        offset: 0)
        @group = group
        @current_user = current_user
        @own_installation = own_installation
        @own_team_id = own_team_id
        @only_team_id = only_team_id
        @offset = offset.to_i.clamp(0, ::SlackIntegration::TEAMS_LIMIT)
      end

      def own_row
        rows.find { |row| row[:team_id] == own_team_id } if own_team_id
      end

      def rows
        shown_team_ids.map { |team_id| row(team_id) }
      end
      strong_memoize_attr :rows

      def more_count
        [team_ids.size - offset - PAGE_SIZE, 0].max
      end

      # Whether GitLab Duo runs in the group for any of its workspaces, on this page or not.
      def runs_here?
        ::Integrations::SlackWorkspace::Workspace.with_duo_namespace(group).for_teams(team_ids).to_a
          .any? { |claim| eligibility(group, claim.team_id).eligible? }
      end

      # `top_level_installed`: the top-level group installed this workspace too, so its page can turn it on.
      def pointer_notice(top_level_installed: true)
        row = own_row

        case row[:state]
        when :instance_managed then instance_managed_notice(row)
        when :off
          key = top_level_installed ? :off_ask_owner : :off_install_on_top_level
          { key: key, **notice_reference(group_reference(group)) }
        when :on_here then { key: :on_here_read_only, **notice_reference(group_reference(group)) }
        else
          row[:duo_group] ? { key: :elsewhere, **notice_reference(row[:duo_group]) } : { key: :elsewhere_unnamed }
        end
      end

      private

      attr_reader :group, :current_user, :own_installation, :own_team_id, :only_team_id, :offset

      def shown_team_ids
        team_ids.drop(offset).first(PAGE_SIZE)
      end
      strong_memoize_attr :shown_team_ids

      # The page's own workspace first, then the workspaces installed below the group; copies of an instance
      # workspace aren't rows here.
      def team_ids
        return [only_team_id] if only_team_id

        own = own_team_id && (instance_team_ids + hierarchy_team_ids).include?(own_team_id) ? [own_team_id] : []
        own + by_name(hierarchy_team_ids - instance_team_ids - own)
      end
      strong_memoize_attr :team_ids

      # Pages must neither repeat nor skip a row, so the order is total: name, then team ID.
      def by_name(ids)
        ids.sort_by { |id| [hierarchy_names[id].to_s.downcase, id] }
      end

      # Names of the workspaces listed from the hierarchy, for the order and for the rows.
      def hierarchy_names
        installations.team_names(hierarchy_team_ids - instance_team_ids)
      end
      strong_memoize_attr :hierarchy_names

      def instance_team_ids
        return [] unless DuoGroupEligibility.instance_installs?

        installations.instance_level_in(group.organization).team_ids
      end
      strong_memoize_attr :instance_team_ids

      # Starts from the group, not from a team, so it can't use the team_id index (DB review).
      def hierarchy_team_ids
        (installations.for_groups_in(group).team_ids + installations.for_projects_in(group).team_ids).uniq.sort
      end
      strong_memoize_attr :hierarchy_team_ids

      def row(team_id)
        instance = instance_team_ids.include?(team_id)
        claim = valid_claims[team_id]
        state = row_state(instance, claim)

        {
          team_id: team_id,
          team_name: team_names[team_id],
          state: state,
          installed_in: instance ? [{ kind: :instance }] : [],
          duo_group: claim && group_reference(claim.duo_namespace),
          duo_on: claim.present?,
          can_manage: can_manage?(state, team_id),
          slack_permissions_ok: slack_permissions_ok?(team_id)
        }
      end

      # The page's own install answers for its row, which the page can reinstall; other rows sample one install.
      def slack_permissions_ok?(team_id)
        return own_mentions? if own_installation && team_id == own_installation.team_id

        team_ids_with_mentions.include?(team_id)
      end

      def own_mentions?
        own_installation.authorized_scope_names.include?(::SlackIntegration::SCOPE_APP_MENTIONS_READ)
      end
      strong_memoize_attr :own_mentions?

      def row_state(instance, claim)
        return :instance_managed if instance
        return :off unless claim
        return :on_here if claim.duo_namespace_id == group.id

        :elsewhere
      end

      def can_manage?(state, team_id)
        %i[on_here off].include?(state) && can_update_group? && eligibility(group, team_id).decided_by == :owner
      end

      def can_update_group?
        !!current_user && Ability.allowed?(current_user, :update_duo_in_slack, group)
      end
      strong_memoize_attr :can_update_group?

      # An instance install is only known here for the page's own organization; elsewhere the rule asks.
      def eligibility(claim_group, team_id)
        instance = instance_team_ids.include?(team_id) if claim_group.organization_id == group.organization_id

        DuoGroupEligibility.new(claim_group, team_id,
          installed_in_hierarchy: installed_in_hierarchy?(claim_group, team_id), instance_install: instance)
      end

      # The group page lists the workspaces installed in its hierarchy, so it knows its own answer.
      def installed_in_hierarchy?(claim_group, team_id)
        return hierarchy_team_ids.include?(team_id) if listed_from_hierarchy?(claim_group)

        installed_elsewhere.include?([team_id, claim_group.id])
      end

      def listed_from_hierarchy?(claim_group)
        claim_group.id == group.id && !only_team_id
      end

      # The pairs the list can't answer, loaded in one query: other groups' claims, and this group's on a
      # single-row page.
      def installed_elsewhere
        pairs = shown_claims.filter_map do |claim|
          [claim.team_id, claim.duo_namespace] unless listed_from_hierarchy?(claim.duo_namespace)
        end
        pairs += shown_team_ids.map { |team_id| [team_id, group] } if only_team_id

        DuoGroupEligibility.installed_in_hierarchies(pairs)
      end
      strong_memoize_attr :installed_elsewhere

      # The route names the group and the settings answer its archived check (`update_duo_in_slack`).
      def shown_claims
        claims = ::Integrations::SlackWorkspace::Workspace.for_teams(shown_team_ids).with_duo_namespace_details.to_a
        ::Preloaders::GroupPolicyPreloader.new(claims.map(&:duo_namespace).uniq, current_user).execute
        claims
      end
      strong_memoize_attr :shown_claims

      def valid_claims
        shown_claims.select { |claim| eligibility(claim.duo_namespace, claim.team_id).eligible? }.index_by(&:team_id)
      end
      strong_memoize_attr :valid_claims

      # One reference per group, however many rows name it.
      def group_reference(reference_group)
        @group_references ||= {}
        @group_references.fetch(reference_group.id) do
          @group_references[reference_group.id] = DuoGroupReference.for(reference_group, current_user)
        end
      end

      # The instance install carries the name Slack reported last; copies can lag behind it.
      def team_names
        ids = shown_team_ids
        instance_ids = ids & instance_team_ids
        names = only_team_id ? {} : hierarchy_names.slice(*ids)
        missing = ids - names.keys - instance_ids
        names.merge!(installations.team_names(missing)) if missing.any?
        return names if instance_ids.empty?

        names.merge(installations.instance_level_in(group.organization).team_names(instance_ids))
      end
      strong_memoize_attr :team_names

      def team_ids_with_mentions
        installations.sampled_team_ids_with_scope(shown_team_ids, ::SlackIntegration::SCOPE_APP_MENTIONS_READ).to_set
      end
      strong_memoize_attr :team_ids_with_mentions

      # `duo_group` is nil both when no group is chosen and when the viewer can't see the chosen one.
      def instance_managed_notice(row)
        reference = row[:duo_group]
        notice = { key: instance_managed_notice_key(reference, row[:duo_on]) }
        notice[:group_name] = reference[:name] if reference
        notice.merge!(link_kind: :admin, link_path: admin_integration_path) if current_user&.can_admin_all_resources?
        notice
      end

      def instance_managed_notice_key(reference, duo_on)
        return :instance_managed_on if reference
        return :instance_managed_on_unnamed if duo_on

        :instance_managed_off
      end

      def notice_reference(reference)
        return {} unless reference

        { group_name: reference[:name], link_kind: reference[:link_kind], link_path: reference[:link_path] }
      end

      def admin_integration_path
        url_helpers.edit_admin_application_settings_integration_path(:gitlab_slack_application)
      end

      def installations
        ::SlackIntegration.with_bot
      end

      def url_helpers
        ::Gitlab::Routing.url_helpers
      end
    end
  end
end

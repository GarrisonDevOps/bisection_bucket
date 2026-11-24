# frozen_string_literal: true

module Preloaders
  class UserMemberRolesInProjectsPreloader
    include Gitlab::Utils::StrongMemoize

    attr_reader :projects, :projects_relation, :user

    def initialize(projects:, user:)
      @projects = projects
      @user = user
    end

    def execute
      return {} if projects.blank? || user.blank?

      project_ids = projects.map { |project| project.respond_to?(:id) ? project.id : project }

      ::Gitlab::Instrumentation::Authz.measure do
        ::Gitlab::SafeRequestLoader.execute(
          resource_key: resource_key,
          resource_ids: project_ids,
          default_value: []
        ) do |project_ids|
          abilities_for_user_grouped_by_project(project_ids)
        end
      end
    end

    private

    def abilities_for_user_grouped_by_project(project_ids)
      return abilities_from_memberships(project_ids) if ::Authz::UserProjectGrants.enabled_for?(user.id)

      custom_role_projects = custom_role_projects(project_ids)

      return {} if custom_role_projects.empty?

      projects_with_traversal_ids = custom_role_projects.map do |project|
        [project.id, Arel.sql("ARRAY[#{project.namespace.traversal_ids_as_sql}]")]
      end

      value_list = Arel::Nodes::ValuesList.new(projects_with_traversal_ids)

      sql = <<~SQL
      SELECT project_ids.project_id, custom_permissions.permissions
        FROM (#{value_list.to_sql}) AS project_ids (project_id, namespace_ids),
        LATERAL (
          #{query}
        ) AS custom_permissions
      SQL

      grouped_by_project = ApplicationRecord.connection.select_all(sql).to_a.group_by do |h|
        h['project_id']
      end

      log_statistics(project_ids)

      grouped_by_project.transform_values do |values|
        project_permissions = values.map do |value|
          Gitlab::Json.safe_parse(value['permissions']).select { |_, v| v }
        end

        project_permissions.inject(:merge).keys.map(&:to_sym) & enabled_project_permissions
      end
    end

    def custom_role_projects(project_ids)
      @projects_relation = Project.select(:id, :namespace_id).id_in(project_ids)

      ::Namespaces::Preloaders::ProjectRootAncestorPreloader.new(projects_relation, :namespace).execute

      projects_relation.select { |project| custom_roles_enabled_on?(project) }
    end

    # Root namespaces come from the traversal IDs the grants already loaded, so only the roots are queried.
    def custom_role_project_ids(project_ids)
      root_ids = ::Authz::ProjectGrantSources.new.project_rows(with_loaded_projects(project_ids))
        .transform_values { |row| row[:traversal_ids].first }
      roots = ::Namespace.id_in(root_ids.values.uniq).index_by(&:id)

      root_ids.filter_map { |project_id, root_id| project_id if custom_roles_enabled_on[roots[root_id]] }
    end

    # Skips project shares to match the SQL path, which reads no custom roles from them.
    # Most users hold no custom role, so the grants answer that before any project or license is loaded.
    def abilities_from_memberships(project_ids)
      grants_by_project = ::Authz::UserProjectGrants.new(user.id).for_projects(with_loaded_projects(project_ids))
      member_role_ids = grants_by_project.filter_map do |project_id, grants|
        ids = grants.filter_map { |grant| grant.member_role_id unless grant.source == :project_share }
        [project_id, ids] if ids.any?
      end.to_h

      return {} if member_role_ids.empty?

      member_role_ids.slice!(*custom_role_project_ids(member_role_ids.keys))

      return {} if member_role_ids.empty?

      log_statistics(project_ids)

      permissions = MemberRole.id_in(member_role_ids.values.flatten.uniq).pluck(:id, :permissions).to_h # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by the user's custom roles

      member_role_ids.transform_values do |ids|
        enabled = ids.flat_map { |id| permissions.fetch(id, {}).select { |_, value| value }.keys }

        enabled.map(&:to_sym) & enabled_project_permissions
      end
    end

    # Passes records given to the preloader rather than their IDs, so a namespace they already loaded isn't queried.
    def with_loaded_projects(project_ids)
      project_ids.map { |id| loaded_projects.fetch(id, id) }
    end

    def loaded_projects
      projects.grep(::Project).index_by(&:id)
    end
    strong_memoize_attr :loaded_projects

    def query
      union_queries = []

      project_member = Member.select('member_roles.permissions')
        .with_user(user)
        .active_state
        .joins(:member_role)
        .where(source_type: 'Project')
        .where('members.source_id = project_ids.project_id')
        .to_sql

      union_queries.push(project_member)

      # This is similar to the query in UserMemberRolesInGroupsPreloader except
      # for the project_ids.namespace_ids. Ideally, we'll extract both to a
      # shared module so there is a SSOT for the query.
      group_permissions_query = ::Authz::UserGroupMemberRole.joins(:member_role)
        .where('user_group_member_roles.group_id IN (SELECT UNNEST(project_ids.namespace_ids) as ids)')
        .where(user: user)

      union_queries.push(
        group_permissions_query.select('member_roles.permissions').to_sql
      )

      union_queries.join(" UNION ALL ")
    end

    def custom_roles_enabled_on
      Hash.new do |hash, namespace|
        hash[namespace] = namespace&.should_process_custom_roles?
      end
    end
    strong_memoize_attr :custom_roles_enabled_on

    def custom_roles_enabled_on?(project)
      custom_roles_enabled_on[project&.root_ancestor]
    end

    def resource_key
      "member_roles_in_projects:user:#{user.id}"
    end

    def enabled_project_permissions
      MemberRole.all_customizable_project_permissions
    end
    strong_memoize_attr :enabled_project_permissions

    def log_statistics(project_ids)
      ::Gitlab::AppLogger.info(
        class: self.class.name,
        user_id: user.id,
        projects_count: project_ids.length
      )
    end
  end
end

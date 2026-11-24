# frozen_string_literal: true

module Preloaders
  class UserMemberRolesInGroupsPreloader
    include Gitlab::Utils::StrongMemoize

    attr_reader :groups, :group_relation, :groups_with_traversal_ids, :user

    def initialize(groups:, user:)
      @groups = groups
      @user = user
    end

    def execute
      return {} if groups.blank? || user.blank?

      group_ids = groups.map { |group| group.respond_to?(:id) ? group.id : group }

      ::Gitlab::SafeRequestLoader.execute(
        resource_key: resource_key,
        resource_ids: group_ids,
        default_value: []
      ) do |group_ids|
        abilities_for_user_grouped_by_group(group_ids)
      end
    end

    private

    def abilities_for_user_grouped_by_group(group_ids)
      build_groups_with_traversal_ids(group_ids)

      log_statistics(group_ids)

      get_results(query)
    end

    def build_groups_with_traversal_ids(group_ids)
      @group_relation = Group.id_in(group_ids)

      ::Namespaces::Preloaders::GroupRootAncestorPreloader.new(group_relation).execute

      @groups_with_traversal_ids = group_relation.filter_map do |group|
        next unless group.root_ancestor&.should_process_custom_roles?

        [group.id, Arel.sql("ARRAY[#{group.traversal_ids_as_sql}]")]
      end
    end

    def get_results(query)
      return {} if groups_with_traversal_ids.empty?

      value_list = Arel::Nodes::ValuesList.new(groups_with_traversal_ids)

      sql = <<~SQL
      SELECT namespace_ids.namespace_id, custom_permissions.permissions
        FROM (#{value_list.to_sql}) AS namespace_ids (namespace_id, namespace_ids),
        LATERAL (
          #{query}
        ) AS custom_permissions
      SQL

      grouped_by_group = ApplicationRecord.connection.select_all(sql).to_a.group_by do |h|
        h['namespace_id']
      end

      grouped_by_group.transform_values do |values|
        group_permissions = values.map do |value|
          Gitlab::Json.safe_parse(value['permissions']).select { |_, v| v }
        end

        group_permissions.inject(&:merge).keys.map(&:to_sym) & enabled_group_permissions
      end
    end

    def query
      query = ::Authz::UserGroupMemberRole.joins(:member_role)
          .where('user_group_member_roles.group_id IN (SELECT UNNEST(namespace_ids) as ids)')
          .where(user: user)

      query.select('member_roles.permissions').to_sql
    end

    def resource_key
      "member_roles_in_groups:user:#{user.id}"
    end

    def enabled_group_permissions
      MemberRole.all_customizable_group_permissions
    end
    strong_memoize_attr :enabled_group_permissions

    def log_statistics(group_ids)
      ::Gitlab::AppLogger.info(
        class: self.class.name,
        user_id: user.id,
        groups_count: group_ids.length,
        group_ids: group_ids.first(10)
      )
    end
  end
end

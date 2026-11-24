# frozen_string_literal: true

module GitlabSubscriptions
  class SeatsCalculator
    class << self
      def execute(hierarchy_root)
        click_house_execute(hierarchy_root)
          .first
          .transform_keys(&:to_sym)
          .transform_values { |user_ids| user_ids.map(&:to_i) }
      end

      private

      def click_house_execute(hierarchy_root)
        query = ::ClickHouse::Client::Query.new(
          raw_query: raw_query(hierarchy_root),
          placeholders: {
            traversal_path: hierarchy_root.traversal_path(with_organization: true),
            planner: ::Gitlab::Access::PLANNER,
            minimal_access: ::Gitlab::Access::MINIMAL_ACCESS,
            user_types: User.user_types.except(*HasUserType::BOT_USER_TYPES).values,
            user_state: User.state_machines[:state].states[:active].value,
            member_state: Member.state_machines[:state].states[:active].value,
            base_seat: GitlabSubscriptions::SeatAssignment.seat_types[:base],
            planner_seat: GitlabSubscriptions::SeatAssignment.seat_types[:plan],
            free_seat: GitlabSubscriptions::SeatAssignment.seat_types[:free]
          }
        )

        ::Gitlab::ApplicationContext.with_context(**context(hierarchy_root)) do
          ::ClickHouse::Client.select(query, :main)
        end
      end

      def context(hierarchy_root)
        key = hierarchy_root.is_a?(Organizations::Organization) ? :organization : :namespace

        { :feature_category => 'seat_cost_management', key => hierarchy_root }
      end

      def raw_query(hierarchy_root)
        <<~CH
          WITH members AS (
            SELECT
              traversal_path,
              id,
              toInt64(splitByChar('/', traversal_path)[2]) AS root_namespace_id,
              argMax(user_id, _siphon_replicated_at) AS user_id,
              argMax(access_level, _siphon_replicated_at) AS access_level,
              argMax(tuple(member_role_id), _siphon_replicated_at).1 AS member_role_id,
              argMax(state, _siphon_replicated_at) AS state,
              argMax(tuple(requested_at), _siphon_replicated_at).1 AS requested_at,
              argMax(tuple(invite_token), _siphon_replicated_at).1 AS invite_token,
              argMax(_siphon_deleted, _siphon_replicated_at) AS _siphon_deleted
            FROM siphon_members
            WHERE startsWith(traversal_path, {traversal_path:String})
            GROUP BY traversal_path, id
            HAVING _siphon_deleted = false
          ),
          namespace_bans AS (
            SELECT
              traversal_path,
              id,
              argMax(namespace_id, _siphon_replicated_at) AS root_namespace_id,
              argMax(user_id, _siphon_replicated_at) AS user_id,
              argMax(_siphon_deleted, _siphon_replicated_at) AS _siphon_deleted
            FROM
              siphon_namespace_bans
            WHERE startsWith(traversal_path, {traversal_path:String})
            GROUP BY traversal_path, id
            HAVING _siphon_deleted = false
          ),
          member_roles AS (
            SELECT
              traversal_path,
              id,
              argMax(occupies_seat, _siphon_replicated_at) AS occupies_seat,
              argMax(base_access_level, _siphon_replicated_at) AS base_access_level,
              argMax(_siphon_deleted, _siphon_replicated_at) AS _siphon_deleted
            FROM siphon_member_roles
            WHERE startsWith(traversal_path, {traversal_path:String})
            GROUP BY traversal_path, id
            HAVING _siphon_deleted = false
          ),
          user_highest_role AS (
            SELECT
              user_id,
              max(access_level) AS access_level
            FROM members
            WHERE state = {member_state:Int8}
            AND requested_at IS NULL
            AND invite_token IS NULL
            AND (user_id, root_namespace_id) NOT IN (SELECT user_id, root_namespace_id FROM namespace_bans)
            GROUP BY user_id
          ),
          users_with_custom_billable_seat AS (
            SELECT
              user_id
            FROM members
            WHERE state = {member_state:Int8}
            AND requested_at IS NULL
            AND invite_token IS NULL
            AND (user_id, root_namespace_id) NOT IN (SELECT user_id, root_namespace_id FROM namespace_bans)
            AND member_role_id IN (SELECT id FROM member_roles WHERE occupies_seat = true AND base_access_level > {minimal_access:Int64})
          ),
          users AS (
            SELECT
              id,
              argMax(state, _siphon_replicated_at) AS state,
              argMax(user_type, _siphon_replicated_at) AS user_type,
              argMax(_siphon_deleted, _siphon_replicated_at) AS _siphon_deleted
            FROM siphon_users
            WHERE id IN (SELECT user_id FROM user_highest_role)
            GROUP BY id
            HAVING _siphon_deleted = false
          ),
          user_seats AS (
            SELECT
              u.id AS user_id,
              #{seat_type_clause(hierarchy_root)}
            FROM user_highest_role AS hr
            JOIN users AS u ON hr.user_id = u.id
            WHERE u.state = {user_state:String}
            AND u.user_type IN ({user_types:Array(Int8)})
          )
          SELECT
            groupArrayIf(user_id, seat_type = {base_seat:Int8}) AS base_seat_user_ids,
            groupArrayIf(user_id, seat_type = {planner_seat:Int8}) AS planner_seat_user_ids,
            groupArrayIf(user_id, seat_type = {free_seat:Int8}) AS free_seat_user_ids
          FROM user_seats;
        CH
      end

      def seat_type_clause(hierarchy_root)
        if hierarchy_root.gitlab_subscription&.exclude_guests?
          <<~CH
              multiIf((hr.access_level > {planner:Int64} OR hr.user_id IN (SELECT user_id FROM users_with_custom_billable_seat)), {base_seat:Int8}, hr.access_level = {planner:Int64}, {planner_seat:Int8}, {free_seat:Int8}) AS seat_type
          CH
        else
          <<~CH
              if(hr.access_level > {minimal_access:Int64}, {base_seat:Int8}, {free_seat:Int8}) AS seat_type
          CH
        end
      end
    end
  end
end

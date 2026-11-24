# frozen_string_literal: true

module Authz
  module ProjectAuthorizations
    # Random (user, project) pairs for the verifier, from both sides: stored rows, which find stale grants,
    # and memberships, which find missing rows.
    class VerificationSample
      # Below this many pages a table is read whole with a random sort.
      SMALL_TABLE_PAGES = 1_000

      # @param size [Integer] about how many pairs to return from each side
      def initialize(size)
        @size = size
      end

      # @return [Array<Array(Integer, Integer)>] user ID and project ID pairs
      def pairs
        (table_pairs + membership_pairs).uniq
      end

      private

      attr_reader :size

      def table_pairs
        sampled(::ProjectAuthorization.all).pluck(:user_id, :project_id) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- sampled limits it
      end

      # A membership gives a project to check: the project itself, or one the group's membership reaches.
      def membership_pairs
        sampled(::Member.authorizable).pluck(:user_id, :source_type, :source_id) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- sampled limits it
          .filter_map do |user_id, source_type, source_id|
            project_id = source_type == ::GroupMember::SOURCE_TYPE ? project_reached_by(source_id) : source_id
            [user_id, project_id] if project_id
          end
      end

      # Picks a random root (the group or one it's invited into), a random group under it, then that group's
      # project or one shared with it, looked up in random order so shares get sampled too. Small queries
      # only: listing the whole reach would read about 200k IDs for a top-level group.
      def project_reached_by(group_id)
        roots = [group_id] + ::GroupGroupLink.where(shared_with_group_id: group_id).limit(20).pluck(:shared_group_id)

        roots.shuffle.each do |root_id|
          namespace_id = subtree_group_ids(root_id).sample
          lookups = [
            -> { ::Project.where(namespace_id: namespace_id).limit(1).pick(:id) },
            -> { ::ProjectGroupLink.where(group_id: namespace_id).limit(1).pick(:project_id) }
          ]
          project_id = lookups.shuffle.lazy.filter_map(&:call).first
          return project_id if project_id
        end

        nil
      end

      # Up to 1,000 groups of the root's subtree, read in order along the traversal_ids index, so the pick
      # favours the start of very large subtrees. The descendants scopes first remove nested roots from their
      # input, which took over two minutes for one large subtree on a production clone.
      def subtree_group_ids(root_id)
        ::Namespace.connection.select_values(::Namespace.sanitize_sql_array([<<~SQL.squish, root_id]))
          SELECT namespaces.id FROM namespaces INNER JOIN namespaces AS root ON root.id = ?
          WHERE namespaces.type = 'Group'
            AND namespaces.traversal_ids >= root.traversal_ids
            AND namespaces.traversal_ids < next_traversal_ids_sibling(root.traversal_ids)
          LIMIT 1000
        SQL
      end

      # Large tables: reads one eligible row from each of twice `size` random pages via a TID range scan, so
      # about one page per row at any table size. `attempt * 0` makes random() per row; OFFSET 0 stops the
      # planner inlining it into both TID bounds, which would pick a different page for each bound.
      def sampled(scope)
        model = scope.model
        table = model.quoted_table_name
        pages = page_count(model)

        sample = if pages < SMALL_TABLE_PAGES
                   scope.reorder(Arel.sql('random()')).limit(size).to_sql
                 else
                   row = scope.where("#{table}.ctid >= format('(%s,0)', picked.page)::tid")
                     .where("#{table}.ctid < format('(%s,0)', picked.page + 1)::tid").limit(1).to_sql

                   <<~SQL.squish
                     SELECT sampled.* FROM generate_series(1, #{Integer(size) * 2}) AS attempt
                     CROSS JOIN LATERAL (SELECT floor(random() * #{pages} + attempt * 0)::bigint AS page OFFSET 0) AS picked
                     CROSS JOIN LATERAL (#{row}) AS sampled
                     LIMIT #{Integer(size)}
                   SQL
                 end

        model.from("(#{sample}) AS #{table}")
      end

      # The table's size on disk, which, unlike the planner's estimates, is never missing.
      def page_count(model)
        model.connection.select_value(model.sanitize_sql_array([
          "SELECT pg_relation_size(?::regclass) / current_setting('block_size')::int", model.table_name
        ])).to_i
      end
    end
  end
end

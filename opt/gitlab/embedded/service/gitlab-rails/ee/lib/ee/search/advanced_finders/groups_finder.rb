# frozen_string_literal: true

# Elasticsearch filters, PostgreSQL sorts: the index stores name and path as analysed
# text and cannot sort on them. Sorting the re-hydrated relation is only sound for a
# complete match set, so a truncated or empty one falls back instead.
module EE
  module Search
    module AdvancedFinders
      module GroupsFinder
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override
        include ::Gitlab::Utils::StrongMemoize
        include ::Namespaces::GroupsFilter

        # An allowed filter that search_options does not map is silently ignored by
        # Elasticsearch, so only add one with its mapping and a parity spec.
        ALLOWED_ES_FILTERS = %i[
          active
          all_available
          exclude_group_ids
          filter_group_ids
          ids
          include_parent_descendants
          organization
          parent
          search
          top_level_only
          visibility
        ].freeze

        # Sorting happens in PostgreSQL, so `sort` never disqualifies Elasticsearch.
        CONTROL_KEYS = %i[sort allow_similarity_sort search_include_parents].freeze

        # GraphQL sends with_statistics on every request and defaults all_available to
        # true, so counting their no-op values as filters would keep every GraphQL
        # request on PostgreSQL. Not lumped in with archived or active, where false is a
        # real filter.
        NO_OP_WHEN_FALSY = %i[
          filter_expired_saml_session_groups
          include_parent_shared_groups
          owned
          top_level_only
          with_duo_agent_platform_enabled
          with_knowledge_graph_enabled
          with_statistics
        ].freeze
        NO_OP_WHEN_TRUTHY = %i[all_available].freeze

        # GroupsFinder reads these with a truthy-default `fetch`, so an explicit nil
        # narrows exactly like false and must not be skipped as a no-op.
        TRUTHY_BY_DEFAULT = %i[all_available include_ancestors].freeze

        # Callers paginate the returned relation, so the match set is fetched up front.
        RESULT_LIMIT = 1_000

        # Group.search reads the routes table's full name and path unless a parent narrows
        # it, so the field set has to follow the same switch or the backends diverge.
        SEARCH_FIELDS = %w[name^3 path^2].freeze
        ROUTE_SEARCH_FIELDS = %w[name^3 full_name^2 path^2 full_path].freeze
        BACKFILL_MIGRATION = :backfill_groups_to_elasticsearch
        ACTIVE_BACKFILL_MIGRATION = :backfill_active_on_groups

        attr_reader :current_user, :params

        override :use_elasticsearch_finder?
        def use_elasticsearch_finder?
          feature_enabled? &&
            advanced_search_available? &&
            searching? &&
            index_ready? &&
            allowed_filters? &&
            expressible_parent? &&
            expressible_minimal_access? &&
            expressible_active?
        end

        # nil means "fall back to PostgreSQL".
        def execute
          result = search
          return unless result

          ids, total_count = result

          return if total_count > RESULT_LIMIT

          # No hits can mean the group is not indexed yet rather than absent, so let
          # PostgreSQL answer instead of treating an empty match set as authoritative.
          return if ids.empty?

          sort(::Group.id_in(ids).with_route.with_namespace_details)
        end

        private

        def search
          query = ::Search::Elastic::GroupQueryBuilder.build(
            query: params[:search],
            options: search_options
          )

          ::Gitlab::Search::Client.execute_search(query: query, options: search_options) do |raw|
            mapper = ::Search::Elastic::ResponseMapper.new(raw, search_options)
            next if mapper.failed?

            [mapper.results.map { |hit| hit.dig(:_source, :id) }, mapper.total_count]
          end
        rescue ::Elasticsearch::Transport::Transport::Error, ::Faraday::Error => e
          ::Gitlab::ErrorTracking.track_exception(e, class: self.class.name)

          nil
        end

        def search_options
          {
            current_user: current_user,
            klass: ::Group,
            index_name: ::Search::Elastic::References::Group.index,
            # Narrows the index's default field set, which also matches description.
            fields: search_fields,
            page: 1,
            per_page: RESULT_LIMIT,
            # Only the id is read out of each hit, and RESULT_LIMIT hits is a large payload.
            source_fields: [:id],
            visibility_levels: visibility_levels,
            ids: included_ids,
            organization_id: organization_id,
            top_level_only: params[:top_level_only],
            active: params[:active],
            authorized_groups_only: authorized_groups_only?,
            # The index stores the group's own archived flag, so leave archived filtering
            # to the by_archived default and let `archived` force a PostgreSQL fallback.
            include_archived: true
          }.merge(search_level_options).compact
        end
        strong_memoize_attr :search_options

        def search_fields
          search_include_parents? ? ROUTE_SEARCH_FIELDS : SEARCH_FIELDS
        end

        # GroupsFinder passes `organization` to `in_organization`, which accepts a record or
        # an id, so an id has to map here too or the filter would be dropped by `compact`.
        def organization_id
          organization = params[:organization]

          organization.respond_to?(:id) ? organization.id : organization
        end

        # An explicit nil narrows like false, because GroupsFinder reads this with a
        # truthy-default fetch. Keys are normalised because an unseen filter would be
        # silently ignored by Elasticsearch rather than rejected.
        def authorized_groups_only?
          key = params.keys.find { |candidate| candidate.to_sym == :all_available }
          return false if key.nil?

          !params[key]
        end

        # Two separate id_in calls on the PostgreSQL side, so both must hold.
        def included_ids
          lists = [params[:ids], params[:filter_group_ids]].compact
          return if lists.empty?

          lists.map { |list| Array(list).map(&:to_i) }.reduce(:&)
        end

        # skip_groups is applied after the finder, so honouring it here would make
        # Elasticsearch narrower than PostgreSQL.
        def excluded_ids
          Array(params[:exclude_group_ids]).map(&:to_i)
        end

        # Elasticsearch cannot see minimal-access memberships, and the visibility filter
        # is built from the same set, so no narrowing clause could bring them back.
        # Declining is cheaper than widening the authorization boundary.
        def expressible_minimal_access?
          return true unless authorized_groups_only?
          return true if current_user.blank?
          # Without the licence PostgreSQL returns none either, so nothing diverges.
          return true unless ::License.feature_available?(:minimal_access_role)

          current_user.minimal_access_groups.empty? && minimal_access_shares.empty?
        end

        # Expiry is deliberately not filtered, because groups_from_shares does not filter
        # it either and expired links are only cleaned up daily.
        def minimal_access_shares
          ::GroupGroupLink.for_shared_with_groups(current_user.groups).minimal_access
        end

        # Documents written before the backfill carry no active field, so a term filter on it
        # would drop them. The flag is also checked here because GET /groups and the GraphQL
        # resolver send active behind an already-100% flag, so this is their only rollback lever.
        def expressible_active?
          params[:active].nil? ||
            (::Elastic::DataMigrationService.migration_has_finished?(ACTIVE_BACKFILL_MIGRATION) &&
              ::Feature.enabled?(:group_children_advanced_finder, current_user))
        end

        # A non-Group parent would otherwise widen silently to a global search.
        def expressible_parent?
          params[:parent].nil? || params[:parent].is_a?(::Group)
        end

        # root_ancestor_ids routes the query to one shard. search_level: :group matches the
        # whole subtree, which is only correct when include_parent_descendants is set.
        def search_level_options
          parent = params[:parent]
          return { search_level: :global, excluded_ids: excluded_ids.presence } unless parent

          options = {
            search_level: :group,
            group_ids: [parent.id],
            root_ancestor_ids: [parent.root_ancestor.id],
            excluded_ids: excluded_ids
          }

          if params[:include_parent_descendants]
            options.merge(excluded_ids: options[:excluded_ids] + [parent.id])
          else
            options.merge(parent_id: parent.id)
          end
        end

        override :can_sort_by_similarity?
        def can_sort_by_similarity?
          super && membership_bounded_scope?
        end

        # GroupsFinder gates similarity on this too, so the two paths would otherwise
        # order the same result set differently.
        def membership_bounded_scope?
          return false if public_or_internal_only?

          authorized_groups_only?
        end

        # An unfiltered listing matches everything, so on any real instance it exceeds
        # RESULT_LIMIT and execute throws the hits away. Decline up front rather than pay
        # a round trip in front of the PostgreSQL query that runs anyway.
        def searching?
          params[:search].present?
        end

        def allowed_filters?
          (constraining_params - ALLOWED_ES_FILTERS).empty?
        end

        # params may be ActionController::Parameters, which is not Enumerable, so read
        # each key rather than iterating pairs.
        def constraining_params
          params.keys.filter_map do |key|
            value = params[key]
            key = key.to_sym

            next if CONTROL_KEYS.include?(key)
            next if value.nil? && TRUTHY_BY_DEFAULT.exclude?(key)
            next if NO_OP_WHEN_TRUTHY.include?(key) && value
            next if NO_OP_WHEN_FALSY.include?(key) && !value

            key
          end
        end

        def feature_enabled?
          ::Feature.enabled?(:advanced_groups_finder_elasticsearch, current_user)
        end

        def advanced_search_available?
          ::Gitlab::CurrentSettings.elasticsearch_search? &&
            !::Gitlab::CurrentSettings.advanced_search_indexing_paused?
        end

        def index_ready?
          ::Elastic::DataMigrationService.migration_has_finished?(BACKFILL_MIGRATION)
        end
      end
    end
  end
end

# frozen_string_literal: true

module Search
  module Elastic
    module Filters
      include Search::Elastic::Filters::ConfidentialityFilters

      ALLOWED_SEARCH_LEVELS = %i[global group project].freeze
      DEFAULT_RELATED_SIZE = 100
      PROJECT_FEATURE_ENABLED_OR_PRIVATE = [::ProjectFeature::ENABLED, ::ProjectFeature::PRIVATE].freeze
      PROJECT_ID_FIELD = :project_id
      ASSIGNEE_ID_FIELD = :assignee_id
      PROJECT_VISIBILITY_FIELD = :visibility_level
      NAMESPACE_VISIBILITY_FIELD = :namespace_visibility_level
      TRAVERSAL_IDS_FIELD = :traversal_ids
      # Most indexes carry the id of the namespace a document belongs to; an index whose
      # documents are themselves groups carries it in `id` instead.
      ANCESTOR_ID_FIELD = :namespace_id

      ALLOWED_NOTEABLE_TYPES = ::Elastic::Latest::NoteClassProxy::NOTEABLE_TYPE_TO_FEATURE.keys.map(&:to_s).freeze

      # min_access_level/private_min_access_level is the user's Gitlab::Access role (GUEST, REPORTER) and
      # describes the user; feature_access_levels is the project's ProjectFeature setting, not the user's.
      FeatureAccessRule = Data.define(
        :custom_role_ids,
        :feature,
        :feature_access_levels,
        :min_access_level,
        :private_min_access_level,
        :relaxed
      )

      class << self
        include ::Elastic::Latest::QueryContext::Aware
        include Search::Elastic::Concerns::FilterUtils
        include Search::Elastic::Concerns::AuthorizationUtils
        include Gitlab::Utils::StrongMemoize

        def by_combined_search_level_and_membership(query_hash:, options:)
          search_level = fetch_search_level!(options)
          if cross_project_search_restricted_for_user?(user: options[:current_user], search_level: search_level)
            return match_none_filter(query_hash)
          end

          combined_filter = Search::Elastic::BoolExpr.new
          combined_options = options.merge(filter_path: [:filter])

          if combined_options[:use_project_authorization]
            add_filter(combined_filter, :should) do
              project_filter = Search::Elastic::BoolExpr.new
              by_search_level_and_membership(query_hash: project_filter, options: combined_options)

              project_filter.to_bool_query
            end
          end

          if combined_options[:use_group_authorization]
            add_filter(combined_filter, :should) do
              group_filter = Search::Elastic::BoolExpr.new
              by_search_level_and_group_membership(query_hash: group_filter, options: combined_options)
              exclude_project_documents(group_filter, combined_options)
              group_filter.to_bool_query
            end
          end

          add_filter(query_hash, :query, :bool, :filter) do
            combined_filter.to_bool_query
          end
        end

        def by_search_level_and_membership(query_hash:, options:)
          search_level = fetch_search_level!(options)
          user = options[:current_user]

          return match_none_filter(query_hash) if cross_project_search_restricted_for_user?(user:, search_level:)

          query_hash = search_level_filter(query_hash: query_hash, options: options)

          filter_path = options.fetch(:filter_path, [:query, :bool, :filter])

          # When restrict_to_membership is true and the user has no memberships,
          # the filter would be empty, which would match all documents.
          # Instead, we need to explicitly match nothing.
          membership_filter = build_membership_filter(options:)
          if options[:restrict_to_membership] && membership_filter.empty?
            return add_filter(query_hash, *filter_path) { { match_none: {} } }
          end

          add_filter(query_hash, *filter_path) do
            membership_filter.to_bool_query
          end
        end

        def by_source_branch(query_hash:, options:)
          source_branch = options[:source_branch]
          not_source_branch = options[:not_source_branch]

          return query_hash unless source_branch || not_source_branch

          context.name(:filters) do
            should = []
            if source_branch
              should << { term: { source_branch: { _name: context.name(:source_branch), value: source_branch } } }
            end

            if not_source_branch
              should << {
                bool: {
                  must_not: {
                    term: { source_branch: { _name: context.name(:not_source_branch), value: not_source_branch } }
                  }
                }
              }
            end

            add_filter(query_hash, :query, :bool, :filter) do
              { bool: { should: should, minimum_should_match: 1 } }
            end
          end
        end

        def by_target_branch(query_hash:, options:)
          target_branch = options[:target_branch]
          not_target_branch = options[:not_target_branch]

          return query_hash unless target_branch || not_target_branch

          context.name(:filters) do
            should = []
            if target_branch
              should << { term: { target_branch: { _name: context.name(:target_branch), value: target_branch } } }
            end

            if not_target_branch
              should << {
                bool: {
                  must_not: {
                    term: { target_branch: { _name: context.name(:not_target_branch), value: not_target_branch } }
                  }
                }
              }
            end

            add_filter(query_hash, :query, :bool, :filter) do
              { bool: { should: should, minimum_should_match: 1 } }
            end
          end
        end

        def by_iids(query_hash:, options:)
          iids = options[:iids]

          return query_hash unless iids

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              {
                bool: {
                  _name: context.name(:iids),
                  filter: {
                    terms: {
                      'iid' => iids
                    }
                  }
                }
              }
            end
          end

          query_hash
        end

        def by_author(query_hash:, options:)
          author_username = options[:author_username]
          not_author_username = options[:not_author_username]

          return query_hash unless author_username || not_author_username

          included_user = User.find_by_username(author_username)
          excluded_user = User.find_by_username(not_author_username)

          return query_hash unless included_user || excluded_user

          context.name(:filters) do
            should = []
            if included_user
              should << { term: { author_id: { _name: context.name(:author), value: included_user.id } } }
            end

            if excluded_user
              should << {
                bool: {
                  must_not: {
                    term: { author_id: { _name: context.name(:not_author), value: excluded_user.id } }
                  }
                }
              }
            end

            add_filter(query_hash, :query, :bool, :filter) do
              { bool: { should: should, minimum_should_match: 1 } }
            end
          end
        end

        def by_closed_at(query_hash:, options:)
          closed_after = options[:closed_after]
          closed_before = options[:closed_before]

          return query_hash unless closed_after || closed_before

          context.name(:filters) do
            if closed_after
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:closed_after),
                    must: {
                      range: {
                        'closed_at' => {
                          gte: closed_after
                        }
                      }
                    }
                  }
                }
              end
            end

            if closed_before
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:closed_before),
                    must: {
                      range: {
                        'closed_at' => {
                          lte: closed_before
                        }
                      }
                    }
                  }
                }
              end
            end
          end

          query_hash
        end

        def by_created_at(query_hash:, options:)
          created_after = options[:created_after]
          created_before = options[:created_before]

          return query_hash unless created_after || created_before

          context.name(:filters) do
            if created_after
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:created_after),
                    must: {
                      range: {
                        'created_at' => {
                          gte: created_after
                        }
                      }
                    }
                  }
                }
              end
            end

            if created_before
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:created_before),
                    must: {
                      range: {
                        'created_at' => {
                          lte: created_before
                        }
                      }
                    }
                  }
                }
              end
            end
          end

          query_hash
        end

        def by_updated_at(query_hash:, options:)
          updated_after = options[:updated_after]
          updated_before = options[:updated_before]

          return query_hash unless updated_after || updated_before

          context.name(:filters) do
            if updated_after
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:updated_after),
                    must: {
                      range: {
                        'updated_at' => {
                          gte: updated_after
                        }
                      }
                    }
                  }
                }
              end
            end

            if updated_before
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:updated_before),
                    must: {
                      range: {
                        'updated_at' => {
                          lte: updated_before
                        }
                      }
                    }
                  }
                }
              end
            end
          end

          query_hash
        end

        def by_due_date(query_hash:, options:)
          due_after = options[:due_after]
          due_before = options[:due_before]

          return query_hash unless due_after || due_before

          context.name(:filters) do
            if due_after
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:due_after),
                    must: {
                      range: {
                        'due_date' => {
                          gte: due_after
                        }
                      }
                    }
                  }
                }
              end
            end

            if due_before
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:due_before),
                    must: {
                      range: {
                        'due_date' => {
                          lte: due_before
                        }
                      }
                    }
                  }
                }
              end
            end
          end

          query_hash
        end

        def by_milestone(query_hash:, options:)
          # milestone_title filters and wildcard filters (any_milestones, none_milestones)
          # are mutually exclusive and should not be used together in the same query
          milestone_titles = options[:milestone_title]
          not_milestone_titles = options[:not_milestone_title]
          none_milestones = options[:none_milestones]
          any_milestones = options[:any_milestones]

          return query_hash unless milestone_titles || not_milestone_titles || none_milestones || any_milestones

          context.name(:filters) do
            if milestone_titles
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    must: {
                      terms: {
                        _name: context.name(:milestone_title),
                        milestone_title: milestone_titles
                      }
                    }
                  }
                }
              end
            end

            if not_milestone_titles
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    must_not: {
                      terms: {
                        _name: context.name(:not_milestone_title),
                        milestone_title: not_milestone_titles
                      }
                    }
                  }
                }
              end
            end

            if any_milestones
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:any_milestones),
                    must: { exists: { field: 'milestone_title' } }
                  }
                }
              end
            end

            if none_milestones
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:none_milestones),
                    must_not: { exists: { field: 'milestone_title' } }
                  }
                }
              end
            end
          end

          query_hash
        end

        def by_milestone_state(query_hash:, options:)
          # Unified milestone state filters holding an array of the following symbols
          # :upcoming, :started, :not_upcoming, :not_started
          milestone_state_filters = options[:milestone_state_filters]

          return query_hash unless milestone_state_filters

          context.name(:filters) do
            milestone_state_filters.each do |filter_type|
              base_query = {
                bool: {
                  _name: context.name("milestone_state_#{filter_type}"),
                  must: [
                    { term: { milestone_state: "active" } }
                  ]
                }
              }

              if filter_type == :upcoming || filter_type == :not_started
                # Both follow the same patterns: active milestones with start_date > now
                base_query[:bool][:must] << {
                  range: { milestone_start_date: { gt: "now/d" } }
                }
              end

              if filter_type == :started
                # Active milestones that have started but not finished
                # or that have started but have no due date
                # or that have no start date but due date is in the future
                base_query[:bool][:must].concat([
                  {
                    bool: {
                      should: [
                        { range: { milestone_start_date: { lte: "now/d" } } },
                        { bool: { must_not: { exists: { field: "milestone_start_date" } } } }
                      ]
                    }
                  },
                  {
                    bool: {
                      should: [
                        { range: { milestone_due_date: { gte: "now/d" } } },
                        { bool: { must_not: { exists: { field: "milestone_due_date" } } } }
                      ]
                    }
                  }
                ])

                base_query[:bool][:must_not] = {
                  bool: {
                    must: [
                      { bool: { must_not: { exists: { field: "milestone_start_date" } } } },
                      { bool: { must_not: { exists: { field: "milestone_due_date" } } } }
                    ]
                  }
                }
              end

              if filter_type == :not_upcoming
                # Active milestones that have already started (start_date <= now)
                base_query[:bool][:must] << {
                  range: { milestone_start_date: { lte: "now/d" } }
                }
              end

              add_filter(query_hash, :query, :bool, :filter) do
                base_query
              end
            end
          end

          query_hash
        end

        def by_assignees(query_hash:, options:)
          assignee_ids = options[:assignee_ids]
          not_assignee_ids = options[:not_assignee_ids]
          or_assignee_ids = options[:or_assignee_ids]
          none_assignees = options[:none_assignees]
          any_assignees = options[:any_assignees]

          unless assignee_ids || not_assignee_ids || or_assignee_ids || none_assignees || any_assignees
            return query_hash
          end

          # Documents store assignees under different field names per doc type:
          # work items use `assignee_id`, merge requests use `assignee_ids`.
          assignee_id_field = options.fetch(:assignee_id_field, ASSIGNEE_ID_FIELD)

          context.name(:filters) do
            if assignee_ids
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:assignee_ids),
                    must: assignee_ids.map do |assignee_id|
                      {
                        term: {
                          "#{assignee_id_field}": assignee_id
                        }
                      }
                    end
                  }
                }
              end
            end

            if not_assignee_ids
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    must_not: {
                      terms: {
                        _name: context.name(:not_assignee_ids),
                        "#{assignee_id_field}": not_assignee_ids
                      }
                    }
                  }
                }
              end
            end

            if or_assignee_ids
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    must: {
                      terms: {
                        _name: context.name(:or_assignee_ids),
                        "#{assignee_id_field}": or_assignee_ids
                      }
                    }
                  }
                }
              end
            end

            if none_assignees
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:none_assignees),
                    must_not: { exists: { field: assignee_id_field.to_s } }
                  }
                }
              end
            end

            if any_assignees
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:any_assignees),
                    must: { exists: { field: assignee_id_field.to_s } }
                  }
                }
              end
            end
          end

          query_hash
        end

        def by_weight(query_hash:, options:)
          weight = options[:weight]
          not_weight = options[:not_weight]
          none_weight = options[:none_weight]
          any_weight = options[:any_weight]

          return query_hash unless weight || not_weight || none_weight || any_weight

          context.name(:filters) do
            if weight
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  term: {
                    weight: {
                      _name: context.name(:weight),
                      value: weight
                    }
                  }
                }
              end
            end

            if not_weight
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    must_not: {
                      term: {
                        weight: {
                          _name: context.name(:not_weight),
                          value: not_weight
                        }
                      }
                    }
                  }
                }
              end
            end

            if none_weight
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:none_weight),
                    must_not: { exists: { field: 'weight' } }
                  }
                }
              end
            end

            if any_weight
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:any_weight),
                    must: { exists: { field: 'weight' } }
                  }
                }
              end
            end
          end

          query_hash
        end

        def by_work_item_type_ids(query_hash:, options:)
          return query_hash if options[:aggregation]

          work_item_type_ids = options[:work_item_type_ids]
          not_work_item_type_ids = options[:not_work_item_type_ids]

          return query_hash unless work_item_type_ids || not_work_item_type_ids

          context.name(:filters) do
            if work_item_type_ids
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    must: {
                      terms: {
                        _name: context.name(:work_item_type_ids),
                        work_item_type_id: work_item_type_ids
                      }
                    }
                  }
                }
              end
            end

            if not_work_item_type_ids
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    must_not: {
                      terms: {
                        _name: context.name(:not_work_item_type_ids),
                        work_item_type_id: not_work_item_type_ids
                      }
                    }
                  }
                }
              end
            end
          end
          query_hash
        end

        def by_not_hidden(query_hash:, options:)
          user = options[:current_user]
          return query_hash if user&.can_admin_all_resources?

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              { term: { hidden: { _name: context.name(:not_hidden), value: false } } }
            end
          end
        end

        def by_forbidden_states(query_hash:, options:)
          user = options[:current_user]
          return query_hash if user&.can_admin_all_resources?

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              { term: { in_forbidden_state: { _name: context.name(:not_forbidden_state), value: false } } }
            end
          end
        end

        def by_health_status(query_hash:, options:)
          health_status = options[:health_status]
          not_health_status = options[:not_health_status]
          none_health_status = options[:none_health_status]
          any_health_status = options[:any_health_status]

          return query_hash unless health_status || not_health_status || none_health_status || any_health_status

          context.name(:filters) do
            if health_status
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    must: {
                      terms: {
                        _name: context.name(:health_status),
                        health_status: health_status
                      }
                    }
                  }
                }
              end
            end

            if not_health_status
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    must_not: {
                      terms: {
                        _name: context.name(:not_health_status),
                        health_status: not_health_status
                      }
                    }
                  }
                }
              end
            end

            if none_health_status
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:none_health_status),
                    must_not: { exists: { field: 'health_status' } }
                  }
                }
              end
            end

            if any_health_status
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:any_health_status),
                    must: { exists: { field: 'health_status' } }
                  }
                }
              end
            end
          end

          query_hash
        end

        def by_state(query_hash:, options:)
          # A state aggregation query must not be scoped to one state, or every bucket
          # but the selected one is empty. See Aggregations.by_state.
          return query_hash if options[:state_aggregation]

          state = options[:state]
          return query_hash if state.blank? || state == 'all'
          return query_hash unless API::Helpers::SearchHelpers.search_states.include?(state)

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              { match: { state: { _name: context.name(:state), query: state } } }
            end
          end
        end

        def by_archived(query_hash:, options:)
          raise ArgumentError, 'search_level is a required option' unless options.key?(:search_level)

          include_archived = !!options[:include_archived]
          search_level = options[:search_level].to_sym
          return query_hash if search_level == :project
          return query_hash if include_archived

          context.name(:filters) do
            archived_false_filter = { bool: { filter: { term: { archived: { value: false } } } } }
            archived_missing_filter = { bool: { must_not: { exists: { field: 'archived' } } } }
            exclude_archived_filter = { bool: { _name: context.name(:non_archived),
                                                should: [archived_false_filter, archived_missing_filter] } }

            add_filter(query_hash, :query, :bool, :filter) do
              exclude_archived_filter
            end
          end
        end

        # @deprecated - all new label filters should use by_label_names
        def by_label_ids(query_hash:, options:)
          return query_hash if options[:count_only]

          return query_hash unless [options[:label_name]].flatten.any?

          label_names_hash = find_labels_by_name([options[:label_name]].flatten, options)
          return query_hash unless label_names_hash.any?

          must_query = { must: [] }
          context.name(:filters) do
            label_names_hash.each_value do |label_ids|
              must_query[:must] << {
                terms: {
                  _name: context.name(:label_ids),
                  label_ids: label_ids
                }
              }
            end
          end

          add_filter(query_hash, :query, :bool, :filter) do
            { bool: must_query }
          end
        end

        def by_label_names(query_hash:, options:)
          label_names = options[:label_names]
          not_label_names = options[:not_label_names]
          or_label_names = options[:or_label_names]
          none_label_names = options[:none_label_names]
          any_label_names = options[:any_label_names]

          unless label_names || not_label_names || or_label_names || none_label_names || any_label_names
            return query_hash
          end

          context.name(:filters) do
            if label_names
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:label_names),
                    must: build_label_queries(label_names)
                  }
                }
              end
            end

            if not_label_names
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:not_label_names),
                    must_not: build_label_queries(not_label_names)
                  }
                }
              end
            end

            if or_label_names
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:or_label_names),
                    should: build_label_queries(or_label_names),
                    minimum_should_match: 1
                  }
                }
              end
            end

            if none_label_names
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:none_label_names),
                    must_not: { exists: { field: 'label_names' } }
                  }
                }
              end
            end

            if any_label_names
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  bool: {
                    _name: context.name(:any_label_names),
                    must: { exists: { field: 'label_names' } }
                  }
                }
              end
            end
          end

          query_hash
        end

        def by_search_level_and_group_membership(query_hash:, options:)
          search_level = fetch_search_level!(options)
          user = options[:current_user]

          return match_none_filter(query_hash) if cross_project_search_restricted_for_user?(user:, search_level:)

          query_hash = search_level_filter(query_hash: query_hash, options: options,
            include_ancestors: options[:include_ancestor_groups])

          filter_path = options.fetch(:filter_path, [:query, :bool, :filter])

          add_filter(query_hash, *filter_path) do
            build_group_membership_filter(user:, search_level:, options:)
          end
        end

        def by_type(query_hash:, options:)
          raise ArgumentError, 'by_type filter requires doc_type option' unless options.key?(:doc_type)

          doc_type = options[:doc_type]
          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              {
                term: {
                  type: {
                    _name: context.name(:doc, :is_a, doc_type),
                    value: doc_type
                  }
                }
              }
            end
          end
        end

        # Caution: use this method with care.
        # Only use if `traversal_ids` is predetermined and on scopes that don't have visibility checks.
        # Prefer to use `by_search_level_and_membership` which takes care of visibility and membership.
        def by_traversal_ids(query_hash:, options:)
          return query_hash unless options[:traversal_ids]

          traversal_ids_ancestry_filter(query_hash, options[:traversal_ids], options)
        end

        # Specific to user search. All visibility and membership queries should use `by_search_level_and_membership` or
        # `by_search_level_and_group_membership`
        def by_user_accessible_namespaces(query_hash:, options:)
          search_level = fetch_search_level!(options)

          prefixes, terms = case search_level
                            when :global
                              user_accessible_traversal_ids_for_global(options)
                            when :group
                              user_accessible_traversal_ids_for_group(options)
                            when :project
                              user_accessible_traversal_ids_for_project(options)
                            end

          return query_hash if terms.empty? && prefixes.empty?

          context.name(:namespace) do
            should = prefixes.map do |traversal_id|
              { prefix: { namespace_ancestry_ids: { _name: context.name(:ancestry_filter, :descendants),
                                                    value: traversal_id } } }
            end

            unless terms.empty?
              should << {
                terms: {
                  namespace_ancestry_ids: terms,
                  _name: context.name(:ancestry_filter, :ancestors)
                }
              }
            end

            add_filter(query_hash, :query, :bool, :filter) do
              { bool: { should: should, minimum_should_match: 1 } }
            end
          end
        end

        def by_noteable_type(query_hash:, options:)
          noteable_type = options[:noteable_type]
          return query_hash unless noteable_type

          unless ALLOWED_NOTEABLE_TYPES.include?(noteable_type)
            raise ArgumentError,
              "Invalid noteable_type: #{noteable_type}. Must be one of: #{ALLOWED_NOTEABLE_TYPES.join(', ')}"
          end

          context.name(:filters) do
            if options[:related_ids_only]
              query_hash[:_source] = ['noteable_id']
              # basic_query_hash automatically adds highlight
              query_hash.delete(:highlight)
              query_hash[:size] = options.fetch(:related_size, DEFAULT_RELATED_SIZE)
            end

            add_filter(query_hash, :query, :bool, :filter) do
              {
                term: {
                  noteable_type: {
                    _name: context.name(:related, noteable_type.downcase),
                    value: noteable_type
                  }
                }
              }
            end
          end
        end

        def by_parent(query_hash:, options:)
          parent_id = options[:parent_id]
          return query_hash unless parent_id

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              { term: { parent_id: { _name: context.name(:parent), value: parent_id } } }
            end
          end
        end

        # Top-level namespaces have no parent, and Elasticsearch does not index null
        # values, so their documents simply have no parent_id field.
        def by_top_level(query_hash:, options:)
          return query_hash unless options[:top_level_only]

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              { bool: { _name: context.name(:top_level), must_not: { exists: { field: 'parent_id' } } } }
            end
          end
        end

        # Intersects with by_search_level_and_group_membership, which stays the visibility
        # boundary, so a mistake here narrows the result set and cannot widen it.
        def by_authorized_groups_only(query_hash:, options:)
          return query_hash unless options[:authorized_groups_only]

          user = options[:current_user]
          # Anonymous requests still get public groups, so there is nothing to narrow.
          return query_hash unless user

          should = authorized_groups_only_clauses(user, options)

          return match_none_filter(query_hash) if should.empty?

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              {
                bool: {
                  _name: context.name(:authorized_groups_only),
                  should: should,
                  minimum_should_match: 1
                }
              }
            end
          end
        end

        # The indexed active flag is ancestor-aware, so this is an exact complement in both
        # directions: NOT(non-archived AND not-aimed-for-deletion) is self_or_ancestors_inactive.
        def by_active(query_hash:, options:)
          return query_hash if options[:active].nil?

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              { term: { active: { _name: context.name(:active), value: options[:active] } } }
            end
          end
        end

        # An empty array means "nothing matches", not "no filter".
        def by_ids(query_hash:, options:)
          ids = options[:ids]
          return query_hash if ids.nil?

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              { terms: { _name: context.name(:ids), id: ids } }
            end
          end
        end

        def by_excluded_ids(query_hash:, options:)
          excluded_ids = options[:excluded_ids]
          return query_hash if excluded_ids.blank?

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :must_not) do
              { terms: { _name: context.name(:excluded_ids), id: excluded_ids } }
            end
          end
        end

        def by_organization(query_hash:, options:)
          organization_id = options[:organization_id]
          return query_hash unless organization_id

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              { term: { organization_id: { _name: context.name(:organization), value: organization_id } } }
            end
          end
        end

        # The levels the caller asked for, not what they may see: callers intersect with
        # their own access first, so an empty array means "nothing matches".
        def by_visibility_level(query_hash:, options:)
          levels = options[:visibility_levels]
          return query_hash if levels.nil?

          field = options.fetch(:namespace_visibility_field, NAMESPACE_VISIBILITY_FIELD)

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              { terms: { _name: context.name(field), "#{field}": levels } }
            end
          end
        end

        private

        def fetch_search_level!(options)
          raise ArgumentError, 'search_level is required' unless options.key?(:search_level)

          options[:search_level].to_sym.tap do |level|
            raise ArgumentError, 'search_level invalid' unless ALLOWED_SEARCH_LEVELS.include?(level)
          end
        end

        # users without read_cross_project permission may not perform global and group searches
        # https://docs.gitlab.com/administration/settings/external_authorization/
        def cross_project_search_restricted_for_user?(user:, search_level:)
          [:global, :group].include?(search_level) && !Ability.allowed?(user, :read_cross_project)
        end

        def match_none_filter(query_hash)
          add_filter(query_hash, :query, :bool, :filter) do
            { match_none: {} }
          end
        end

        # For document types whose project and group documents share a visibility field, the group
        # branch would otherwise grant project documents by project visibility alone.
        def exclude_project_documents(group_filter, options)
          field = options[:project_document_field]
          return unless field

          group_filter.must_not << {
            exists: { _name: context.name(:filters, :group_documents_only), field: field }
          }
        end

        def group_ids_user_has_min_access_as(access_level:, user:, group_ids:)
          finder_params = { min_access_level: access_level }
          if group_ids.present?
            finder_params[:filter_group_ids] =
              Group.id_in(group_ids.uniq).map(&:self_and_descendants_ids).uniq
          end

          ::GroupsFinder.new(user, finder_params).execute.pluck("#{Group.table_name}.#{Group.primary_key}") # rubocop:disable CodeReuse/ActiveRecord -- we need pluck only the ids from the finder
        end

        def traversal_ids_ancestry_filter(query_hash, namespace_ancestry, options)
          return query_hash if namespace_ancestry.empty?

          context.name(:namespace) do
            add_filter(query_hash, :query, :bool, :filter) do
              {
                bool: {
                  should: ancestry_filter(namespace_ancestry,
                    traversal_id_field: options.fetch(:traversal_ids_prefix, TRAVERSAL_IDS_FIELD)),
                  minimum_should_match: 1
                }
              }
            end
          end
        end

        def find_labels_by_name(names, options)
          raise ArgumentError, 'search_level is a required option' unless options.key?(:search_level)

          return [] if names.empty?

          search_level = options[:search_level].to_sym
          finder_params = { name: names }

          labels = case search_level
                   when :global
                     find_global_labels(finder_params)
                   when :group
                     find_group_labels(finder_params, options[:group_ids])
                   when :project
                     find_project_labels(finder_params, options[:group_ids], options[:project_ids])
                   else
                     raise ArgumentError, 'Invalid search_level option provided'
                   end

          group_labels_by_name(labels)
        end

        def find_global_labels(finder_params)
          LabelsFinder.new(nil, finder_params).execute(skip_authorization: true)
        end

        def find_group_labels(finder_params, group_ids)
          return find_global_labels(finder_params) if group_ids.blank?

          finder_params[:include_descendant_groups] = true
          finder_params[:include_ancestor_groups] = true

          group_ids.flat_map do |group_id|
            LabelsFinder.new(nil, finder_params.merge(group_id: group_id)).execute(skip_authorization: true)
          end
        end

        def find_project_labels(finder_params, group_ids, project_ids)
          # try group labels if no project_ids are provided or set to :any which means user has admin access
          return find_group_labels(finder_params, group_ids) if project_ids.blank? || project_ids == :any

          finder_params[:include_descendant_groups] = false
          finder_params[:include_ancestor_groups] = true

          project_ids.flat_map do |project_id|
            LabelsFinder.new(nil, finder_params.merge(project_id: project_id)).execute(skip_authorization: true)
          end
        end

        def group_labels_by_name(labels)
          labels.each_with_object(Hash.new { |h, k| h[k] = [] }) do |label, hash|
            hash[label.name] << label.id
          end
        end

        def search_level_filter(query_hash:, options:, include_ancestors: false)
          user = options[:current_user]
          search_level = options[:search_level].to_sym
          namespace_ids = options[:group_ids]
          project_ids = scoped_project_ids(user, options[:project_ids])
          filter_path = options.fetch(:filter_path, [:query, :bool, :filter])

          add_filter(query_hash, *filter_path) do
            context.name(:filters, :level, search_level) do
              case search_level
              when :global
                nil
              when :group
                raise ArgumentError, 'No group_ids provided for group level search' if namespace_ids.empty?

                namespaces = Namespace.id_in(namespace_ids)
                traversal_ids = namespaces.map(&:elastic_namespace_ancestry)
                traversal_id_field = options.fetch(:traversal_ids_prefix, TRAVERSAL_IDS_FIELD)
                should = ancestry_filter(traversal_ids, traversal_id_field: traversal_id_field)
                ancestor_ids = include_ancestors ? ancestor_traversal_ids(traversal_ids) : []
                if ancestor_ids.any?
                  should << { terms: { _name: context.name(:ancestors), "#{traversal_id_field}": ancestor_ids } }
                end

                { bool: { _name: context.name, minimum_should_match: 1, should: should } }
              when :project
                raise ArgumentError, 'No project_ids provided for project level search' if project_ids.empty?

                if include_ancestors && project_ids.is_a?(Array)
                  # Matches documents of the project's group and its ancestors.
                  namespace_traversal_ids = Namespace.id_in(Project.id_in(project_ids).select(:namespace_id))
                    .map(&:elastic_namespace_ancestry)
                  traversal_id_field = options.fetch(:traversal_ids_prefix, TRAVERSAL_IDS_FIELD)
                  group_traversal_ids = (namespace_traversal_ids + ancestor_traversal_ids(namespace_traversal_ids)).uniq

                  { terms: { _name: context.name(:ancestors), "#{traversal_id_field}": group_traversal_ids } }
                else
                  project_id_field = options.fetch(:project_id_field, PROJECT_ID_FIELD)
                  { terms: { _name: context.name, "#{project_id_field}": project_ids } }
                end
              end
            end
          end
        end

        # A document of an ancestor group has exactly that group's traversal_ids, so a prefix match can't reach it.
        # For `1-2-3-` this returns `1-` and `1-2-`.
        def ancestor_traversal_ids(traversal_ids)
          traversal_ids.flat_map do |traversal_id|
            ids = traversal_id.split('-')
            (1...ids.size).map { |depth| "#{ids.first(depth).join('-')}-" }
          end.uniq
        end

        def build_membership_filter(options:)
          user = options[:current_user]
          search_level = options[:search_level].to_sym

          membership_filter = Search::Elastic::BoolExpr.new

          context.name(:filters, :permissions, search_level) do
            membership_filter = build_project_and_group_membership_filters(filter: membership_filter,
              user: user, options: options)
            membership_filter = build_public_and_internal_filters(filter: membership_filter, user: user,
              options: options)
          end

          membership_filter
        end

        # add visibility level filter for public and internal visibility, does not include group or project membership
        # admins do not add any filter
        # logged-in users get PUBLIC and INTERNAL
        # anonymous and logged in external users only get PUBLIC
        def add_visibility_level_filter(filter:, user:, visibility_level_field:)
          return if user&.can_read_all_resources?

          add_filter(filter, :filter) do
            if user && !user.external?
              { terms: {
                _name: context.name(visibility_level_field, :public_and_internal),
                "#{visibility_level_field}": [::Gitlab::VisibilityLevel::PUBLIC, ::Gitlab::VisibilityLevel::INTERNAL]
              } }
            else
              { terms: {
                _name: context.name(visibility_level_field, :public),
                "#{visibility_level_field}": [::Gitlab::VisibilityLevel::PUBLIC]
              } }
            end
          end
        end

        # add project feature visibility filter, does not include group or project membership
        # admins get ENABLED and PRIVATE, all other users get ENABLED
        def add_project_feature_visibility_filter(filter:, features:, user:)
          return if features.blank?

          access_level_allowed = [::ProjectFeature::ENABLED]
          access_context_name = :enabled
          if user&.can_read_all_resources?
            access_level_allowed << ::ProjectFeature::PRIVATE
            access_context_name = :enabled_or_private
          end

          features.each do |feature|
            add_filter(filter, :should) do
              {
                terms: {
                  _name: context.name(:"#{feature}_access_level", access_context_name),
                  "#{feature}_access_level": access_level_allowed
                }
              }
            end
          end
        end

        def build_public_and_internal_filters(filter:, user:, options:)
          return filter if options[:restrict_to_membership]

          features = Array.wrap(options[:features])
          visibility_level_field = options.fetch(:project_visibility_level_field, PROJECT_VISIBILITY_FIELD)

          new_filter = filter.dup

          # for admins and anonymous users, do not nest the query
          if user.nil? || user&.can_read_all_resources?
            add_visibility_level_filter(filter: new_filter, user: user, visibility_level_field: visibility_level_field)
            add_project_feature_visibility_filter(filter: new_filter, user: user, features: features)

            return new_filter
          end

          public_and_internal_filter = Search::Elastic::BoolExpr.new
          add_visibility_level_filter(filter: public_and_internal_filter, user: user,
            visibility_level_field: visibility_level_field)
          add_project_feature_visibility_filter(filter: public_and_internal_filter, user: user, features: features)

          add_filter(new_filter, :should) do
            public_and_internal_filter.to_bool_query
          end

          new_filter
        end

        def build_project_and_group_membership_filters(filter:, user:, options:)
          return filter if user&.can_read_all_resources? && !options[:restrict_to_membership]

          new_filter = filter.dup
          add_group_membership_filters(new_filter, user, options)
          add_project_membership_filters(new_filter, user, options)

          new_filter
        end

        def add_group_membership_filters(membership_filters, user, options)
          groups = groups_for_user(user: user)

          return unless groups.exists?

          features = Array.wrap(options[:features])
          if features.empty?
            add_filter(membership_filters, :should) do
              traversal_id_field = options.fetch(:traversal_ids_prefix, TRAVERSAL_IDS_FIELD)
              traversal_ids = format_traversal_ids(traversal_ids_for_search_level(groups, options))

              ancestry_filter(traversal_ids, traversal_id_field: traversal_id_field)
            end

            return
          end

          process_features_for_groups(
            membership_filters: membership_filters,
            user: user,
            groups: groups,
            features: features,
            options: options
          )
        end

        def process_features_for_groups(membership_filters:, user:, groups:, features:, options:)
          user_abilities = ::Authz::Group.new(user, scope: groups).permitted
          rules = feature_access_rules(features, options, user_abilities)
          public_and_internal_branch_rules = rules_for_branch(rules, &:min_access_level)
          private_branch_rules = rules_for_branch(rules, &:private_min_access_level)

          # do not limit to private visibility level groups because private access allows access to all
          # visibility levels
          private_group_ids_by_access_level =
            private_branch_rules.map(&:private_min_access_level).uniq.index_with do |level|
              groups_for_user(user: user, min_access_level: level).pluck_primary_key
            end

          # limit to public/internal visibility level groups to avoid duplicate access filters
          public_and_internal_group_ids_by_access_level =
            public_and_internal_branch_rules.map(&:min_access_level).uniq.index_with do |level|
              groups_for_user(user: user, min_access_level: level).public_and_internal_only.pluck_primary_key
            end

          # find private groups first so they can be removed from public_internal groups
          private_ids_by_rule = private_branch_rules.index_with do |rule|
            private_group_ids_by_access_level.fetch(rule.private_min_access_level, []) + rule.custom_role_ids
          end

          # remove private groups from the public/internal list, they already have access
          public_and_internal_ids_by_rule = public_and_internal_branch_rules.index_with do |rule|
            public_and_internal_group_ids_by_access_level.fetch(rule.min_access_level, []) +
              rule.custom_role_ids - private_ids_by_rule.fetch(rule, [])
          end

          public_and_internal_rules = group_rules_by_ids(public_and_internal_ids_by_rule)
          private_rules = group_rules_by_ids(private_ids_by_rule)

          public_and_internal_rules.each do |group_ids, feature_rules|
            next if group_ids.empty?

            add_filter(membership_filters, :should) do
              build_public_and_internal_group_filters(
                traversal_ids: traversal_ids_for_groups(group_ids, options),
                feature_rules: feature_rules,
                options: options
              )
            end
          end

          private_rules.each do |group_ids, feature_rules|
            next if group_ids.empty?

            add_filter(membership_filters, :should) do
              build_private_group_filters(
                traversal_ids: traversal_ids_for_groups(group_ids, options),
                feature_rules: feature_rules,
                options: options
              )
            end
          end
        end

        # A feature normally grants access at its documented minimum level. `options[:relaxed_feature_access]`
        # adds a second, lower-level route for a narrower set of `<feature>_access_level` values, which is how
        # milestone search reaches Guest and Planner members of projects with issues disabled.
        def feature_access_rules(features, options, user_abilities)
          relaxed_rules = options[:relaxed_feature_access] || {}

          features.flat_map do |feature|
            access_levels = get_feature_access_levels(feature)

            rules = [
              FeatureAccessRule.new(
                feature: feature,
                feature_access_levels: PROJECT_FEATURE_ENABLED_OR_PRIVATE,
                min_access_level: access_levels[:project],
                private_min_access_level: access_levels[:private_project],
                custom_role_ids: allowed_ids_by_ability(feature:, user_abilities:),
                relaxed: false
              )
            ]

            relaxed = relaxed_rules[feature.to_sym]
            next rules unless relaxed

            min_access_level = relaxed.fetch(:min_access_level)
            # No custom-role ids: a relaxed rule is authorized purely by membership level.
            rules << FeatureAccessRule.new(
              feature: feature,
              feature_access_levels: relaxed.fetch(:feature_access_levels),
              min_access_level: min_access_level,
              private_min_access_level: min_access_level,
              custom_role_ids: [],
              relaxed: true
            )
          end
        end

        def feature_access_level_context_name(feature_access_levels)
          feature_access_levels.include?(::ProjectFeature::PRIVATE) ? :enabled_or_private : :enabled
        end

        # Drop a relaxed rule from a branch where its base rule already grants the same access.
        def rules_for_branch(rules)
          base_rules = rules.reject(&:relaxed).index_by(&:feature)

          rules.reject do |rule|
            next false unless rule.relaxed

            base_rule = base_rules.fetch(rule.feature)

            yield(base_rule) <= yield(rule) && (rule.feature_access_levels - base_rule.feature_access_levels).empty?
          end
        end

        # Rules that resolve to the same id list share one clause, with their feature predicates OR-ed
        # inside it, so the list is serialized into the query body once instead of once per rule.
        def group_rules_by_ids(ids_by_rule)
          ids_by_rule.each_with_object({}) do |(rule, ids), rules_by_ids|
            (rules_by_ids[ids] ||= []) << rule
          end
        end

        def traversal_ids_for_groups(group_ids, options)
          format_traversal_ids(traversal_ids_for_search_level(Group.id_in(group_ids), options))
        end

        def build_feature_access_level_filter(feature_rules)
          terms = feature_rules.map do |rule|
            {
              terms: {
                _name: context.name(
                  :"#{rule.feature}_access_level",
                  feature_access_level_context_name(rule.feature_access_levels)
                ),
                "#{rule.feature}_access_level": rule.feature_access_levels
              }
            }
          end

          # For anyone already clearing the base minimum, the relaxed rule resolves to the same ids and
          # produces an identical predicate; without this the clause gains a redundant bool/should wrapper.
          terms.uniq!

          return terms.first if terms.one?

          { bool: { should: terms, minimum_should_match: 1 } }
        end

        def build_public_and_internal_group_filters(traversal_ids:, feature_rules:, options:)
          return if traversal_ids.empty?

          filter = Search::Elastic::BoolExpr.new
          visibility_level_field = options.fetch(:project_visibility_level_field, PROJECT_VISIBILITY_FIELD)
          traversal_id_field = options.fetch(:traversal_ids_prefix, TRAVERSAL_IDS_FIELD)

          context.name(:public_and_internal_access) do
            add_filter(filter, :filter) do
              build_feature_access_level_filter(feature_rules)
            end

            add_filter(filter, :filter) do
              {
                terms: {
                  _name: context.name(:project_visibility_level, :public_or_internal),
                  "#{visibility_level_field}": [::Gitlab::VisibilityLevel::PUBLIC, ::Gitlab::VisibilityLevel::INTERNAL]
                }
              }
            end

            traversal_ids.each do |traversal_id|
              add_filter(filter, :should) do
                {
                  prefix: {
                    "#{traversal_id_field}": {
                      _name: context.name(:ancestry_filter, :descendants),
                      value: traversal_id
                    }
                  }
                }
              end
            end
          end

          filter.to_bool_query
        end

        def build_private_group_filters(traversal_ids:, feature_rules:, options:)
          return if traversal_ids.empty?

          filter = Search::Elastic::BoolExpr.new
          traversal_id_field = options.fetch(:traversal_ids_prefix, TRAVERSAL_IDS_FIELD)

          context.name(:private_access) do
            add_filter(filter, :filter) do
              build_feature_access_level_filter(feature_rules)
            end

            traversal_ids.each do |traversal_id|
              add_filter(filter, :should) do
                {
                  prefix: {
                    "#{traversal_id_field}": {
                      _name: context.name(:ancestry_filter, :descendants),
                      value: traversal_id
                    }
                  }
                }
              end
            end
          end

          filter.to_bool_query
        end

        def add_project_membership_filters(membership_filters, user, options)
          return unless user

          projects = projects_for_user(user, options)
          return unless projects.exists?

          features = Array.wrap(options[:features])

          if features.empty?
            project_id_field = options.fetch(:project_id_field, PROJECT_ID_FIELD)
            add_filter(membership_filters, :should) do
              {
                terms: {
                  _name: context.name(:project, :member),
                  "#{project_id_field}": projects.pluck_primary_key
                }
              }
            end

            return
          end

          process_features_for_projects(membership_filters: membership_filters, user: user, projects: projects,
            features: features, options: options)
        end

        def process_features_for_projects(membership_filters:, user:, projects:, features:, options:)
          user_abilities = ::Authz::Project.new(user, scope: projects).permitted

          rules = feature_access_rules(features, options, user_abilities)
          public_and_internal_branch_rules = rules_for_branch(rules, &:min_access_level)
          private_branch_rules = rules_for_branch(rules, &:private_min_access_level)

          public_and_internal_project_ids_by_access_level =
            public_and_internal_branch_rules.map(&:min_access_level).uniq.index_with do |level|
              projects.public_and_internal_only
                .where_exists(user.authorizations_for_projects(min_access_level: level)).pluck_primary_key
            end

          private_project_ids_by_access_level =
            private_branch_rules.map(&:private_min_access_level).uniq.index_with do |level|
              projects.private_only
                .where_exists(user.authorizations_for_projects(min_access_level: level)).pluck_primary_key
            end

          public_and_internal_ids_by_rule = public_and_internal_branch_rules.index_with do |rule|
            public_and_internal_project_ids_by_access_level.fetch(rule.min_access_level, []) + rule.custom_role_ids
          end

          private_ids_by_rule = private_branch_rules.index_with do |rule|
            private_project_ids_by_access_level.fetch(rule.private_min_access_level, []) + rule.custom_role_ids
          end

          public_and_internal_rules = group_rules_by_ids(public_and_internal_ids_by_rule)
          private_rules = group_rules_by_ids(private_ids_by_rule)

          public_and_internal_rules.each do |project_ids, feature_rules|
            add_filter(membership_filters, :should) do
              build_public_and_internal_project_filters(
                project_ids: project_ids,
                feature_rules: feature_rules,
                options: options
              )
            end
          end

          private_rules.each do |project_ids, feature_rules|
            add_filter(membership_filters, :should) do
              build_private_project_filters(
                project_ids: project_ids,
                feature_rules: feature_rules,
                options: options
              )
            end
          end
        end

        def build_public_and_internal_project_filters(project_ids:, feature_rules:, options:)
          return if project_ids.empty?

          filter = Search::Elastic::BoolExpr.new
          visibility_level_field = options.fetch(:project_visibility_level_field, PROJECT_VISIBILITY_FIELD)
          project_id_field = options.fetch(:project_id_field, PROJECT_ID_FIELD)

          context.name(:public_and_internal_access) do
            add_filter(filter, :filter) do
              build_feature_access_level_filter(feature_rules)
            end

            add_filter(filter, :filter) do
              {
                terms: {
                  _name: context.name(:project_visibility_level, :public_or_internal),
                  "#{visibility_level_field}": [::Gitlab::VisibilityLevel::PUBLIC, ::Gitlab::VisibilityLevel::INTERNAL]
                }
              }
            end

            add_filter(filter, :filter) do
              {
                terms: {
                  _name: context.name(:project, :member),
                  "#{project_id_field}": project_ids
                }
              }
            end
          end

          filter.to_bool_query
        end

        def build_private_project_filters(project_ids:, feature_rules:, options:)
          return if project_ids.empty?

          filter = Search::Elastic::BoolExpr.new
          project_id_field = options.fetch(:project_id_field, PROJECT_ID_FIELD)

          context.name(:private_access) do
            add_filter(filter, :filter) do
              build_feature_access_level_filter(feature_rules)
            end

            add_filter(filter, :filter) do
              {
                terms: {
                  _name: context.name(:project, :member),
                  "#{project_id_field}": project_ids
                }
              }
            end
          end

          filter.to_bool_query
        end

        # Builds ES queries for label filtering with wildcard support for scoped labels.
        #
        # Supports both exact matching for regular labels
        # and wildcard prefix matching for scoped labels like:
        # - "advanced search" (exact match)
        # - "workflow::complete" (exact match)
        # - "workflow::in dev" (exact match)
        # - "workflow::*" (prefix match for all labels starting with "workflow::")
        #
        # For now, it uses `prefix` queries for wildcard matching as they provide optimal performance
        # for keyword fields when doing "starts with" operations.
        #
        # This implementation follows the same pattern as the PostgreSQL version in
        # ee/app/finders/ee/issuables/label_filter.rb
        def build_label_queries(label_names)
          label_names.map do |label_name|
            if scoped_label_wildcard?(label_name)
              prefix = label_name[0...-1]
              {
                prefix: {
                  label_names: prefix
                }
              }
            else
              {
                term: {
                  label_names: label_name
                }
              }
            end
          end
        end

        def scoped_label_wildcard?(label_name)
          # Follows the existing pattern of SCOPED_LABEL_SEPARATOR in ee/app/models/ee/label.rb
          # and SCOPED_LABEL_WILDCARD in ee/app/finders/ee/issuables/label_filter.rb#extract_scoped_label_wildcards
          label_name.end_with?('::*')
        end

        def build_group_membership_filter(user:, search_level:, options:)
          context.name(:filters, :permissions, search_level) do
            filter = Search::Elastic::BoolExpr.new

            namespace_visibility_field = options.fetch(:namespace_visibility_field, NAMESPACE_VISIBILITY_FIELD)
            traversal_ids_prefix = options.fetch(:traversal_ids_prefix, TRAVERSAL_IDS_FIELD)

            if user&.can_read_all_resources?
              next context.name(:admin_all_groups) do
                {
                  exists: {
                    _name: context.name(namespace_visibility_field, :all),
                    field: namespace_visibility_field
                  }
                }
              end
            end

            add_visibility_level_filter(user: user, visibility_level_field: namespace_visibility_field, filter: filter)

            should = [{ bool: filter.to_h }]
            should << build_private_group_membership_filters(user:, namespace_visibility_field:, traversal_ids_prefix:,
              options:)
            should << build_private_project_ancestry_filters(user:, namespace_visibility_field:, options:)
            should.compact!

            {
              bool: {
                _name: context.name,
                should: should,
                minimum_should_match: 1
              }
            }
          end
        end

        def build_private_group_membership_filters(user:, namespace_visibility_field:, traversal_ids_prefix:, options:)
          # The search level narrows the user's groups to the searched subtree, which can't match an ancestor.
          # The level filter already limits the scope, so authorize ancestors against all of the user's groups.
          membership_options = options[:include_ancestor_groups] ? options.merge(search_level: :global) : options
          authorized_traversal_ids = traversal_ids_for_user(user, membership_options)
          return if authorized_traversal_ids.empty?

          membership_filters = Search::Elastic::BoolExpr.new

          add_filter(membership_filters, :must) do
            { terms: {
              _name: context.name(namespace_visibility_field, :private),
              "#{namespace_visibility_field}": [::Gitlab::VisibilityLevel::PRIVATE]
            } }
          end

          membership_filters.should += ancestry_filter(authorized_traversal_ids,
            traversal_id_field: traversal_ids_prefix)

          # `ancestry_filter` only reaches descendants, but PostgreSQL's
          # `authorized_groups.self_and_ancestors` also grants a member of a subgroup
          # sight of its private parents. Only a group document can stand in for one.
          if options[:ancestor_id_field]
            membership_filters.should << {
              terms: {
                _name: context.name(:group, :ancestors),
                "#{options[:ancestor_id_field]}": authorized_group_ancestor_ids(user, options)
              }
            }
          end

          membership_filters.to_bool_query
        end

        # Descendants are reachable by traversal_ids prefix; ancestors are not, so they
        # need an id match.
        def authorized_groups_only_clauses(user, options)
          ancestor_id_field = options.fetch(:ancestor_id_field, ANCESTOR_ID_FIELD)

          clauses = ancestry_filter(
            traversal_ids_for_user(user, options),
            traversal_id_field: options.fetch(:traversal_ids_prefix, TRAVERSAL_IDS_FIELD)
          )

          {
            ancestors: authorized_group_ancestor_ids(user, options),
            project_ancestors: authorized_namespace_ids_for_project_group_ancestry(user)
          }.each do |name, ids|
            next if ids.blank?

            clauses << { terms: { _name: context.name(:authorized, name), "#{ancestor_id_field}": ids } }
          end

          clauses
        end

        def build_private_project_ancestry_filters(user:, namespace_visibility_field:, options:)
          authorized_ids = authorized_namespace_ids_for_project_group_ancestry(user)
          return if authorized_ids.empty?

          membership_filters = Search::Elastic::BoolExpr.new

          add_filter(membership_filters, :must) do
            { terms: {
              _name: context.name(namespace_visibility_field, :private),
              "#{namespace_visibility_field}": [::Gitlab::VisibilityLevel::PRIVATE]
            } }
          end

          add_filter(membership_filters, :must) do
            { terms: {
              _name: context.name(:project, :membership),
              "#{options.fetch(:ancestor_id_field, ANCESTOR_ID_FIELD)}": authorized_ids
            } }
          end

          membership_filters.to_bool_query
        end

        def user_accessible_traversal_ids_for_global(options)
          user = options[:current_user]
          return [[], []] unless user && options[:autocomplete]

          authorized_groups = ::Search::GroupsFinder.new(user: user).execute
          group_trie = ::Namespaces::Traversal::TrieNode.build(authorized_groups.map(&:traversal_ids))
          prefixes = group_trie.to_a.map { |id_array| "#{id_array.join('-')}-" }

          authorized_projects = ::Search::ProjectsFinder.new(user: user).execute.inc_routes
          terms = authorized_projects.map(&:elastic_namespace_ancestry)

          [prefixes, terms]
        end

        def user_accessible_traversal_ids_for_group(options)
          group = Group.find_by_id(options[:group_id])
          return [[], []] unless group

          terms = split_traversal_ids_into_prefixes(group.elastic_namespace_ancestry)
          prefixes = [terms.pop]
          [prefixes, terms]
        end

        def user_accessible_traversal_ids_for_project(options)
          project = Project.find_by_id(options[:project_id])
          return [[], []] unless project

          [[], split_traversal_ids_into_prefixes(project.elastic_namespace_ancestry)]
        end

        def split_traversal_ids_into_prefixes(ids)
          separator = '-'
          ids = ids.split(separator)

          ids.map.with_index do |_, idx|
            ids.slice(0..idx).join(separator) + separator
          end
        end
      end
    end
  end
end

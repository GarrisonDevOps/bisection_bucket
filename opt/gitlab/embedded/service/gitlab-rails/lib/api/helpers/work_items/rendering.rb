# frozen_string_literal: true

module API
  module Helpers
    module WorkItems
      # Apart from render_work_item_response, the methods here reach into Preloads and Authorization, and the
      # collection renderers into CursorPagination, so endpoints mounting this module must mount those too.
      module Rendering
        def render_work_items_collection_for(resource_parent)
          check_pagination_param!
          validate_requested_keys!
          validate_search_rate_limit! if params[:search].present?

          authorize! :read_work_item, resource_parent
          authorize_job_token_policies!(resource_parent) if resource_parent.is_a?(::Project)

          field_keys = requested_field_keys(params[:fields])
          feature_keys = requested_feature_keys(params[:features])
          preloads = preload_associations_for(field_keys, feature_keys, resource_parent)

          work_items_relation = build_work_items_relation(
            resource_parent, preloads: (preloads + Preloads::WORK_ITEM_POLICY_PRELOADS).uniq
          )

          work_items = paginate_work_items_collection(work_items_relation)
          preload_feature_authorization(work_items, feature_keys)
          preload_field_authorization(work_items, field_keys)
          work_items = filter_readable_work_items(work_items)

          present work_items,
            with: Entities::WorkItemBasic,
            **work_item_entity_options(work_items, field_keys, feature_keys, resource_parent: resource_parent)
        end

        def render_work_item_response(result, status:, notifications_subscriptions: nil)
          if result[:status] == :success
            feature_keys = requested_feature_keys(params[:features]&.keys&.join(','))
            field_keys = requested_field_keys(params[:fields])
            work_item = result[:work_item]

            present work_item,
              with: Entities::WorkItemBasic,
              current_user: current_user,
              requested_features: feature_keys,
              fields: field_keys,
              notifications_subscriptions: notifications_subscriptions,
              # Single-item render path: opt into the participant? fallback so the entity matches GraphQL's `subscribed`
              notifications_allow_participant_fallback: true,
              status: status,
              **count_preloads_for([work_item], field_keys, feature_keys)
          else
            render_api_error_from_response(result)
          end
        end

        def render_children_for(parent_work_item)
          render_paginated_work_items_for(parent_work_item, entity: Entities::WorkItemBasic) do |preloads|
            build_children_relation(parent_work_item, state: params[:state], preloads: preloads)
          end
        end

        def render_child_response(result, work_item, status_code:)
          if result[:status] == :success
            status status_code
            present work_item,
              with: Entities::WorkItemBasic,
              current_user: current_user,
              notifications_allow_participant_fallback: true
          else
            render_api_error_from_response(result)
          end
        end

        def render_linked_items_for(parent_work_item, link_type: nil)
          render_paginated_work_items_for(
            parent_work_item, entity: ::API::Entities::WorkItems::LinkedWorkItem
          ) do |preloads|
            build_linked_items_relation(
              parent_work_item, state: params[:state], link_type: link_type, preloads: preloads
            )
          end
        end

        # Work items are loaded via the parent relation (keyset-ordered, by relative position for children), not via
        # WorkItemsFinder. Pagination runs first so finalize sees the full page and produces a correct next-cursor,
        # then per-record :read_work_item policy filters the response in Ruby. A page may therefore present fewer items
        # than per_page when some records are not readable, but cursor advancement stays correct.
        def render_paginated_work_items_for(parent_work_item, entity:)
          authorize_work_item_feature!(parent_work_item)
          check_pagination_param!
          validate_requested_keys!

          resource_parent = parent_work_item.resource_parent
          field_keys = requested_field_keys(params[:fields])
          feature_keys = requested_feature_keys(params[:features])
          preloads = preload_associations_for(field_keys, feature_keys, resource_parent)

          relation = yield(preloads)

          paginated = paginate_with_keyset_cursor(relation) do |records|
            preload_feature_authorization(records, feature_keys)
            preload_field_authorization(records, field_keys)
            records
          end

          visible = filter_readable_work_items(Array(paginated))

          present visible,
            with: entity,
            **work_item_entity_options(visible, field_keys, feature_keys, resource_parent: resource_parent)
        end

        def render_work_item_for(resource_parent, work_item_iid)
          check_work_item_rest_api_feature_flag!
          validate_requested_keys!

          authorize! :read_work_item, resource_parent
          authorize_job_token_policies!(resource_parent) if resource_parent.is_a?(::Project)

          field_keys = requested_field_keys(params[:fields])
          feature_keys = requested_feature_keys(params[:features])
          preloads = preload_associations_for(field_keys, feature_keys, resource_parent)

          work_item = work_item_for!(resource_parent, work_item_iid, preloads: preloads)

          # The finder enforces container visibility and confidentiality in SQL, but type-level rules such as
          # requirements access live only in the policy, so the found item still has to pass :read_work_item.
          not_found!('Work Item') unless can?(current_user, :read_work_item, work_item)

          preload_feature_authorization([work_item], feature_keys)

          # Single-item render path: opt into the participant? fallback so the entity matches GraphQL's `subscribed`
          present work_item,
            with: Entities::WorkItemDetail,
            **work_item_entity_options(
              [work_item], field_keys, feature_keys, notifications_allow_participant_fallback: true
            )
        end

        private

        # Entity options every work item render shares; `extra` carries the per-path additions.
        def work_item_entity_options(work_items, field_keys, feature_keys, **extra)
          {
            current_user: current_user,
            scope_validator: ::Gitlab::Auth::ScopeValidator.new(
              access_token.present?, Gitlab::Auth::RequestAuthenticator.new(request)
            ),
            access_token: access_token,
            requested_features: feature_keys,
            fields: field_keys,
            notifications_subscriptions: preload_notifications_subscriptions(work_items, feature_keys),
            **count_preloads_for(work_items, field_keys, feature_keys),
            **extra
          }
        end

        def filter_readable_work_items(work_items)
          preload_work_item_policies(work_items)

          DeclarativePolicy.user_scope do
            work_items.select { |work_item| Ability.allowed?(current_user, :read_work_item, work_item) }
          end
        end

        def requested_field_keys(requested_fields)
          (::API::WorkItems::DEFAULT_FIELDS + filter_requested_keys(
            requested_fields, ::API::WorkItems::FIELD_NAME_LOOKUP
          )).uniq
        end

        def requested_feature_keys(requested_features)
          split_requested_values(requested_features)
            .select { |value| ::API::WorkItems::KNOWN_FEATURE_NAMES.include?(value) }
            .map(&:to_sym)
            .uniq
        end

        def validate_requested_keys!(
          available_fields: ::API::WorkItems::FIELD_NAME_LOOKUP,
          available_features: ::API::WorkItems::KNOWN_FEATURE_NAMES
        )
          lookups = { fields: available_fields, features: available_features }.compact
          unknown = lookups.filter_map do |param, available|
            values = unknown_requested_keys(params[param], available)
            [param, values] if values.any?
          end
          return if unknown.empty?

          message = unknown
            .map { |param, values| "#{param} does not have a valid value: #{values.join(', ')}" }
            .join(', ')

          render_structured_api_error!({ error: message }, :bad_request)
        end

        def unknown_requested_keys(requested_param, available_keys)
          split_requested_values(requested_param).reject { |value| available_keys.include?(value) }
        end

        def filter_requested_keys(requested_param, available_keys)
          split_requested_values(requested_param).filter_map { |value| available_keys[value] }.uniq
        end

        # Write endpoints send `features` as a Hash; its valid names are the declared params, not the read entity.
        def declared_features
          declared_params(include_missing: false)[:features].to_h.stringify_keys
        end

        def split_requested_values(requested_param)
          return [] if requested_param.nil?
          return requested_param.keys.map(&:to_s) if requested_param.is_a?(Hash)

          requested_param.split(',').map { |value| value.strip.downcase }.reject(&:blank?)
        end

        def render_api_error_from_response(response)
          render_api_error!(Array(response[:message]).join(', '), response[:http_status] || :unprocessable_entity)
        end
      end
    end
  end
end

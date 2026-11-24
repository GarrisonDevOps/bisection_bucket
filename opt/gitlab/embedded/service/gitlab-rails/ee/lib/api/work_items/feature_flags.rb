# frozen_string_literal: true

module API
  module WorkItems
    class FeatureFlags < ::API::Base
      before { authenticate! }
      before { check_work_item_rest_api_feature_flag! }

      feature_category :portfolio_management
      urgency :low

      helpers ::API::Helpers::WorkItems::Authorization
      helpers ::API::Helpers::WorkItems::CursorPagination
      helpers ::API::Helpers::WorkItems::Preloads
      helpers ::API::Helpers::WorkItems::Rendering

      helpers do
        def render_feature_flags_for(parent_work_item)
          authorize_work_item_feature!(parent_work_item)
          check_pagination_param!

          feature_flags = parent_work_item.feature_flags.ordered.with_api_entity_associations.to_a

          ::Preloaders::ProjectPolicyPreloader
            .new(feature_flags.map(&:project), current_user)
            .execute

          visible = ::Ability.feature_flags_readable_by_user(feature_flags, current_user)

          present paginate_with_offset_cursor(visible),
            with: ::API::Entities::WorkItems::Features::FeatureFlag,
            current_user: current_user,
            reference_from: parent_work_item.namespace
        end
      end

      resource :namespaces do
        params do
          requires :id, types: [String, Integer], desc: 'The ID or URL-encoded full path of the namespace'
        end

        namespace ':id/-/work_items', requirements: { id: FULL_PATH_ID_REQUIREMENT } do
          desc 'List feature flags of a work item.' do
            detail 'Get a paginated list of feature flags associated with a work item in a namespace. ' \
              'Project and group namespaces are supported.'
            hidden true
            success ::API::Entities::WorkItems::Features::FeatureFlag
            failure FAILURE_RESPONSES
            is_array true
            tags WORK_ITEMS_TAGS
          end
          params do
            requires :work_item_iid, type: Integer, desc: 'The internal ID of the work item'
            use :work_items_cursor_pagination_params
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization,
            permissions: :read_work_item,
            boundary: -> { namespace_path_boundary },
            boundaries: [{ boundary_type: :group }, { boundary_type: :project }]
          get ':work_item_iid/feature_flags' do
            render_feature_flags_for(work_item_for_namespace!(params[:id], params[:work_item_iid]))
          end
        end
      end

      resource :projects do
        params do
          requires :id, types: [String, Integer], desc: 'The ID or URL-encoded path of the project'
        end

        namespace ':id/-/work_items', requirements: { id: FULL_PATH_ID_REQUIREMENT } do
          desc 'List feature flags of a work item in a project.' do
            detail 'Get a paginated list of feature flags associated with a work item in a project.'
            hidden true
            success ::API::Entities::WorkItems::Features::FeatureFlag
            failure FAILURE_RESPONSES
            is_array true
            tags WORK_ITEMS_TAGS
          end
          params do
            requires :work_item_iid, type: Integer, desc: 'The internal ID of the work item'
            use :work_items_cursor_pagination_params
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization,
            permissions: :read_work_item,
            boundary_type: :project
          get ':work_item_iid/feature_flags' do
            render_feature_flags_for(work_item_for!(user_project, params[:work_item_iid]))
          end
        end
      end

      resource :groups do
        params do
          requires :id, types: [String, Integer], desc: 'The ID or URL-encoded path of the group'
        end

        namespace ':id/-/work_items', requirements: { id: FULL_PATH_ID_REQUIREMENT } do
          desc 'List feature flags of a work item in a group.' do
            detail 'Get a paginated list of feature flags associated with a work item in a group.'
            hidden true
            success ::API::Entities::WorkItems::Features::FeatureFlag
            failure FAILURE_RESPONSES
            is_array true
            tags WORK_ITEMS_TAGS
          end
          params do
            requires :work_item_iid, type: Integer, desc: 'The internal ID of the work item'
            use :work_items_cursor_pagination_params
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization,
            permissions: :read_work_item,
            boundary_type: :group
          get ':work_item_iid/feature_flags' do
            render_feature_flags_for(work_item_for!(find_group!(params[:id]), params[:work_item_iid]))
          end
        end
      end
    end
  end
end

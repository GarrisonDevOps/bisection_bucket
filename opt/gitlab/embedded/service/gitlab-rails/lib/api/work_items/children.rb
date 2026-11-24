# frozen_string_literal: true

module API
  module WorkItems
    class Children < ::API::Base
      include APIGuard

      allow_access_with_scope :ai_workflows, if: ->(request) { request.get? || request.head? }

      before { authenticate! }
      before { check_work_item_rest_api_feature_flag! }

      feature_category :portfolio_management
      urgency :low

      helpers ::API::Helpers::WorkItems::ShowParams
      helpers ::API::Helpers::WorkItems::CursorPagination
      helpers ::API::Helpers::WorkItems::Authorization
      helpers ::API::Helpers::WorkItems::Preloads
      helpers ::API::Helpers::WorkItems::Rendering
      helpers ::API::Helpers::WorkItems::HierarchyActions
      helpers ::API::Helpers::WorkItems::HierarchyFinders

      # Shared by the namespace, project, and group routes. The membership rules come from :admin_parent_link
      # (WorkItemPolicy), which ParentLinks services check on the parent and child. Without it, the child is
      # reported as not found.
      LIST_CHILDREN_DETAIL = "Opened child work items are listed before closed child work items, each in the order " \
        "set on the parent work item."
      ATTACH_CHILD_DETAIL = "The child work item is placed first. A work item that already has a different parent " \
        "work item is moved to this parent work item. The current user must be able to update the parent work item. " \
        "The current user must also be a member of the project or group of each work item. If not, the child work " \
        "item is not found. If the parent work item is an epic in a group, only the child work item needs that " \
        "membership."
      DETACH_CHILD_DETAIL = "The child work item is not deleted. The current user must be able to update the parent " \
        "work item. The current user must also be a member of the project or group of each work item. If not, the " \
        "child work item is not found."
      REORDER_CHILD_DETAIL = "The current user must be able to update the parent work item. The current user must " \
        "also be a member of the project or group of each work item. If not, the child work item is not found. The " \
        "work item in `move_before_id` or `move_after_id` must be another child work item of the same parent work " \
        "item that the current user can view."

      ATTACH_CHILD_FAILURE_RESPONSES = (FAILURE_RESPONSES + [
        { code: 409, message: 'Conflict - the work item is already a child work item of this parent work item' },
        {
          code: 422,
          message: 'Unprocessable entity - the hierarchy is not valid. For example, the work item types cannot be ' \
            'parent and child work items (a task cannot have child work items), the maximum depth is reached, ' \
            'the child work item is the parent work item or one of its ancestors, the parent work item is ' \
            'confidential and the child work item is not, the work items are linked as related items, ' \
            'or the parent work item already has 5,000 child work items'
        }
      ]).freeze

      DETACH_CHILD_FAILURE_RESPONSES = (FAILURE_RESPONSES + [
        { code: 422, message: 'Unprocessable entity - the child work item could not be detached' }
      ]).freeze

      REORDER_CHILD_FAILURE_RESPONSES = (FAILURE_RESPONSES + [
        { code: 422, message: 'Unprocessable entity - the child work item could not be reordered' }
      ]).freeze

      helpers do
        params :list_children_params do
          requires :work_item_iid, type: Integer, desc: 'The internal ID of the parent work item'
          use :work_items_show_params
          optional :state, type: String, values: %w[opened closed],
            desc: 'Filter child work items by state. Supported values: opened, closed.'
          use :work_items_cursor_pagination_params
        end

        params :attach_child_params do
          requires :work_item_iid, type: Integer, desc: 'The internal ID of the parent work item'
          requires :child_id, type: Integer,
            desc: 'The ID of the work item to attach as a child work item. ' \
              'The internal ID (iid) cannot be used because the child work item ' \
              'can belong to a different namespace than the parent work item.'
        end

        params :detach_child_params do
          requires :work_item_iid, type: Integer, desc: 'The internal ID of the parent work item'
          requires :child_id, type: Integer,
            desc: 'The ID of the child work item to detach from the parent work item. ' \
              'The internal ID (iid) cannot be used because the child work item ' \
              'can belong to a different namespace than the parent work item.'
        end

        params :reorder_child_params do
          requires :work_item_iid, type: Integer, desc: 'The internal ID of the parent work item'
          requires :child_id, type: Integer,
            desc: 'The ID of the child work item to reorder. ' \
              'The internal ID (iid) cannot be used because the child work item ' \
              'can belong to a different namespace than the parent work item.'
          optional :move_before_id, type: Integer,
            desc: 'The ID (not iid) of the sibling work item that should be positioned before the child work item. ' \
              'If `move_after_id` is also set, `move_after_id` is ignored.'
          optional :move_after_id, type: Integer,
            desc: 'The ID (not iid) of the sibling work item that should be positioned after the child work item.'
          at_least_one_of :move_before_id, :move_after_id
        end
      end

      resource :namespaces do
        params do
          requires :id, types: [String, Integer], desc: 'The ID or URL-encoded full path of the namespace'
        end

        namespace ':id/-/work_items', requirements: { id: FULL_PATH_ID_REQUIREMENT } do
          desc 'List child work items of a work item.' do
            detail 'This feature was introduced in GitLab 19.1. ' \
              'Get a paginated list of child work items for a work item in a namespace. ' \
              'Project and group namespaces are supported. ' \
              "#{LIST_CHILDREN_DETAIL}"
            hidden true
            success Entities::WorkItemBasic
            failure FAILURE_RESPONSES
            is_array true
            tags WORK_ITEMS_TAGS
          end
          params do
            use :list_children_params
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization,
            permissions: :read_work_item,
            boundary: -> { namespace_path_boundary },
            boundaries: [{ boundary_type: :group }, { boundary_type: :project }]
          get ':work_item_iid/children' do
            parent_work_item = work_item_for_namespace!(params[:id], params[:work_item_iid])
            render_children_for(parent_work_item)
          end

          desc 'Attach a child work item.' do
            detail 'This feature was introduced in GitLab 19.3. ' \
              'Attach an existing work item as a child work item of a work item in a namespace. ' \
              'Project and group namespaces are supported. ' \
              "#{ATTACH_CHILD_DETAIL}"
            hidden true
            success Entities::WorkItemBasic
            failure ATTACH_CHILD_FAILURE_RESPONSES
            tags WORK_ITEMS_TAGS
          end
          params do
            use :attach_child_params
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization,
            permissions: :update_work_item,
            boundary: -> { namespace_path_boundary },
            boundaries: [{ boundary_type: :group }, { boundary_type: :project }]
          post ':work_item_iid/children/:child_id' do
            resource_parent = resolve_namespace_resource_parent!(params[:id])

            attach_child_work_item!(resource_parent, params[:work_item_iid], params[:child_id])
          end

          desc 'Detach a child work item.' do
            detail 'This feature was introduced in GitLab 19.4. ' \
              'Remove a child work item from its parent work item in a namespace. ' \
              'Project and group namespaces are supported. ' \
              "#{DETACH_CHILD_DETAIL}"
            hidden true
            success code: 204
            failure DETACH_CHILD_FAILURE_RESPONSES
            tags WORK_ITEMS_TAGS
          end
          params do
            use :detach_child_params
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization,
            permissions: :update_work_item,
            boundary: -> { namespace_path_boundary },
            boundaries: [{ boundary_type: :group }, { boundary_type: :project }]
          delete ':work_item_iid/children/:child_id' do
            resource_parent = resolve_namespace_resource_parent!(params[:id])

            detach_child_work_item!(resource_parent, params[:work_item_iid], params[:child_id])
          end

          desc 'Reorder a child work item.' do
            detail 'This feature was introduced in GitLab 19.4. ' \
              'Reorder a child work item in the list of child work items of its parent work item in a namespace. ' \
              'Project and group namespaces are supported. ' \
              "#{REORDER_CHILD_DETAIL}"
            hidden true
            success Entities::WorkItemBasic
            failure REORDER_CHILD_FAILURE_RESPONSES
            tags WORK_ITEMS_TAGS
          end
          params do
            use :reorder_child_params
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization,
            permissions: :update_work_item,
            boundary: -> { namespace_path_boundary },
            boundaries: [{ boundary_type: :group }, { boundary_type: :project }]
          put ':work_item_iid/children/:child_id' do
            resource_parent = resolve_namespace_resource_parent!(params[:id])

            reorder_child_work_item!(
              resource_parent: resource_parent,
              work_item_iid: params[:work_item_iid],
              child_id: params[:child_id],
              move_before_id: params[:move_before_id],
              move_after_id: params[:move_after_id]
            )
          end
        end
      end

      resource :projects do
        params do
          requires :id, types: [String, Integer], desc: 'The ID or URL-encoded path of the project'
        end

        namespace ':id/-/work_items', requirements: { id: FULL_PATH_ID_REQUIREMENT } do
          desc 'List child work items of a work item in a project.' do
            detail 'This feature was introduced in GitLab 19.1. ' \
              'Get a paginated list of child work items for a work item in a project. ' \
              "#{LIST_CHILDREN_DETAIL}"
            hidden true
            success Entities::WorkItemBasic
            failure FAILURE_RESPONSES
            is_array true
            tags WORK_ITEMS_TAGS
          end
          params do
            use :list_children_params
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization,
            permissions: :read_work_item,
            boundary_type: :project
          get ':work_item_iid/children' do
            parent_work_item = work_item_for!(user_project, params[:work_item_iid])
            render_children_for(parent_work_item)
          end

          desc 'Attach a child work item to a work item in a project.' do
            detail 'This feature was introduced in GitLab 19.3. ' \
              'Attach an existing work item as a child work item of a work item in a project. ' \
              "#{ATTACH_CHILD_DETAIL}"
            hidden true
            success Entities::WorkItemBasic
            failure ATTACH_CHILD_FAILURE_RESPONSES
            tags WORK_ITEMS_TAGS
          end
          params do
            use :attach_child_params
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization,
            permissions: :update_work_item,
            boundary_type: :project
          post ':work_item_iid/children/:child_id' do
            project = user_project

            attach_child_work_item!(project, params[:work_item_iid], params[:child_id])
          end

          desc 'Detach a child work item from a work item in a project.' do
            detail 'This feature was introduced in GitLab 19.4. ' \
              'Remove a child work item from its parent work item in a project. ' \
              "#{DETACH_CHILD_DETAIL}"
            hidden true
            success code: 204
            failure DETACH_CHILD_FAILURE_RESPONSES
            tags WORK_ITEMS_TAGS
          end
          params do
            use :detach_child_params
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization,
            permissions: :update_work_item,
            boundary_type: :project
          delete ':work_item_iid/children/:child_id' do
            project = user_project

            detach_child_work_item!(project, params[:work_item_iid], params[:child_id])
          end

          desc 'Reorder a child work item in a project.' do
            detail 'This feature was introduced in GitLab 19.4. ' \
              'Reorder a child work item in the list of child work items of its parent work item in a project. ' \
              "#{REORDER_CHILD_DETAIL}"
            hidden true
            success Entities::WorkItemBasic
            failure REORDER_CHILD_FAILURE_RESPONSES
            tags WORK_ITEMS_TAGS
          end
          params do
            use :reorder_child_params
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization,
            permissions: :update_work_item,
            boundary_type: :project
          put ':work_item_iid/children/:child_id' do
            project = user_project

            reorder_child_work_item!(
              resource_parent: project,
              work_item_iid: params[:work_item_iid],
              child_id: params[:child_id],
              move_before_id: params[:move_before_id],
              move_after_id: params[:move_after_id]
            )
          end
        end
      end

      resource :groups do
        params do
          requires :id, types: [String, Integer], desc: 'The ID or URL-encoded path of the group'
        end

        namespace ':id/-/work_items', requirements: { id: FULL_PATH_ID_REQUIREMENT } do
          desc 'List child work items of a work item in a group.' do
            detail 'This feature was introduced in GitLab 19.1. ' \
              'Get a paginated list of child work items for a work item in a group. ' \
              "#{LIST_CHILDREN_DETAIL}"
            hidden true
            success Entities::WorkItemBasic
            failure FAILURE_RESPONSES
            is_array true
            tags WORK_ITEMS_TAGS
          end
          params do
            use :list_children_params
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization,
            permissions: :read_work_item,
            boundary_type: :group
          get ':work_item_iid/children' do
            parent_work_item = work_item_for!(find_group!(params[:id]), params[:work_item_iid])
            render_children_for(parent_work_item)
          end

          desc 'Attach a child work item to a work item in a group.' do
            detail 'This feature was introduced in GitLab 19.3. ' \
              'Attach an existing work item as a child work item of a work item in a group. ' \
              "#{ATTACH_CHILD_DETAIL}"
            hidden true
            success Entities::WorkItemBasic
            failure ATTACH_CHILD_FAILURE_RESPONSES
            tags WORK_ITEMS_TAGS
          end
          params do
            use :attach_child_params
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization,
            permissions: :update_work_item,
            boundary_type: :group
          post ':work_item_iid/children/:child_id' do
            group = find_group!(params[:id])

            attach_child_work_item!(group, params[:work_item_iid], params[:child_id])
          end

          desc 'Detach a child work item from a work item in a group.' do
            detail 'This feature was introduced in GitLab 19.4. ' \
              'Remove a child work item from its parent work item in a group. ' \
              "#{DETACH_CHILD_DETAIL}"
            hidden true
            success code: 204
            failure DETACH_CHILD_FAILURE_RESPONSES
            tags WORK_ITEMS_TAGS
          end
          params do
            use :detach_child_params
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization,
            permissions: :update_work_item,
            boundary_type: :group
          delete ':work_item_iid/children/:child_id' do
            group = find_group!(params[:id])

            detach_child_work_item!(group, params[:work_item_iid], params[:child_id])
          end

          desc 'Reorder a child work item in a group.' do
            detail 'This feature was introduced in GitLab 19.4. ' \
              'Reorder a child work item in the list of child work items of its parent work item in a group. ' \
              "#{REORDER_CHILD_DETAIL}"
            hidden true
            success Entities::WorkItemBasic
            failure REORDER_CHILD_FAILURE_RESPONSES
            tags WORK_ITEMS_TAGS
          end
          params do
            use :reorder_child_params
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization,
            permissions: :update_work_item,
            boundary_type: :group
          put ':work_item_iid/children/:child_id' do
            group = find_group!(params[:id])

            reorder_child_work_item!(
              resource_parent: group,
              work_item_iid: params[:work_item_iid],
              child_id: params[:child_id],
              move_before_id: params[:move_before_id],
              move_after_id: params[:move_after_id]
            )
          end
        end
      end
    end
  end
end

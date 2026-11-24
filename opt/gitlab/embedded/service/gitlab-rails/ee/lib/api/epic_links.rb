# frozen_string_literal: true

module API
  class EpicLinks < ::API::Base
    include ::Gitlab::Utils::StrongMemoize

    feature_category :portfolio_management
    urgency :low

    before do
      authenticate!
    end

    helpers ::API::Helpers::EpicsHelpers

    helpers do
      def child_epic
        strong_memoize(:child_epic) do
          find_epics(finder_params: { parent: epic }, children_only: true)
            .find_by_id(declared_params[:child_epic_id])
        end
      end

      def child_epics
        ::Epics::CrossHierarchyChildrenFinder.new(current_user, { parent: epic, sort: 'relative_position' })
          .execute(preload: true)
          .with_api_entity_associations_from_work_item
      end

      params :child_epic_id do
        # Unique ID should be used because epics from other groups can be assigned as child.
        requires :child_epic_id,
          type: Integer,
          desc: "Global ID of the child epic. The internal ID can't be used because internal IDs can conflict with epics from other groups.",
          documentation: { example: 1 }
      end
    end

    params do
      requires :id, type: String, desc: 'ID or URL-encoded path of the group.', documentation: { example: '1' }
      requires :epic_iid, type: Integer, desc: 'Internal ID of the epic.', documentation: { example: 1 }
    end

    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      desc 'Get related epics' do
        detail 'Lists all child epics of an epic.'
        success ::API::Entities::Epic
        is_array true
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags ['epics']
      end
      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :read_epic_link, boundary_type: :group
      get ':id/(-/)epics/:epic_iid/epics' do
        authorize_epics_feature!
        authorize_can_read!

        present child_epics, with: ::API::Entities::Epic
      end

      desc 'Relate epics' do
        detail 'Creates an association between two epics, designating one as the parent epic and the other as the child epic.'
        success ::API::Entities::Epic
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' },
          { code: 409, message: 'Conflict' }
        ]
        tags ['epics']
      end
      params do
        use :child_epic_id
      end
      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :create_epic_link, boundary_type: :group
      post ':id/(-/)epics/:epic_iid/epics/:child_epic_id' do
        authorize_create_epic_tree_relation!

        target_child_epic = Epic.find_by_id(declared_params[:child_epic_id])

        create_params = { target_issuable: target_child_epic }

        result = ::WorkItems::LegacyEpics::EpicLinks::CreateService.new(epic, current_user, create_params).execute

        if result[:status] == :success
          present child_epic, with: ::API::Entities::Epic
        else
          render_api_error!(result[:message], result[:http_status])
        end
      end

      desc 'Create and relate epic to a parent' do
        detail 'Creates a new epic and associates it with the provided parent epic.'
        success ::API::Entities::Epic
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' },
          { code: 409, message: 'Conflict' }
        ]
        tags ['epics']
      end
      params do
        requires :title, type: String, desc: 'Title of the child epic.', documentation: { example: "Epic title" }
        optional :confidential,
          type: Boolean,
          desc: 'If `true`, marks the epic as confidential. Ignored if the `confidential_epics` feature flag is disabled. Defaults to the confidentiality state of the parent epic.',
          documentation: { example: true }
      end
      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :create_epic_link, boundary_type: :group
      post ':id/(-/)epics/:epic_iid/epics' do
        authorize_can_create!
        authorize_create_epic_tree_relation!

        confidential = params[:confidential].nil? ? epic.confidential : params[:confidential]
        create_params = { parent_id: epic.id, title: params[:title], confidential: confidential }

        child_epic = ::WorkItems::LegacyEpics::CreateService.new(group: user_group, current_user: current_user,
          params: create_params).execute

        if child_epic.errors.empty? && child_epic.valid?
          present child_epic, with: ::API::Entities::LinkedEpic, user: current_user
        else
          render_validation_error!(child_epic)
        end
      end

      desc 'Remove epics relation' do
        detail 'Unassigns a child epic from a parent epic.'
        success ::API::Entities::Epic
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 404, message: 'Not found' }
        ]
        tags ['epics']
      end
      params do
        use :child_epic_id
      end
      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :delete_epic_link, boundary_type: :group
      delete ':id/(-/)epics/:epic_iid/epics/:child_epic_id' do
        authorize!(:read_epic_relation, epic)

        result = ::WorkItems::LegacyEpics::EpicLinks::DestroyService.new(child_epic, current_user).execute

        if result[:status] == :success
          present child_epic, with: ::API::Entities::Epic
        else
          render_api_error!(result[:message], result[:http_status])
        end
      end

      desc 'Reorder child epics' do
        detail 'Reorders a child epic.'
        success ::API::Entities::Epic
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 404, message: 'Not found' }
        ]
        tags ['epics']
      end
      params do
        use :child_epic_id
        optional :move_before_id,
          type: Integer,
          desc: 'ID of the epic to position before the child epic.',
          documentation: { example: 1 }
        optional :move_after_id,
          type: Integer,
          desc: 'ID of the epic to position after the child epic.',
          documentation: { example: 1 }
      end
      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :update_epic_link, boundary_type: :group
      put ':id/(-/)epics/:epic_iid/epics/:child_epic_id' do
        authorize_admin_epic_tree_relation!

        update_params = params.slice(:move_before_id, :move_after_id)

        result = ::WorkItems::LegacyEpics::EpicLinks::UpdateService.new(child_epic, current_user, update_params).execute

        if result[:status] == :success
          present child_epics, with: ::API::Entities::Epic
        else
          render_api_error!(result[:message], result[:http_status])
        end
      end
    end
  end
end

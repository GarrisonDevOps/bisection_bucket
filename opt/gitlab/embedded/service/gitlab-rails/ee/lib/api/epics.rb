# frozen_string_literal: true

module API
  class Epics < ::API::Base
    include ::API::Concerns::AiWorkflowsAccess
    include APIGuard
    include PaginationParams

    EPICS_TAG = %w[epics].freeze

    feature_category :portfolio_management

    before do
      authenticate_non_get!
      authorize_epics_feature!
    end

    allow_ai_workflows_access

    helpers ::API::Helpers::EpicsHelpers

    helpers do
      params :negatable_epic_filter_params do
        optional :labels,
          type: Array[String],
          coerce_with: ::API::Validations::Types::CommaSeparatedToArray.coerce,
          desc: 'Comma-separated list of label names.',
          documentation: { example: %w[bug reproduced] }
        optional :author_id,
          type: Integer,
          desc: 'Return epics not authored by the user with the given ID.',
          documentation: { example: 7 }
        optional :author_username,
          type: String,
          desc: 'Return epics not authored by the given username.',
          documentation: { example: 'root' }
        mutually_exclusive :author_id, :author_username
      end
    end

    params do
      requires :id, type: String, desc: 'ID or URL-encoded path of the group.'
    end

    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      [':id/epics', ':id/-/epics'].each do |path|
        desc 'List all group epics' do
          detail 'Lists all epics for a specified group and its subgroups. ' \
            'Responses are paginated and return 20 results by default.'
          success ::API::Entities::Epic
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 422, message: 'Unprocessable entity' }
          ]
          is_array true
          tags EPICS_TAG
        end
        params do
          optional :order_by,
            type: String,
            values: %w[created_at updated_at title],
            default: 'created_at',
            desc: 'Sort results by the specified field.'
          optional :sort,
            type: String,
            values: %w[asc desc],
            default: 'desc',
            desc: 'Sort results in ascending or descending order.'
          optional :search,
            type: String,
            desc: 'Search epics for text present in the title or description.',
            documentation: { example: 'title search term' }
          optional :state,
            type: String,
            values: %w[opened closed all],
            default: 'all',
            desc: 'Filter epics by state.'
          optional :author_id,
            type: Integer,
            desc: 'Return epics authored by the user with the given ID.',
            documentation: { example: 7 }
          optional :author_username,
            type: String,
            desc: 'Return epics authored by the given username.',
            documentation: { example: 'root' }
          mutually_exclusive :author_id, :author_username
          optional :labels,
            type: Array[String],
            coerce_with: Validations::Types::CommaSeparatedToArray.coerce,
            desc: 'Comma-separated list of label names. Label names from the epic group or a parent group can be used.',
            documentation: { example: %w[bug reproduced] }
          optional :with_labels_details,
            type: Boolean,
            desc: 'If `true`, the response returns more details for each label in the labels field: `name`, `color`, ' \
              '`description`, `description_html`, `text_color`.',
            default: false
          optional :created_after,
            type: DateTime,
            desc: 'Return epics created on or after the specified time.',
            documentation: { example: '2019-03-15T08:00:00Z' }
          optional :created_before,
            type: DateTime,
            desc: 'Return epics created on or before the specified time.',
            documentation: { example: '2019-03-15T08:00:00Z' }
          optional :updated_after,
            type: DateTime,
            desc: 'Return epics updated on or after the specified time.',
            documentation: { example: '2019-03-15T08:00:00Z' }
          optional :updated_before,
            type: DateTime,
            desc: 'Return epics updated on or before the specified time.',
            documentation: { example: '2019-03-15T08:00:00Z' }
          optional :include_ancestor_groups, type: Boolean, default: false,
            desc: "If `true`, includes epics from the requested group's ancestors."
          optional :include_descendant_groups,
            type: Boolean,
            default: true,
            desc: "If `true`, includes epics from the requested group's descendants."
          optional :my_reaction_emoji,
            type: String,
            desc: 'Return epics reacted to by the authenticated user with the given emoji. `None` returns epics with ' \
              'no reaction and `Any` returns epics with at least one reaction.',
            documentation: { example: 'slight_frown' }
          optional :confidential, type: Boolean, desc: 'If `true`, returns only confidential epics. If `false`, ' \
                                                   'returns only non-confidential epics.'
          use :pagination

          optional :not, type: Hash, desc: 'Return epics that do not match the specified parameters.' do
            use :negatable_epic_filter_params
          end
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_epic, boundary_type: :group
        get path, urgency: :low do
          validate_search_rate_limit! if declared_params[:search].present?
          epics = paginate(find_epics(finder_params: { group_id: user_group.id }))
            .with_api_entity_associations_from_work_item

          if declared_params[:with_labels_details]
            labels = epics.flat_map { |epic| epic.work_item.labels }.compact
            ActiveRecord::Associations::Preloader.new(records: labels, associations: [:group, { project: :group }]).call
          end

          # issuable_metadata has to be set because `Entities::Epic` doesn't inherit from `Entities::IssuableEntity`
          extra_options = {
            issuable_metadata: Gitlab::IssuableMetadata.new(current_user, epics).data,
            with_labels_details: declared_params[:with_labels_details]
          }
          present epics, **epic_options.merge(extra_options)
        end
      end

      [':id/epics/:epic_iid', ':id/-/epics/:epic_iid'].each do |path|
        desc 'Get details of an epic' do
          detail 'Gets a single epic'
          success ::API::Entities::Epic
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
          tags EPICS_TAG
        end
        params do
          requires :epic_iid, type: Integer, desc: 'Internal ID of the epic.', documentation: { example: 5 }
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_epic, boundary_type: :group
        get path, urgency: :low do
          authorize_can_read!

          present epic, **epic_options.merge(include_subscribed: true)
        end
      end

      desc 'Create a new epic' do
        detail 'Creates a new epic'
        success ::API::Entities::Epic
        failure [
          { code: 400, message: 'Bad request' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' },
          { code: 429, message: 'Too many requests' }
        ]
        tags EPICS_TAG
      end
      params do
        requires :title,
          type: String,
          desc: 'Title of the epic.',
          documentation: { example: 'My Epic' }
        optional :description,
          type: String,
          desc: 'Description of the epic.',
          documentation: { example: 'Epic description' }
        optional :color,
          type: ::Gitlab::Color,
          desc: 'Color of the epic.',
          coerce_with: ->(value) { ::Gitlab::Color.of(value) unless value.nil? },
          documentation: { example: '#1068bf' }
        optional :confidential, type: Boolean, desc: 'If `true`, the epic is confidential.'
        optional :created_at,
          type: DateTime,
          desc: 'Date and time the epic was created. Available only for administrators and project owners.',
          documentation: { example: '2016-03-11T03:45:40Z' }
        optional :start_date,
          type: String,
          desc: 'Start date of the epic. Deprecated. Use `start_date_fixed` instead.',
          documentation: { example: '2018-07-31' }
        optional :start_date_fixed,
          type: String,
          desc: 'Start date of the epic.',
          documentation: { example: '2018-07-31' }
        optional :start_date_is_fixed,
          type: Boolean,
          desc: 'If `true`, sources the start date from the `start_date_fixed` field instead of the issue milestones.'
        optional :end_date,
          type: String,
          desc: 'Due date of the epic. Deprecated. Use `due_date_fixed` instead.',
          documentation: { example: '2019-08-11' }
        optional :due_date_fixed,
          type: String,
          desc: 'Due date of the epic.',
          documentation: { example: '2019-08-11' }
        optional :due_date_is_fixed,
          type: Boolean,
          desc: 'If `true`, sources the due date from the `due_date_fixed` field instead of the issue milestones.'
        optional :labels,
          type: Array[String],
          coerce_with: Validations::Types::CommaSeparatedToArray.coerce,
          desc: 'Comma-separated list of label names. Label names from the epic group or a parent group can be used.',
          documentation: { example: %w[bug reproduced] }
        optional :parent_id,
          type: Integer,
          desc: 'ID of the parent epic.',
          documentation: { example: 12 }
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :create_epic, boundary_type: :group
      post ':id/(-/)epics' do
        authorize_can_create!

        # Setting created_at is allowed only for admins and owners
        params.delete(:created_at) unless Ability.allowed?(current_user, :set_epic_created_at, user_group)
        validator = ::Gitlab::Auth::ScopeValidator.new(current_user, Gitlab::Auth::RequestAuthenticator.new(request))
        create_params = declared_params(include_missing: false).merge(scope_validator: validator)

        # Backward compatibility for deprecated fields "start_date" and "end_date"
        create_params[:start_date_fixed] ||= create_params.delete(:start_date) if create_params.key?(:start_date)
        create_params[:due_date_fixed] ||= create_params.delete(:end_date) if create_params.key?(:end_date)

        begin
          epic = ::WorkItems::LegacyEpics::CreateService.new(
            group: user_group,
            current_user: current_user,
            params: create_params
          ).execute
        rescue QuickActions::InterpretService::QuickActionsNotAllowedError => error
          forbidden!(error.message)
        end

        if epic.errors.empty? && epic.valid?
          present epic, **epic_options
        else
          render_validation_error!(epic)
        end
      end

      desc 'Update an epic' do
        detail 'Updates an epic'
        success ::API::Entities::Epic
        failure [
          { code: 400, message: 'Bad request' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags EPICS_TAG
      end
      params do
        requires :epic_iid,
          type: Integer, desc: 'Internal ID of the epic.', documentation: { example: 5 }
        optional :title,
          type: String, desc: 'Title of the epic.', documentation: { example: 'My Epic' }
        optional :color,
          type: ::Gitlab::Color, desc: 'Color of the epic.',
          coerce_with: ->(value) { ::Gitlab::Color.of(value) unless value.nil? },
          documentation: { example: '#1068bf' }
        optional :description,
          type: String,
          desc: 'Description of the epic.',
          documentation: { example: 'Epic description' }
        optional :confidential, type: Boolean, desc: 'If `true`, the epic is confidential.'
        optional :updated_at,
          type: DateTime,
          desc: 'Date and time the epic was updated. Available only for administrators and project owners.',
          documentation: { example: '2016-03-11T03:45:40Z' }
        optional :start_date,
          type: String,
          desc: 'Start date of the epic. Deprecated. Use `start_date_fixed` instead.',
          documentation: { example: '2018-07-31' }
        optional :start_date_fixed,
          type: String,
          desc: 'Start date of the epic.',
          documentation: { example: '2018-07-31' }
        optional :start_date_is_fixed,
          type: Boolean,
          desc: 'If `true`, sources the start date from the `start_date_fixed` field instead of the issue milestones.'
        optional :end_date,
          type: String,
          desc: 'Due date of the epic. Deprecated. Use `due_date_fixed` instead.',
          documentation: { example: '2019-08-11' }
        optional :due_date_fixed,
          type: String,
          desc: 'Due date of the epic.',
          documentation: { example: '2019-08-11' }
        optional :due_date_is_fixed,
          type: Boolean,
          desc: 'If `true`, sources the due date from the `due_date_fixed` field instead of the issue milestones.'
        optional :labels,
          type: Array[String],
          coerce_with: Validations::Types::CommaSeparatedToArray.coerce,
          desc: 'Comma-separated label names for the epic.',
          documentation: { example: %w[bug reproduced] }
        optional :add_labels,
          type: Array[String],
          coerce_with: Validations::Types::CommaSeparatedToArray.coerce,
          desc: 'Comma-separated label names to add to the epic.',
          documentation: { example: 'critical,documentation' }
        optional :remove_labels,
          type: Array[String],
          coerce_with: Validations::Types::CommaSeparatedToArray.coerce,
          desc: 'Comma-separated label names to remove from the epic.',
          documentation: { example: 'documentation,enhancement' }
        optional :state_event, type: String, values: %w[reopen close], desc: 'Event to change the state of the epic.'
        optional :parent_id, type: Integer, desc: 'ID of the parent epic.', documentation: { example: 12 }
        at_least_one_of :add_labels, :color, :confidential, :description, :due_date_fixed, :due_date_is_fixed, :labels,
          :parent_id, :remove_labels, :start_date_fixed, :start_date_is_fixed, :state_event, :title,
          :start_date, :end_date
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :update_epic, boundary_type: :group
      put ':id/(-/)epics/:epic_iid', urgency: :low do
        authorize_can_update!

        # Setting updated_at is allowed only for admins and owners
        params.delete(:updated_at) unless Ability.allowed?(current_user, :set_epic_updated_at, user_group)

        update_params = declared_params(include_missing: false)
        update_params.delete(:epic_iid)

        # Backward compatibility for deprecated fields "start_date" and "end_date"
        update_params[:start_date_fixed] ||= update_params.delete(:start_date) if update_params.key?(:start_date)
        update_params[:due_date_fixed] ||= update_params.delete(:end_date) if update_params.key?(:end_date)
        validator = ::Gitlab::Auth::ScopeValidator.new(current_user, Gitlab::Auth::RequestAuthenticator.new(request))
        update_params[:scope_validator] ||= validator

        begin
          result = ::WorkItems::LegacyEpics::UpdateService.new(
            group: user_group,
            current_user: current_user,
            params: update_params
          ).execute(epic)
        rescue QuickActions::InterpretService::QuickActionsNotAllowedError => error
          forbidden!(error.message)
        end

        if result.valid?
          present result, **epic_options
        else
          render_validation_error!(result)
        end
      end

      desc 'Destroy an epic' do
        detail 'Deletes an epic'
        success code: 204
        failure [
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags EPICS_TAG
      end
      params do
        requires :epic_iid, type: Integer, desc: 'Internal ID of the epic.', documentation: { example: 5 }
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :delete_epic, boundary_type: :group
      delete ':id/(-/)epics/:epic_iid' do
        authorize_can_destroy!

        Issuable::DestroyService.new(container: nil, current_user: current_user).execute(epic)
      end
    end
  end
end

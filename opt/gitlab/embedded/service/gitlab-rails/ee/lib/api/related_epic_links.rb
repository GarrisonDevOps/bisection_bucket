# frozen_string_literal: true

# These API endpoints are used to manage the relationship between one epic with other epic
# (similar to issue links).  Note that this relation is different from existing
# API::EpicLinks (which is used for parent-child epic hierarchy).

module API
  class RelatedEpicLinks < ::API::Base
    include PaginationParams

    feature_category :portfolio_management

    helpers do
      def find_permissioned_epic!(iid, group_id: nil, permission: :admin_epic_link_relation)
        group = group_id ? find_group!(group_id) : user_group
        epic = group.epics.find_by_iid!(iid)

        authorize!(permission, epic)

        epic
      end

      def can_read_link?(link)
        source = link.source
        target = link.target

        return true if source.namespace_id == target.namespace_id &&
          !source.confidential? && !target.confidential?

        can?(current_user, :read_work_item, source) && can?(current_user, :read_work_item, target)
      end
    end

    helpers ::API::Helpers::EpicsHelpers

    before do
      authenticate_non_get!
      authorize_related_epics_feature!
      authorize_epics_feature!
    end

    params do
      requires :id,
        type: String,
        desc: 'ID or URL-encoded path of the group.',
        documentation: { example: '1' }
    end
    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      params do
        optional :updated_before,
          type: DateTime,
          desc: 'Return related epic links updated on or before the specified time.',
          documentation: { type: 'dateTime', example: '2016-01-19T09:05:50.355Z' }
        optional :updated_after,
          type: DateTime,
          desc: 'Return related epic links updated on or after the specified time.',
          documentation: { type: 'dateTime', example: '2016-01-19T09:05:50.355Z' }
        optional :created_before,
          type: DateTime,
          desc: 'Return related epic links created on or before the specified time.',
          documentation: { type: 'dateTime', example: '2016-01-19T09:05:50.355Z' }
        optional :created_after,
          type: DateTime,
          desc: 'Return related epic links created on or after the specified time.',
          documentation: { type: 'dateTime', example: '2016-01-19T09:05:50.355Z' }
        use :pagination
      end
      desc 'List all related epic links for a group' do
        detail 'Lists all related epic links for a specified group and its subgroups. The user needs to have access ' \
          'to both the `source_epic` and `target_epic` to view the related epic link.'
        success Entities::RelatedEpic
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' }
        ]
        is_array true
        tags ['epics']
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_related_epic_link, boundary_type: :group
      get ':id/related_epic_links' do
        related_links = ::WorkItems::LegacyEpics::RelatedLinksFinder
          .new(user_group, current_user: current_user, params: declared_params).execute

        related_links = paginate(related_links)

        # Links can reference epics the user has no access to (e.g. cross-group or confidential).
        # Source/target are WorkItems, so we check work item permissions.
        related_links = related_links.select { |link| can_read_link?(link) }

        source_and_target_epics = related_links.reduce(Set.new) { |acc, link| acc << link.source << link.target }
        source_and_target_epics = source_and_target_epics.map(&:synced_epic)

        epics_metadata = Gitlab::IssuableMetadata.new(current_user, source_and_target_epics).data
        present related_links, issuable_metadata: epics_metadata, with: Entities::RelatedEpicLink
      end

      desc 'List all linked epics for an epic' do
        detail 'Lists all linked epics for a specified epic.'
        success Entities::RelatedEpic
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' }
        ]
        is_array true
        tags ['epics']
      end

      params do
        requires :epic_iid, type: Integer, desc: 'Internal ID of the epic.', documentation: { example: 1 }
      end

      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_related_epic_link, boundary_type: :group
      get ':id/epics/:epic_iid/related_epics' do
        authorize_can_read!

        preload_for_collection = [:author, :sync_object, :work_item, { group: [:saml_provider, :route] }]
        related_epics = epic.related_epics(current_user, preload: preload_for_collection,
          &:with_api_entity_associations_from_work_item)

        epics_metadata = Gitlab::IssuableMetadata.new(current_user, related_epics).data
        presenter_options = epic_options(entity: Entities::RelatedEpic, issuable_metadata: epics_metadata)

        present related_epics, **presenter_options
      end

      desc 'Create a related epic link' do
        detail 'Creates a two-way relation between two epics. The user must have the Guest, Planner, Reporter, ' \
          'Developer, Maintainer, or Owner role for both groups.'
        success Entities::RelatedEpicLink
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 404, message: 'Not found' },
          { code: 409, message: 'Conflict' },
          { code: 422, message: 'Unprocessable entity' }
        ]
        tags ['epics']
      end
      params do
        requires :target_group_id,
          type: String,
          desc: 'ID or URL-encoded path of the target group.',
          documentation: { example: '1' }
        requires :target_epic_iid,
          type: Integer,
          desc: "Internal ID of the target group's epic.",
          documentation: { example: 1 }
        optional :link_type,
          type: String,
          values: ::Epic::RelatedEpicLink.available_link_types,
          desc: 'Type of the relation. Defaults to `relates_to`.',
          documentation: { example: 'relates_to' }
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :create_related_epic_link, boundary_type: :group
      post ':id/epics/:epic_iid/related_epics' do
        source_epic = find_permissioned_epic!(params[:epic_iid])
        target_epic = find_permissioned_epic!(
          declared_params[:target_epic_iid],
          group_id: declared_params[:target_group_id],
          permission: :read_epic_link_relation
        )

        create_params = { target_issuable: target_epic, link_type: declared_params[:link_type] }

        result = ::WorkItems::LegacyEpics::RelatedEpicLinks::CreateService
                   .new(source_epic, current_user, create_params)
                   .execute

        if result[:status] == :success
          # If status is success, there should be always a created link, so
          # we can rely on it.
          present result[:created_references].first, with: Entities::RelatedEpicLink
        else
          render_api_error!(result[:message], result[:http_status])
        end
      end

      desc 'Delete a related epic link' do
        detail 'Deletes a two-way relation between two specified epics. The user must have the Guest, Planner, ' \
          'Reporter, Developer, Maintainer, or Owner role for both groups.'
        success Entities::RelatedEpicLink
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags ['epics']
      end
      params do
        requires :related_epic_link_id,
          type: Integer,
          desc: 'ID of the related epic link.',
          documentation: { example: 1 }
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :delete_related_epic_link, boundary_type: :group
      delete ':id/epics/:epic_iid/related_epics/:related_epic_link_id' do
        epic = find_permissioned_epic!(params[:epic_iid])
        epic_link = ::Epic::RelatedEpicLink
          .for_source_or_target(epic)
          .find(declared_params[:related_epic_link_id])

        result = ::WorkItems::LegacyEpics::RelatedEpicLinks::DestroyService
          .new(epic_link, epic, current_user)
          .execute

        if result[:status] == :success
          present epic_link, with: Entities::RelatedEpicLink
        else
          render_api_error!(result[:message], result[:http_status])
        end
      end
    end
  end
end

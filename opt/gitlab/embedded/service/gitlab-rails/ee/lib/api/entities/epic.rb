# frozen_string_literal: true

module API
  module Entities
    class Epic < Grape::Entity
      include ::API::Helpers::RelatedResourcesHelpers
      include ::API::Helpers::Presentable

      expose :id, documentation: { type: 'Integer', format: 'int64', example: 123 }
      expose :work_item_id, documentation: {
        type: 'Integer', example: 123, documentation: "ID of the corresponding work item for a legacy epic"
      }
      expose :iid, documentation: { type: 'Integer', example: 123 } do |_epic|
        epic_view.iid
      end

      expose :color, documentation: { type: 'String', example: "#1068bf" } do |_epic|
        epic_view.color
      end

      expose :text_color, documentation: { type: 'String', example: "#1068bf" } do |_epic|
        epic_view.text_color
      end

      expose :group_id, documentation: { type: 'Integer', format: 'int64', example: 17 } do |_epic|
        epic_view.group_id
      end

      expose :parent_id, documentation: { type: 'Integer', format: 'int64', example: 12 } do |_epic|
        epic_view.parent_id
      end

      expose :parent_iid, documentation: { type: 'Integer', example: 19 } do |_epic|
        epic_view.parent_iid
      end

      expose :imported?, as: :imported, documentation: { type: 'Boolean', example: false } do |_epic|
        epic_view.imported?
      end

      expose :imported_from, documentation: { type: 'String', example: "github" } do |_epic|
        epic_view.imported_from
      end

      expose :title, documentation: { type: 'String', example: "My Epic" } do |_epic|
        epic_view.title
      end

      expose :description, documentation: { type: 'String', example: "Epic description" } do |_epic|
        epic_view.description
      end

      expose :confidential, documentation: { type: 'Boolean', example: false } do |_epic|
        epic_view.confidential
      end

      expose :author, using: ::API::Entities::UserBasic do |_epic|
        epic_view.author
      end

      expose :start_date, documentation: { type: 'DateTime', example: "2022-01-31T15:10:45.080Z" } do |_epic|
        epic_view.start_date
      end

      expose :start_date_is_fixed?,
        as: :start_date_is_fixed,
        documentation: { type: 'Boolean', example: true } do |_epic|
        epic_view.start_date_is_fixed?
      end

      expose :start_date_fixed,
        documentation: { type: 'DateTime', example: "2022-01-31T15:10:45.080Z" } do |_epic|
        epic_view.start_date_fixed
      end

      expose :start_date_from_inherited_source,
        documentation: { type: 'DateTime', example: "2022-01-31T15:10:45.080Z" } do |_epic|
        epic_view.start_date_from_inherited_source&.iso8601
      end

      expose :start_date_from_milestones, # @deprecated in favor of start_date_from_inherited_source
        documentation: { type: 'DateTime', example: "2022-01-31T15:10:45.080Z" } do |_epic|
        epic_view.start_date_from_milestones&.iso8601
      end

      expose :end_date, # @deprecated in favor of due_date
        documentation: { type: "DateTime", example: "2022-01-31T15:10:45.080Z" } do |_epic|
        epic_view.due_date
      end

      expose :end_date,
        as: :due_date,
        documentation: { type: "DateTime", example: "2022-01-31T15:10:45.080Z" } do |_epic|
        epic_view.due_date
      end

      expose :due_date_is_fixed?,
        as: :due_date_is_fixed,
        documentation: { type: 'Boolean', example: true } do |_epic|
        epic_view.due_date_is_fixed?
      end

      expose :due_date_fixed,
        documentation: { type: 'DateTime', example: "2022-01-31T15:10:45.080Z" } do |_epic|
        epic_view.due_date_fixed
      end

      expose :due_date_from_inherited_source,
        documentation: { type: 'DateTime', example: "2022-01-31T15:10:45.080Z" } do |_epic|
        epic_view.due_date_from_inherited_source&.iso8601
      end

      expose :due_date_from_milestones, # @deprecated in favor of due_date_from_inherited_source
        documentation: { type: 'DateTime', example: "2022-01-31T15:10:45.080Z" } do |_epic|
        epic_view.due_date_from_milestones&.iso8601
      end

      expose :state, documentation: { type: 'String', example: "opened" } do |_epic|
        epic_view.state
      end
      expose :web_edit_url, # @deprecated
        documentation: { type: 'String', example: "http://gitlab.example.com/groups/test/-/epics/4/edit" }
      expose :web_url, documentation: { type: 'String', example: "http://gitlab.example.com/groups/test/-/epics/4" }
      expose :references, documentation: { type: 'Hash', is_array: true } do |epic, options|
        ::API::Entities::IssuableReferences.represent(epic, group: options[:user_group])
      end
      # reference is deprecated in favour of references
      # Introduced [Gitlab 12.6](https://gitlab.com/gitlab-org/gitlab/merge_requests/20354)
      expose :reference, documentation: { type: 'String', example: '&1' }, if: { with_reference: true } do |_epic|
        epic_view.to_reference(full: true)
      end
      expose :created_at, documentation: { type: 'DateTime', example: "2022-01-31T15:10:45.080Z" } do |_epic|
        epic_view.created_at
      end

      expose :updated_at, documentation: { type: 'DateTime', example: "2022-01-31T15:10:45.080Z" } do |_epic|
        epic_view.updated_at
      end

      expose :closed_at, documentation: { type: 'DateTime', example: "2022-01-31T15:10:45.080Z" } do |_epic|
        epic_view.closed_at
      end
      expose :labels, documentation: { type: 'String', is_array: true } do |_epic, options|
        labels = epic_view.labels.sort_by(&:title)

        options[:with_labels_details] ? ::API::Entities::LabelBasic.represent(labels) : labels.map(&:title)
      end
      expose :upvotes, documentation: { type: 'Integer', example: 4 } do |epic, options|
        if options[:issuable_metadata]
          # Avoids an N+1 query when metadata is included
          options[:issuable_metadata][epic.id].upvotes
        else
          epic_view.upvotes
        end
      end
      expose :downvotes, documentation: { type: 'Integer', example: 3 } do |epic, options|
        if options[:issuable_metadata]
          # Avoids an N+1 query when metadata is included
          options[:issuable_metadata][epic.id].downvotes
        else
          epic_view.downvotes
        end
      end

      # Calculating the value of subscribed field triggers Markdown
      # processing. We can't do that for multiple epics
      # requests in a single API request.
      expose :subscribed?,
        as: :subscribed,
        documentation: { type: 'Boolean', example: true },
        if: ->(_, options) { options.fetch(:include_subscribed, false) }

      def epic_view
        @epic_view ||= ::WorkItems::LegacyEpics::WorkItemAsEpic.new(object.work_item)
      end

      def web_url
        epic_view.web_url
      end

      def web_edit_url
        epic_view.web_edit_url
      end

      expose :_links, documentation: { type: 'Hash' } do
        expose :self,
          documentation: {
            type: 'String',
            example: "http://gitlab.example.com/api/v4/groups/7/epics/5"
          } do |_epic|
            expose_url(api_v4_groups_epics_path(id: epic_view.group_id, epic_iid: epic_view.iid))
          end

        expose :epic_issues,
          documentation: {
            type: 'String',
            example: "http://gitlab.example.com/api/v4/groups/7/epics/5/issues"
          } do |_epic|
            expose_url(api_v4_groups_epics_issues_path(id: epic_view.group_id, epic_iid: epic_view.iid))
          end

        expose :group,
          documentation: {
            type: 'String',
            example: "http://gitlab.example.com/api/v4/groups/7"
          } do |_epic|
            expose_url(api_v4_groups_path(id: epic_view.group_id))
          end

        expose :parent,
          documentation: {
            type: 'String',
            example: "http://gitlab.example.com/api/v4/groups/7/epics/4"
          } do |_epic|
            if epic_view.has_parent?
              expose_url(api_v4_groups_epics_path(id: epic_view.parent_group_id, epic_iid: epic_view.parent_iid))
            end
          end
      end
    end
  end
end

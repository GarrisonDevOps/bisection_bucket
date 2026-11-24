# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class WorkItemReference < Grape::Entity
          expose :id,
            documentation: { type: 'Integer', example: 1, desc: 'ID of the work item, unique across the instance.' }

          expose :global_id,
            documentation: {
              type: 'String', example: 'gid://gitlab/WorkItem/1',
              desc: 'Global ID of the work item, as used by the GraphQL API.'
            } do |work_item|
            work_item.to_gid.to_s
          end

          expose :iid,
            documentation: {
              type: 'Integer', example: 42,
              desc: 'Internal ID of the work item, unique within its project or group. Used in work item URLs.'
            }

          expose :title,
            documentation: { type: 'String', example: 'Plan first milestone', desc: 'Title of the work item.' }

          expose :title_html,
            documentation: {
              type: 'String', example: '<p>Plan first milestone</p>', desc: 'Title of the work item rendered as HTML.'
            } do |work_item, options|
            MarkupHelper.markdown_field(work_item, :title, current_user: options[:current_user])
          end

          expose :state,
            documentation: { type: 'String', example: 'opened', desc: 'State of the work item: `opened` or `closed`.' }

          expose :confidential,
            documentation: {
              type: 'Boolean', example: false,
              desc: 'Whether the work item is confidential. Confidential work items are visible only to the ' \
                'author, assignees, and members with the Planner, Reporter, Security Manager, Developer, ' \
                'Maintainer, or Owner role.'
            }

          expose :work_item_type,
            using: ::API::Entities::WorkItems::Type,
            documentation: {
              type: 'Entities::WorkItems::Type', desc: 'Type of the work item, for example issue, task, or epic.'
            },
            expose_nil: true

          expose :reference,
            documentation: {
              type: 'String', example: 'gitlab-org/example#42',
              desc: 'Full reference of the work item, including the path of its project or group.'
            } do |work_item|
            work_item.to_reference(full: true)
          end

          expose :web_url,
            documentation: {
              type: 'String',
              example: 'https://gitlab.example.com/groups/example/-/work_items/42',
              desc: 'URL of the work item.'
            } do |work_item|
            Gitlab::UrlBuilder.build(work_item)
          end

          expose :web_path,
            documentation: {
              type: 'String', example: '/groups/example/-/work_items/42',
              desc: 'Path of the work item, without the GitLab host.'
            } do |work_item|
            Gitlab::UrlBuilder.build(work_item, only_path: true)
          end
        end
      end
    end
  end
end

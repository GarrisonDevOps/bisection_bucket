# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module BasicFields
        extend ActiveSupport::Concern

        included do
          include ::API::Entities::WorkItems::ConditionalExposureHelpers
          include ::Gitlab::Utils::StrongMemoize

          expose :id, documentation: {
            type: 'Integer', format: 'int64', example: 1, desc: 'ID of the work item, unique across the instance.'
          }
          expose :global_id,
            documentation: {
              type: 'String', example: 'gid://gitlab/WorkItem/1',
              desc: 'Global ID of the work item, as used by the GraphQL API.'
            } do |work_item|
            work_item.to_gid.to_s
          end
          expose :iid,
            documentation: {
              type: 'Integer', example: 1,
              desc: 'Internal ID of the work item, unique within its project or group. Used in work item URLs.'
            }
          expose :title, documentation: { type: 'String', example: 'Fix the bug' }
          expose_field :state,
            documentation: { type: 'String', example: 'opened', desc: 'State of the work item: `opened` or `closed`.' }
          expose_field :confidential,
            documentation: {
              type: 'Boolean', example: false,
              desc: 'Whether the work item is confidential. Confidential work items are visible only to the ' \
                'author, assignees, and members with the Planner, Reporter, Security Manager, Developer, ' \
                'Maintainer, or Owner role.'
            }
          expose_field :imported?, as: :imported,
            documentation: { type: 'Boolean', example: false, desc: 'Whether the work item was created by an import.' }
          expose_field :hidden?, as: :hidden,
            documentation: {
              type: 'Boolean', example: false, desc: 'Whether the work item is hidden because its author is banned.'
            }
          expose_field :lock_version,
            documentation: {
              type: 'Integer', example: 0,
              desc: 'Lock version of the work item. Incremented each time the work item is updated.'
            }
          expose_field :created_at,
            documentation: { type: 'DateTime', example: '2022-08-17T12:46:35.053Z' }
          expose_field :updated_at,
            documentation: { type: 'DateTime', example: '2022-11-14T17:22:01.470Z' }
          expose_field :closed_at,
            documentation: {
              type: 'DateTime', example: '2022-11-15T08:30:55.232Z',
              desc: 'Time the work item was closed. Null if the work item is open.'
            },
            expose_nil: true
          expose_field :title_html,
            documentation: {
              type: 'String', example: '<p>Fix the bug</p>', desc: 'Title of the work item rendered as HTML.'
            },
            expose_nil: true do |work_item, options|
            MarkupHelper.markdown_field(work_item, :title, current_user: options[:current_user])
          end

          expose_field :author,
            using: ::API::Entities::WorkItems::Author,
            documentation: { type: 'Entities::WorkItems::Author' }

          expose_field :external_author,
            documentation: {
              type: 'String', example: 'user@example.com',
              desc: 'Email address of the non-GitLab user who created the work item through Service Desk. ' \
                'Obfuscated for users without at least the Reporter role. Null if not created through Service Desk.'
            },
            expose_nil: true do |_work_item|
            work_item_presenter.external_author
          end

          expose_field :closed_by,
            using: ::API::Entities::WorkItems::Author,
            documentation: {
              type: 'Entities::WorkItems::Author',
              desc: 'User who closed the work item. Null if the work item is open or the user is unknown.'
            },
            expose_nil: true

          expose_field :work_item_type, as: :work_item_type, using: ::API::Entities::WorkItems::Type,
            documentation: {
              type: 'Entities::WorkItems::Type', desc: 'Type of the work item, for example issue, task, or epic.'
            },
            expose_nil: true do |work_item, _options|
            work_item.work_item_type
          end

          expose_field :namespace,
            using: ::API::Entities::NamespaceBasic,
            documentation: {
              type: 'Entities::NamespaceBasic', desc: 'Project or group namespace the work item belongs to.'
            }

          expose_field :create_note_email,
            documentation: {
              type: 'String', example: 'issue-1@example.com',
              desc: 'Email address the current user can send email to, in order to add a comment to the work item. ' \
                'Null if adding comments by email is not available, for example for work items in groups, ' \
                'when the token does not have the `api` scope, or when a fine-grained personal access token ' \
                'cannot create work items in the project.'
            },
            expose_nil: true do |work_item, options|
            scope_validator = options[:scope_validator]

            next if scope_validator && !scope_validator.valid_for?([:api])

            if options[:granular_token] || (token = options[:access_token]).try(:granular?)
              boundary = ::Authz::Boundary.for(work_item.project)
              next unless token.permitted_for_boundary?(boundary, :create_issue_note)
            end

            work_item.creatable_note_email_address(options[:current_user])
          end

          expose_field :duplicated_to_work_item_url,
            documentation: {
              type: 'String', example: 'https://gitlab.example.com/groups/gitlab-org/-/work_items/2',
              desc: 'URL of the work item this work item was marked as a duplicate of. ' \
                'Null if it is not a duplicate, or if the current user cannot view that work item.'
            },
            expose_nil: true do |_work_item|
            work_item_presenter.duplicated_to_work_item_url
          end

          expose_field :moved_to_work_item_url,
            documentation: {
              type: 'String', example: 'https://gitlab.example.com/groups/gitlab-org/-/work_items/3',
              desc: 'URL of the work item this work item was moved to. ' \
                'Null if it was not moved, or if the current user cannot view that work item.'
            },
            expose_nil: true do |_work_item|
            work_item_presenter.moved_to_work_item_url
          end

          expose_field :moved_to_id,
            documentation: { type: 'Integer', format: 'int64', example: 3 },
            expose_nil: true do |_work_item|
            work_item_presenter.moved_to_work_item_id
          end

          expose_field :reference,
            documentation: {
              type: 'String', example: 'gitlab-org#1',
              desc: 'Full reference of the work item, including the path of its project or group.'
            } do |work_item|
            work_item.to_reference(full: true)
          end

          expose_field :web_url,
            documentation: {
              type: 'String', example: 'https://gitlab.example.com/groups/gitlab-org/-/work_items/1',
              desc: 'URL of the work item.'
            },
            if: ->(_work_item, options) { options.fetch(:include_web_url, true) } do |work_item|
            Gitlab::UrlBuilder.build(work_item)
          end

          expose_field :web_path,
            documentation: {
              type: 'String', example: '/groups/gitlab-org/-/work_items/1',
              desc: 'Path of the work item, without the GitLab host.'
            },
            if: ->(_work_item, options) { options.fetch(:include_web_path, true) } do |work_item|
            Gitlab::UrlBuilder.build(work_item, only_path: true)
          end

          expose_field :user_permissions,
            using: ::API::Entities::WorkItems::Permissions,
            documentation: {
              type: 'Entities::WorkItems::Permissions',
              desc: 'Actions the current user can perform on the work item. ' \
                "Does not take the token's scopes or permissions into account. For example, a token with only the " \
                '`read_api` scope can show `update_work_item: true`, but cannot update the work item.'
            } do |work_item|
            work_item
          end

          expose_field :user_discussions_count,
            documentation: {
              type: 'Integer', example: 3, desc: 'Number of discussions on the work item, not counting system notes.'
            } do |work_item, options|
            options[:user_discussions_counts]&.fetch(work_item.id, 0) || 0
          end

          # Reads parent links regardless of the current user's access to each child, like GraphQL's
          # `hasChildren`, so GET /work_items/:iid/children may still return nothing.
          expose_field :has_children,
            documentation: {
              type: 'Boolean', example: true,
              desc: 'Whether the work item has child items. ' \
                'Can be `true` when the current user cannot view any of the children.'
            } do |work_item, options|
            options[:parent_ids_with_children]&.include?(work_item.id) || false
          end

          strong_memoize_attr :work_item_presenter
        end

        private

        def work_item_presenter
          WorkItemPresenter.new(object, current_user: current_user)
        end

        def current_user
          options[:current_user]
        end
      end
    end
  end
end

# frozen_string_literal: true

module API
  module Entities
    class MergeRequestBasic < IssuableEntity
      # Deprecated in favour of merge_user
      expose :merged_by, using: ::API::Entities::UserBasic,
        documentation: {
          type: '::API::Entities::UserBasic',
          desc: 'User who merged the merge request or set it to auto-merge. Deprecated. Use `merge_user` instead.'
        } do |merge_request, _options|
        merge_request.metrics&.merged_by
      end
      expose :merge_user, using: ::API::Entities::UserBasic,
        documentation: {
          type: '::API::Entities::UserBasic',
          desc: 'User who merged the merge request or set it to auto-merge, or `null`.'
        } do |merge_request|
        merge_request.metrics&.merged_by || merge_request.merge_user
      end
      expose :merged_at,
        documentation: {
          type: 'DateTime', example: '2022-01-31T15:10:45.080Z', desc: 'Timestamp of when the merge request was merged.'
        } do |merge_request, _options|
        merge_request.metrics&.merged_at
      end
      expose :closed_by, using: ::API::Entities::UserBasic,
        documentation: {
          type: '::API::Entities::UserBasic',
          desc: 'User who closed the merge request. `null` if the merge request is not closed.'
        } do |merge_request, _options|
        merge_request.metrics&.latest_closed_by
      end
      expose :closed_at,
        documentation: {
          type: 'DateTime', example: '2022-01-31T15:10:45.080Z', desc: 'Timestamp of when the merge request was closed.'
        } do |merge_request, _options|
        merge_request.metrics&.latest_closed_at
      end
      expose :title_html,
        documentation: {
          type: 'String', desc: 'Title of the merge request rendered as HTML. Returned only if `render_html` is `true`.'
        },
        if: ->(_, options) { options[:render_html] } do |entity|
        MarkupHelper.markdown_field(entity, :title)
      end
      expose :description_html,
        documentation: {
          type: 'String',
          desc: 'Description of the merge request rendered as HTML. Returned only if `render_html` is `true`.'
        },
        if: ->(_, options) {
          options[:render_html]
        } do |entity|
        MarkupHelper.markdown_field(entity, :description)
      end
      expose :target_branch, documentation: { type: 'String', desc: 'Name of the target branch.' }
      expose :source_branch, documentation: { type: 'String', desc: 'Name of the source branch.' }
      expose(:user_notes_count,
        documentation: { type: 'Integer',
                         desc: 'Number of user comments on the merge request.' }) do |merge_request, options|
        issuable_metadata.user_notes_count
      end
      expose(:upvotes,
        documentation: { type: 'Integer',
                         desc: 'Number of upvotes for the merge request.' }) do |merge_request, options|
        issuable_metadata.upvotes
      end
      expose(:downvotes,
        documentation: { type: 'Integer',
                         desc: 'Number of downvotes for the merge request.' }) do |merge_request, options|
        issuable_metadata.downvotes
      end

      expose :author, using: ::API::Entities::MergeRequestAuthor,
        documentation: { type: '::API::Entities::MergeRequestAuthor', desc: 'User who created the merge request.' }
      expose :assignees, using: ::API::Entities::UserBasic,
        documentation: {
          type: '::API::Entities::UserBasic', is_array: true, desc: 'Users assigned to the merge request.'
        }
      expose :assignee, using: ::API::Entities::UserBasic,
        documentation: {
          type: '::API::Entities::UserBasic',
          desc: 'First user assigned to the merge request. Deprecated. Use `assignees` instead.'
        }
      expose :reviewers, using: ::API::Entities::UserBasic,
        documentation: { type: '::API::Entities::UserBasic', is_array: true, desc: 'Reviewers of the merge request.' }
      expose :source_project_id,
        documentation: {
          type: 'Integer', format: 'int64',
          desc: 'ID of the source project. Equal to `target_project_id`, unless the merge request comes from a fork.'
        }
      expose :target_project_id, documentation: { type: 'Integer', format: 'int64', desc: 'ID of the target project.' }
      expose :labels,
        documentation: {
          type: 'String', is_array: true,
          desc: 'Names of the labels assigned to the merge request, sorted by name. If `with_labels_details` is ' \
            '`true`, an array of label objects with `id`, `name`, `color`, `text_color`, `description`, ' \
            '`description_html` and `archived` instead.'
        } do |merge_request, options|
        if options[:with_labels_details]
          ::API::Entities::LabelBasic.represent(merge_request.labels.sort_by(&:title))
        else
          merge_request.labels.map(&:title).sort
        end
      end
      expose :draft?, as: :draft, documentation: { type: 'Boolean', desc: 'If `true`, the merge request is a draft.' }
      expose :imported?, as: :imported,
        documentation: { type: 'Boolean', desc: 'If `true`, the merge request was imported.' }
      expose :imported_from,
        documentation: { type: 'String', example: 'bitbucket', desc: 'Source of the import, such as `bitbucket`.' }

      # [Deprecated]  see draft
      #
      expose :draft?, as: :work_in_progress,
        documentation: {
          type: 'Boolean', desc: 'If `true`, the merge request is a draft. Deprecated. Use `draft` instead.'
        }
      expose :milestone, using: ::API::Entities::Milestone,
        documentation: { type: '::API::Entities::Milestone', desc: 'Milestone assigned to the merge request.' }
      expose :merge_when_pipeline_succeeds,
        documentation: { type: 'Boolean', desc: 'If `true`, the merge request is set to auto-merge.' }

      # Ideally we should deprecate `MergeRequest#merge_status` exposure and
      # use `MergeRequest#mergeable?` instead (boolean).
      # See https://gitlab.com/gitlab-org/gitlab-foss/issues/42344 for more
      # information.
      #
      # For list endpoints, we skip the recheck by default, since it's expensive
      expose :merge_status,
        documentation: {
          type: 'String', example: 'unchecked',
          desc: 'Status of the merge request. Can be `unchecked`, `checking`, `can_be_merged`, `cannot_be_merged` ' \
            'or `cannot_be_merged_recheck`. Affects `has_conflicts`. Deprecated. Use `detailed_merge_status` instead.'
        } do |merge_request, options|
        if !options[:skip_merge_status_recheck] && can_check_mergeability?(merge_request.project)
          merge_request.check_mergeability(async: true)
        end

        merge_request.public_merge_status
      end
      expose :detailed_merge_status,
        documentation: {
          type: 'String', example: 'mergeable',
          desc: 'Detailed merge status of the merge request. Accounts for every check that can block a merge. ' \
            'Can be `approvals_syncing` (approvals are syncing), ' \
            '`checking` (Git is testing whether a valid merge is possible), ' \
            '`ci_must_pass` (a CI/CD pipeline must succeed before merge), ' \
            '`ci_still_running` (a CI/CD pipeline is still running), ' \
            '`commits_status` (the source branch must exist and contain commits), ' \
            '`conflict` (conflicts exist between the source and target branches), ' \
            '`discussions_not_resolved` (all discussions must be resolved before merge), ' \
            '`draft_status` (the merge request is a draft), ' \
            '`jira_association_missing` (the title or description must reference a Jira issue), ' \
            '`locked_lfs_files` (LFS files locked by other users must be unlocked before merge), ' \
            '`locked_paths` (paths locked by other users must be unlocked before merging to the default branch), ' \
            '`merge_request_blocked` (blocked by another merge request), ' \
            '`merge_time` (cannot be merged until after the specified time), ' \
            '`mergeable` (the branch can merge cleanly into the target branch), ' \
            '`need_rebase` (the merge request must be rebased), ' \
            '`not_approved` (approval is required before merge), ' \
            '`not_open` (the merge request must be open before merge), ' \
            '`preparing` (the merge request diff is being created), ' \
            '`requested_changes` (reviewers have requested changes), ' \
            '`security_policy_pipeline_check` (when security policies are enforced, all pipelines for the ' \
            'latest commit must succeed before merge), ' \
            '`security_policy_violations` (all security policies must be satisfied), ' \
            '`status_checks_must_pass` (all status checks must pass before merge), ' \
            '`title_regex` (the title must match the regular expression set in the project settings), ' \
            'or `unchecked` (Git has not yet tested whether a valid merge is possible).'
        }

      expose :merge_after,
        documentation: {
          type: 'DateTime', example: '2022-01-31T15:10:45.080Z',
          desc: 'If set, timestamp after which the merge request can be merged. ' \
            '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/510992) in GitLab 17.8.'
        } do |merge_request, _options|
        merge_request.merge_schedule&.merge_after
      end

      expose :diff_head_sha, as: :sha,
        documentation: { type: 'String', example: '1234abcd', desc: 'SHA of the head commit of the source branch.' }
      expose :merge_commit_sha,
        documentation: {
          type: 'String', example: '1234abcd',
          desc: 'SHA of the merge commit. `null` until the merge request is merged.'
        }
      expose :squash_commit_sha,
        documentation: {
          type: 'String', example: '1234abcd',
          desc: 'SHA of the squash commit. Empty until the merge request is merged.'
        }
      expose :discussion_locked,
        documentation: {
          type: 'Boolean',
          desc: 'If `true`, discussions are locked. Only project members can add, edit or resolve comments in ' \
            'locked discussions.'
        }
      expose :should_remove_source_branch?, as: :should_remove_source_branch,
        documentation: { type: 'Boolean', desc: 'If `true`, the source branch is deleted after merge.' }
      expose :force_remove_source_branch?, as: :force_remove_source_branch,
        documentation: { type: 'Boolean', desc: 'If `true`, the source branch is forced to be deleted after merge.' }
      expose :prepared_at,
        documentation: {
          type: 'DateTime', example: '2022-01-31T15:10:45.080Z',
          desc: 'Timestamp of when the merge request was prepared. Set one time, after the diff is created, ' \
            'pipeline creation and the mergeability check are started, Git LFS objects are linked, and ' \
            'notifications are sent. Not updated when more changes are added.'
        }

      with_options if: ->(merge_request, _) { merge_request.for_fork? } do
        expose :allow_collaboration,
          documentation: {
            type: 'Boolean',
            desc: 'If `true`, the fork allows commits from members who can merge to the target branch. ' \
              'Returned only for merge requests from forks.'
          }
        # Deprecated
        expose :allow_collaboration, as: :allow_maintainer_to_push,
          documentation: {
            type: 'Boolean',
            desc: 'Returned only for merge requests from forks. Deprecated. Use `allow_collaboration` instead.'
          }
      end

      # reference is deprecated in favour of references
      # Introduced [Gitlab 12.6](https://gitlab.com/gitlab-org/gitlab/merge_requests/20354)
      expose :reference,
        documentation: {
          type: 'String', example: '!1',
          desc: 'Internal reference of the merge request, in short format. Deprecated. Use `references` instead.'
        } do |merge_request, options|
        merge_request.to_reference(options[:project])
      end

      expose :references,
        documentation: {
          type: 'Hash',
          desc: 'Internal references of the merge request: `short`, `relative` and `full`. When fetched from the ' \
            'project of the merge request, `relative` matches `short`. When fetched from a project or group in ' \
            'another namespace, `relative` matches `full`.'
        },
        with: IssuableReferences do |merge_request|
        merge_request
      end

      expose :web_url,
        documentation: {
          type: 'String',
          example: 'https://gitlab.example.com/my-group/my-project/-/merge_requests/1',
          desc: 'Web URL of the merge request.'
        } do |merge_request|
        Gitlab::UrlBuilder.build(merge_request)
      end

      expose :time_stats, using: ::API::Entities::IssuableTimeStats,
        documentation: {
          type: '::API::Entities::IssuableTimeStats',
          desc: 'Time tracking statistics of the merge request: `time_estimate`, `total_time_spent`, ' \
            '`human_time_estimate` and `human_total_time_spent`.'
        } do |merge_request|
        merge_request
      end

      expose :squash,
        documentation: {
          type: 'Boolean',
          desc: 'If `true`, squash commits when merging. Project squash settings can override this value. ' \
            'Use `squash_on_merge` to take them into account.'
        }
      expose :squash_on_merge?, as: :squash_on_merge,
        documentation: { type: 'Boolean', desc: 'If `true`, commits are squashed on merge.' }
      expose :task_completion_status,
        using: ::API::Entities::TaskCompletionStatus,
        documentation: {
          type: 'Entities::TaskCompletionStatus',
          desc: 'Completion status of the task list: `count` and `completed_count`.'
        }

      # #cannot_be_merged? is generally indicative of conflicts, and is set via
      #   MergeRequests::MergeabilityCheckService. However, it can also indicate
      #   that either #has_no_commits? or #branch_missing? are true.
      #
      expose :cannot_be_merged?, as: :has_conflicts,
        documentation: {
          type: 'Boolean',
          desc: 'If `true`, the merge request has conflicts and cannot merge. `false` unless `merge_status` is ' \
            '`cannot_be_merged`.'
        }
      expose :mergeable_discussions_state?, as: :blocking_discussions_resolved,
        documentation: {
          type: 'Boolean',
          desc: 'If `true`, no unresolved threads block the merge. Always `true` if the project does not ' \
            'require all threads to be resolved before merge.'
        }

      private

      def detailed_merge_status
        ::MergeRequests::Mergeability::DetailedMergeStatusService.new(
          merge_request: object,
          batched_branch_heads: options[:batched_branch_heads]
        ).execute
      end

      def can_check_mergeability?(project)
        Ability.allowed?(options[:current_user], :update_merge_request, project)
      end
    end
  end
end

API::Entities::MergeRequestBasic.prepend_mod_with('API::Entities::MergeRequestBasic', with_descendants: true)

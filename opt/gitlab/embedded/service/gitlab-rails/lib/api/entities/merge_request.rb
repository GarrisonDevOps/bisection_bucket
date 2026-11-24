# frozen_string_literal: true

module API
  module Entities
    class MergeRequest < MergeRequestBasic
      expose :subscribed,
        documentation: {
          type: 'Boolean', desc: 'If `true`, the current user is subscribed to the merge request.'
        },
        if: ->(_, options) { options.fetch(:include_subscribed, true) } do |merge_request, options|
        merge_request.subscribed?(options[:current_user], options[:project])
      end

      expose :changes_count,
        documentation: {
          type: 'String', example: '1',
          desc: 'Number of changed files in the merge request, as a string. Empty when the merge request is ' \
            'created, and populates asynchronously. When the diff exceeds the file limit, the value is the ' \
            'limit followed by `+`, like `"1000+"`.'
        } do |merge_request, _options|
        merge_request.merge_request_diff.real_size
      end

      expose :latest_build_started_at,
        documentation: {
          type: 'DateTime', example: '2022-01-31T15:10:45.080Z',
          desc: 'Timestamp of when the latest build for the merge request started.'
        },
        if: ->(_, options) { build_available?(options) } do |merge_request, _options|
        merge_request.metrics&.latest_build_started_at
      end

      expose :latest_build_finished_at,
        documentation: {
          type: 'DateTime', example: '2022-01-31T15:10:45.080Z',
          desc: 'Timestamp of when the latest build for the merge request finished.'
        },
        if: ->(_, options) { build_available?(options) } do |merge_request, _options|
        merge_request.metrics&.latest_build_finished_at
      end

      expose :first_deployed_to_production_at,
        documentation: {
          type: 'DateTime', example: '2022-01-31T15:10:45.080Z',
          desc: 'Timestamp of when the first deployment to production finished.'
        },
        if: ->(_, options) { build_available?(options) } do |merge_request, _options|
        merge_request.metrics&.first_deployed_to_production_at
      end

      expose :pipeline, using: ::API::Entities::Ci::PipelineBasic,
        documentation: {
          type: '::API::Entities::Ci::PipelineBasic',
          desc: 'Pipeline running on the branch HEAD of the merge request. Use `head_pipeline` instead, ' \
            'because it contains more information.'
        },
        if: ->(_, options) { build_available?(options) } do |merge_request, _options|
        merge_request.metrics&.pipeline
      end

      expose :head_pipeline, using: ::API::Entities::Ci::Pipeline,
        documentation: {
          type: '::API::Entities::Ci::Pipeline',
          desc: 'Pipeline that runs on the HEAD commit of the source branch. Use instead of `pipeline`, ' \
            'because it contains more information. Returned only if the current user can view pipelines ' \
            'for the project.'
        },
        if: ->(_, options) do
          Ability.allowed?(options[:current_user], :read_pipeline, options[:project])
        end

      expose :diff_refs, using: ::API::Entities::DiffRefs,
        documentation: {
          type: '::API::Entities::DiffRefs',
          desc: 'Base, head, and start SHAs of the latest diff version of the merge request. Empty when the ' \
            'merge request is created, and populates asynchronously.'
        }

      # Allow the status of a rebase to be determined
      expose :merge_error,
        documentation: {
          type: 'String', example: 'Merge error',
          desc: 'Error message shown when a merge fails. To check mergeability, use `detailed_merge_status` instead.'
        }
      expose :rebase_in_progress?, as: :rebase_in_progress,
        documentation: {
          type: 'Boolean',
          desc: 'If `true`, a rebase operation is in progress on the source branch. ' \
            'Returned only if `include_rebase_in_progress` is `true`.'
        },
        if: ->(_, options) { options[:include_rebase_in_progress] }

      expose :diverged_commits_count, as: :diverged_commits_count,
        documentation: {
          type: 'Integer', example: 0,
          desc: 'Number of commits the source branch is behind the target branch. ' \
            'Returned only if `include_diverged_commits_count` is `true`.'
        },
        if: ->(_, options) { options[:include_diverged_commits_count] }

      # We put this into an option because list of TODOs API will attach their
      # targets with Entities::MergeRequest instead of
      # Entities::MergeRequestBasic, but this attribute cannot be eagerly
      # loaded in batch for now. The list of merge requests API will
      # use Entities::MergeRequestBasic which does not support this, and
      # we always enable this for the single merge request API. This way
      # we avoid N+1 queries in the TODOs API and can still enable it for
      # the single merge request API.
      expose :first_contribution?, as: :first_contribution,
        documentation: {
          type: 'Boolean', desc: "If `true`, the merge request is the author's first contribution to the project."
        },
        if: ->(_, options) { options[:include_first_contribution] }

      def build_available?(options)
        options[:project]&.feature_available?(:builds, options[:current_user])
      end

      expose :user, documentation: { type: 'Hash', desc: 'Permissions of the current user for the merge request.' } do
        expose :can_merge,
          documentation: { type: 'Boolean', desc: 'If `true`, the current user can merge the merge request.' } do |merge_request, options|
          merge_request.can_be_merged_by?(options[:current_user])
        end
      end
    end
  end
end

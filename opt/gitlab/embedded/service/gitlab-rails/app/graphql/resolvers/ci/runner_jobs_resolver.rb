# frozen_string_literal: true

module Resolvers
  module Ci
    class RunnerJobsResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include LooksAhead

      type ::Types::Ci::JobInterface.connection_type, null: true
      authorize :read_runner_job
      authorizes_object!
      authorize_granular_token(
        permissions: :read_runner_job,
        boundaries: [
          { boundary: :owner, boundary_type: :project },
          { boundary: :owner, boundary_type: :group },
          { boundary: :instance, boundary_type: :instance }
        ]
      )
      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

      argument :statuses, [::Types::Ci::JobStatusEnum],
        required: false,
        description: 'Filter jobs by status. When the `ci_rate_limit_runner_job_list_completed_statuses` ' \
          'feature flag is enabled, requests filtered by `SUCCESS`, `FAILED`, or `CANCELED` are rate limited ' \
          'per user (`runner_job_list_completed_statuses_limit_per_user` application setting), and statuses ' \
          'a runner\'s jobs cannot have, such as `PENDING`, match no jobs. Until the ' \
          '`ci_enforce_runner_job_list_completed_statuses_limit` feature flag is enabled, requests over this ' \
          'limit are logged but not blocked.'

      alias_method :runner, :object

      def resolve_with_lookahead(statuses: nil)
        context[:job_field_authorization] = :read_build # Instruct JobType to perform field-level authorization

        verify_rate_limit!(statuses)

        scope = statuses_to_filter(statuses)
        # When every requested status was dropped, return no records
        return ::Ci::Build.none if statuses.present? && scope.empty?

        jobs = ::Ci::JobsFinder.new(current_user: current_user, runner: runner, params: { scope: scope }).execute

        apply_lookahead(jobs)
      end

      private

      # Statuses a runner's jobs can't have match nothing but make the database read every job, so we drop them
      def statuses_to_filter(statuses)
        return statuses unless statuses && completed_statuses_limit_enabled?

        statuses & ::Ci::Build::RUNNER_JOB_LIST_STATUSES
      end

      def verify_rate_limit!(statuses)
        return if (Array(statuses) & ::Ci::Build::RUNNER_JOB_LIST_RATE_LIMITED_STATUSES).empty?
        return unless completed_statuses_limit_enabled?
        return unless throttled?

        raise_resource_not_available_error!(::Gitlab::ApplicationRateLimiter.throttled_error_message)
      end

      def throttled?
        key = :runner_job_list_completed_statuses
        scope = { user: current_user }
        # GraphQL over ActionCable has no request in the context, so use the connection's
        request = context[:request] || context[:channel]&.connection&.request

        if request
          ::Gitlab::ApplicationRateLimiter.throttled_request?(request, current_user, key, scope: scope)
        else
          ::Gitlab::ApplicationRateLimiter.throttled?(key, scope: scope)
        end
      end

      def completed_statuses_limit_enabled?
        Feature.enabled?(:ci_rate_limit_runner_job_list_completed_statuses, current_user)
      end

      def preloads
        {
          previous_stage_jobs_or_needs: [:needs, :pipeline],
          artifacts: [:job_artifacts],
          pipeline: [:user],
          project: [{ project: [:route, { namespace: [:route] }, :project_feature] }],
          detailed_status: [
            :job_definition,
            :error_job_messages,
            { pipeline: [:merge_request] },
            { project: [:route, { namespace: :route }] }
          ],
          commit_path: [:pipeline, { project: { namespace: [:route] } }],
          ref_path: [{ project: [:route, { namespace: [:route] }] }],
          browse_artifacts_path: [{ project: { namespace: [:route] } }],
          play_path: [{ project: { namespace: [:route] } }],
          web_path: [{ project: { namespace: [:route] } }],
          short_sha: [:pipeline],
          tags: [:job_definition],
          trace: [{ project: [:namespace] }, :job_artifacts_trace],
          [:trace, :html_summary] => [:trace_chunks],
          [:user_permissions, :read_job_artifacts] => [:pipeline]
        }
      end
    end
  end
end

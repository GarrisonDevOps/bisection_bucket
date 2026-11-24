# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    class CreateMergeRequestService < BaseService
      include Gitlab::Utils::StrongMemoize
      include Gitlab::ExclusiveLeaseHelpers
      include Gitlab::InternalEventsTracking

      MAX_OUTPUT_ARTIFACT_SIZE = 5.megabytes
      MAX_FILE_ACTIONS = 50
      WORKLOAD_JOB_NAME = 'workload'
      LEASE_TIMEOUT = 1.minute

      private_constant :MAX_OUTPUT_ARTIFACT_SIZE, :MAX_FILE_ACTIONS, :WORKLOAD_JOB_NAME

      # @param project [Project]
      # @param pipeline [Ci::Pipeline] the completed workload pipeline
      # @param vulnerability [Vulnerability]
      def initialize(project:, pipeline:, vulnerability:)
        super(project: project)

        @pipeline = pipeline
        @vulnerability = vulnerability
      end

      def execute
        return error_response(message: 'Feature not available') unless feature_available?
        return error_response(message: 'Pipeline has not completed successfully') unless pipeline_succeeded?

        account_error = service_account_error
        return account_error if account_error

        output = fetch_and_parse_output
        return output if fetch_or_parse_failed?(output)

        empty_output = empty_output_response(output)
        return empty_output if empty_output

        # A user already closed an MR for this vulnerability and we're not proposing a
        # newer version, so don't recreate it.
        if remediation_dismissed?(output)
          reschedule_remaining_remediations
          return skipped_response
        end

        commit_result = create_branch_and_commit(output)
        return commit_result if commit_result.error?

        if commit_result.payload[:skip_reason]
          return skip_merge_request_update(commit_result.payload[:merge_request], output)
        end

        mr_result = in_lock(lease_key, ttl: LEASE_TIMEOUT, retries: 2, sleep_sec: 1.second) do
          create_or_update_merge_request(output)
        end
        return mr_result if mr_result.error?

        merge_request = mr_result.payload[:merge_request]

        link_vulnerability_to_merge_request(merge_request)
        record_remediation(merge_request, output)

        # The MR now reflects this resolution, so hold off re-resolving it for a while.
        RefreshCooldown.start(merge_request) if merge_request&.persisted?

        success_response(payload: { merge_request: merge_request })
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
        error_response(message: 'Could not obtain lock for merge request creation')
      rescue StandardError => e
        log_error(e)
        error_response(message: 'Unexpected error creating merge request')
      end

      private

      attr_reader :pipeline, :vulnerability

      def feature_available?
        project.licensed_feature_available?(:dependency_scanning)
      end

      def pipeline_succeeded?
        pipeline.complete? && pipeline.success?
      end

      def service_account
        result = DependencyManagement::ProvisionServiceAccountService
          .new(project: project)
          .execute

        return unless result.success?

        result.payload[:user]
      end
      strong_memoize_attr :service_account

      # @return [ServiceResponse, nil] an error when there is no service account, or it cannot open
      #   the merge request; nil to carry on
      def service_account_error
        return error_response(message: 'Service account not available') unless service_account

        merge_request_denial_response(service_account)
      end

      def workload_job
        pipeline.find_job_with_archive_artifacts(WORKLOAD_JOB_NAME)
      end
      strong_memoize_attr :workload_job

      def fetch_and_parse_output
        return error_response(message: 'job producing output.json artifact not found') unless workload_job

        raw_json = Gitlab::Ci::ArtifactFileReader
          .new(workload_job, max_archive_size: MAX_OUTPUT_ARTIFACT_SIZE)
          .read('output.json', max_size: MAX_OUTPUT_ARTIFACT_SIZE)

        return error_response(message: 'output.json artifact not found') unless raw_json

        OutputParser.parse(raw_json)
      rescue Gitlab::Ci::ArtifactFileReader::Error => e
        error_response(message: "Failed to read output.json artifact: #{e.message}")
      rescue OutputParser::ParseError => e
        error_response(message: "Failed to parse output.json: #{e.message}")
      end

      def fetch_or_parse_failed?(output)
        output.respond_to?(:error?) && output.error?
      end

      def empty_output_response(output)
        return error_response(message: 'No dependency changes found in output') if output.dependencies.empty?

        error_response(message: 'No updated files found in output') if output.updated_files.empty?
      end

      # The remediation branch the update is committed to, and the MR source branch. The job is guaranteed by
      # fetch_and_parse_output, which runs first.
      def update_branch
        workload_job.variables&.find { |v| v.key == UpdateService::SOURCE_REF_VARIABLE }&.value
      end
      strong_memoize_attr :update_branch

      # The project's default branch where dependency updates will be merged into.
      # Used as the MR target branch.
      def default_branch
        project.default_branch_or_main
      end

      def create_branch_and_commit(output)
        return error_response(message: 'Source ref is not set on pipeline') unless update_branch

        # Evaluated at the SHA the workload ran against: the commit is written on top of it.
        existing_paths = project.repository.blobs_at(
          output.updated_files.map { |f| [pipeline.sha, f.path] },
          blob_size_limit: 0 # existence check only, no content needed
        ).map(&:path).to_set

        actions = output.updated_files.map do |file|
          {
            action: existing_paths.include?(file.path) ? 'update' : 'create',
            file_path: file.path,
            content: file.content,
            encoding: file.encoding
          }
        end

        return error_response(message: "Too many file changes (#{actions.size})") if actions.size > MAX_FILE_ACTIONS

        merge_request = find_existing_merge_request
        return unchanged_response(merge_request) if merge_request && skip_unchanged?(merge_request, output)

        # start_sha creates the branch when it is missing; force lets the commit replace an existing
        # branch, so it always ends up as one commit on the pipeline SHA.
        result = ::Files::MultiService.new(project, service_account, {
          commit_message: build_commit_message(output),
          branch_name: update_branch,
          start_sha: pipeline.sha,
          force: true,
          actions: actions,
          author_name: service_account.name,
          author_email: service_account.commit_email_or_default
        }).execute

        if result[:status] == :success
          success_response
        else
          error_response(message: "Failed to commit changes: #{result[:message]}")
        end
      rescue Gitlab::Git::PreReceiveError => e
        error_response(
          message: "Git pre-receive hook rejected the push: #{Gitlab::Utils::ErrorMessage.to_user_facing(e.message)}"
        )
      rescue Gitlab::Git::CommandError => e
        log_error(e)
        error_response(message: "Git error while committing: #{e.message}")
      end

      def skip_unchanged?(merge_request, output)
        tip = project.repository.commit(update_branch)
        return false unless tip && output_matches_branch_tip?(output, tip)
        # A new subject, such as a move to Conventional Commits, needs a commit even when the files match.
        return false unless tip.full_title == commit_subject(output)

        !needs_rebase?(merge_request, tip)
      end

      # A merge request that cannot merge without a rebase still gets the forced commit, and so does one
      # whose merge status is not confirmed for this tip.
      def needs_rebase?(merge_request, tip)
        return true unless merge_request.diff_head_sha == tip.sha
        return true unless confirmed_mergeable?(merge_request)

        project.ff_merge_must_be_possible? && !project.repository.ancestor?(pipeline.sha, tip.sha)
      end

      # Checked now: every push resets the status, so an async check can be reset before it is read.
      # Unknown counts as not mergeable, because a needless commit is recoverable and a skip every round is not.
      def confirmed_mergeable?(merge_request)
        merge_request.check_mergeability(sync_retry_lease: true)
        merge_request.can_be_merged?
      rescue StandardError => e
        log_error(e)
        false
      end

      # The forced commit would add nothing when the merge request's change, against whatever base
      # it has, touches only the output files and already holds each of them.
      def output_matches_branch_tip?(output, tip)
        base = project.repository.merge_base(pipeline.sha, tip.sha)
        changed = project.repository.raw_repository.diff_stats(base, tip.sha)
          .flat_map { |stat| [stat.old_path.presence, stat.path] }.compact.to_set
        # No change is never unchanged output: a tip at the pipeline SHA, no merge base, and a Gitaly
        # error all come back from diff_stats as an empty collection.
        return false if changed.empty?
        return false unless changed.subset?(output.updated_files.map(&:path).to_set)

        # Comparing blob IDs avoids loading the blob data and its charset handling.
        blob_ids = project.repository.blobs_at(
          output.updated_files.map { |f| [tip.sha, f.path] },
          blob_size_limit: 0
        ).to_h { |blob| [blob.path, blob.id] }

        output.updated_files.all? { |file| blob_ids[file.path] == git_blob_id(file) }
      end

      # Mirrors the encoding the commit actions pass through; OutputParser only emits text today.
      def git_blob_id(file)
        bytes = file.encoding == 'base64' ? Base64.decode64(file.content.to_s) : file.content.to_s.b
        # rubocop:disable Fips/SHA1 -- must match the object IDs of a SHA-1 repository
        digest = project.repository.object_format == Repository::FORMAT_SHA256 ? Digest::SHA256 : Digest::SHA1
        # rubocop:enable Fips/SHA1

        digest.hexdigest("blob #{bytes.bytesize}\0".b + bytes)
      end

      def unchanged_response(merge_request)
        Gitlab::AppLogger.info(
          message: 'DependencyManagement: workload output matches the open merge request, skipping commit',
          skip_reason: :unchanged,
          Labkit::Fields::GL_PROJECT_ID => project.id,
          source_branch: update_branch
        )

        success_response(payload: { skip_reason: :unchanged, merge_request: merge_request })
      end

      # Nothing was pushed, so approvals and the diff stay. The title and description still follow the
      # output, and the idempotent bookkeeping repairs a failed first run. A workload ran, so the cooldown applies.
      def skip_merge_request_update(merge_request, output)
        mr_result = in_lock(lease_key, ttl: LEASE_TIMEOUT, retries: 2, sleep_sec: 1.second) do
          update_existing_merge_request(merge_request, output)
        end
        return mr_result if mr_result.error?

        merge_request = mr_result.payload[:merge_request]
        link_vulnerability_to_merge_request(merge_request)
        record_remediation(merge_request, output)
        RefreshCooldown.start(merge_request)
        # The head stays, but this refresh found no conflict on it, so one found later need not wait.
        RefreshCooldown.release_head(merge_request)

        success_response(payload: { merge_request: merge_request, skipped: true })
      end

      # Squash merges use the MR title as the commit, so in a conventional repository the
      # subject has to be the title or only one of the two passes commitlint.
      def build_commit_message(output)
        "#{commit_subject(output)}\n\n" \
          "#{ActionController::Base.helpers.word_wrap(build_commit_body(output), line_width: 72)}"
      end

      def commit_subject(output)
        commit_style ? build_mr_title(output) : "Update #{output.dependencies.map(&:name).join(', ')}"
      end

      def build_commit_body(output)
        dep_lines = output.dependencies.map do |dep|
          "#{dep.name}: #{dep.previous_version} → #{dep.version}"
        end

        <<~MSG.strip
          #{dep_lines.join("\n")}

          This commit was automatically generated by GitLab Dependency Management
          to remediate a security vulnerability.

          Vulnerability: #{vulnerability.title}
          Severity: #{vulnerability.severity}
        MSG
      end

      def create_or_update_merge_request(output)
        # Re-check after acquiring lock - another worker may have already created the MR
        existing_mr = find_existing_merge_request
        return update_existing_merge_request(existing_mr, output) if existing_mr

        create_new_merge_request(output)
      end

      def lease_key
        "dependency_management:create_merge_request:#{project.id}:#{update_branch}"
      end

      def find_existing_merge_request
        project.merge_requests
          .opened
          .find_by(source_branch: update_branch) # rubocop:disable CodeReuse/ActiveRecord -- single lookup
      end

      def create_new_merge_request(output)
        merge_request = ::MergeRequests::CreateService.new(
          project: project,
          current_user: service_account,
          params: {
            source_branch: update_branch,
            target_branch: default_branch,
            title: build_mr_title(output),
            description: render_mr_description(output)
          }
        ).execute_without_rate_limiting

        unless merge_request.persisted?
          return error_response(
            message: "Failed to create merge request: #{merge_request.errors.full_messages.to_sentence}"
          )
        end

        track_internal_event(
          'create_dependency_management_auto_remediation_mr',
          project: project,
          additional_properties: {
            purl_type: purl_type,
            merge_request_id: merge_request.id
          }
        )

        merge_request.assignees << service_account

        success_response(payload: { merge_request: merge_request })
      # Access can change between the check in #execute and here.
      rescue Gitlab::Access::AccessDeniedError
        log_merge_request_denial(:access_denied)
        merge_requests_not_permitted(:access_denied)
      end

      # The title carries the proposed version, and RemediationDismissalChecker parses it
      # back out of closed MRs to compare against later proposals. A refresh that resolves
      # a newer version has to move the title with the diff or that comparison reads a
      # version we never actually proposed.
      def update_existing_merge_request(merge_request, output)
        updated_mr = ::MergeRequests::UpdateService.new(
          project: project,
          current_user: service_account,
          params: {
            title: build_mr_title(output),
            description: render_mr_description(output)
          }
        ).execute(merge_request)

        if updated_mr.errors.empty?
          success_response(payload: { merge_request: updated_mr })
        else
          error_response(
            message: "Failed to update merge request: #{updated_mr.errors.full_messages.to_sentence}"
          )
        end
      end

      def build_mr_title(output)
        MergeRequestTitle.build(output.dependencies, style: commit_style)
      end

      # Decided once per MR: a refresh re-detecting from history could rename an open MR
      # back to the plain format. A plain open MR still detects, so it can move to conventional.
      def commit_style
        CommitConvention.from_title(find_existing_merge_request&.title) ||
          CommitConvention.detect(project, exclude_email: service_account.commit_email_or_default)
      end
      strong_memoize_attr :commit_style

      def render_mr_description(output)
        ApplicationController.render(
          template: 'dependency_management/security_update/merge_request_description',
          formats: :md,
          locals: {
            dependencies: output.dependencies,
            updated_files: output.updated_files,
            vulnerability: vulnerability,
            vulnerability_url: vulnerability_url
          }
        )
      end

      def vulnerability_url
        Gitlab::Routing.url_helpers.project_security_vulnerability_url(project, vulnerability)
      end

      # Named by the workload: one vulnerability can span several installed
      # versions, so guessing would record a bump that was never proposed.
      def remediated_occurrence
        candidates = SbomOccurrenceFinder.new(project: project, vulnerability: vulnerability).execute

        # Through the finder, so a foreign id cannot escape project and vulnerability.
        return candidates.find_by_id(remediated_occurrence_id) if remediated_occurrence_id

        # A pipeline started before this variable existed reaches here without it,
        # so this should stop firing once those have drained.
        Gitlab::AppLogger.warn(
          message: 'DependencyManagement: workload did not name the remediated occurrence',
          project_id: project.id,
          vulnerability_id: vulnerability.id
        )

        candidates.first
      end
      strong_memoize_attr :remediated_occurrence

      # The job is guaranteed by fetch_and_parse_output, but its variables are not,
      # and the dismissal check below runs before the source ref is validated.
      def remediated_occurrence_id
        id = workload_job.variables&.find { |v| v.key == UpdateService::SBOM_OCCURRENCE_ID_VARIABLE }&.value.to_i
        id if id.nonzero?
      end
      strong_memoize_attr :remediated_occurrence_id

      # purl_type is identical across all sbom_occurrences for a given vulnerability
      # (enforced during ingestion in Sbom::CreateOccurrencesVulnerabilitiesService),
      # so picking any one occurrence is safe.
      def purl_type
        vulnerability.sbom_occurrences.first&.purl_type
      end
      strong_memoize_attr :purl_type

      # Only the dependency this MR remediates gets a row. The updater may bump other
      # packages to make it resolve, but closing the MR is not a decision about those.
      def record_remediation(merge_request, output)
        return unless merge_request&.persisted?

        # Without a row the merge request is untracked and the bump is proposed again.
        unless remediated_occurrence&.purl_type
          Gitlab::AppLogger.warn(
            message: 'DependencyManagement: no sbom occurrence to record the remediation against',
            project_id: project.id,
            vulnerability_id: vulnerability.id
          )

          return
        end

        ::DependencyManagement::Remediation.record_proposal(
          project: project,
          merge_request: merge_request,
          purl_type: remediated_occurrence.purl_type,
          package_name: remediated_occurrence.component_name,
          input_file_path: remediated_occurrence.input_file_path,
          current_version: remediated_occurrence.version,
          target_version: target_version_for(output)
        )
      rescue StandardError => e
        # The merge request already exists, so failing would skip the refresh
        # cooldown and make the next pipeline redo the work.
        log_error(e)
      end

      def target_version_for(output)
        name = remediated_occurrence.component_name
        updater_name = JobBuilder.updater_dependency_name(remediated_occurrence.package_manager, name.to_s)
        proposed = output.version_for(updater_name)

        return proposed if proposed

        Gitlab::AppLogger.warn(
          message: 'DependencyManagement: remediated component absent from updater output',
          project_id: project.id,
          component_name: name
        )

        # target_version is the dismissal ceiling, so another package's version
        # could put it out of reach for good.
        remediated_occurrence.version
      end

      def link_vulnerability_to_merge_request(merge_request)
        return unless merge_request&.persisted?

        # A refresh reuses the existing link. Not atomic: a concurrent run can lose to the unique index, which keeps the
        # data consistent, and only logs. safe_find_or_create_by is out: its transaction skips the vulnerability read
        # trigger flag, and wrapping it in feature_flagged_transaction_for would make it a subtransaction.
        link = Vulnerabilities::MergeRequestLink.find_by_vulnerability_and_merge_request(vulnerability, merge_request)
        link ||= Vulnerabilities::MergeRequestLink.create(
          vulnerability: vulnerability,
          finding: vulnerability.finding,
          merge_request: merge_request,
          source: :auto_remediation
        )

        unless link.persisted?
          Gitlab::AppLogger.warn(
            message: 'DependencyManagement: failed to link vulnerability to merge request',
            vulnerability_id: vulnerability.id,
            merge_request_iid: merge_request.iid,
            project_id: project.id,
            errors: link.errors.full_messages
          )
          return
        end

        Vulnerabilities::Reads::UpsertService.new(
          vulnerability,
          { has_merge_request: true },
          projects: project,
          findings: Array(vulnerability.finding)
        ).execute
      rescue StandardError => e
        log_error(e)
      end

      def remediation_dismissed?(output)
        # An open MR is handled by the update path, not treated as a dismissal.
        return false if find_existing_merge_request

        # Flag-gated here rather than in the checker, so the flag also keeps the
        # occurrence lookup off this path.
        if Feature.enabled?(:dependency_management_persisted_remediations, project)
          sbom_occurrence = remediated_occurrence
        end

        RemediationDismissalChecker
          .new(project: project, vulnerability: vulnerability, sbom_occurrence: sbom_occurrence)
          .dismissed?(output)
      end

      def reschedule_remaining_remediations
        ::DependencyManagement::SecurityUpdate::RescheduleWorker.perform_async(project.id)
      end

      def skipped_response
        Gitlab::AppLogger.info(
          message: 'DependencyManagement: skipping recreation of a user-dismissed remediation',
          project_id: project.id,
          vulnerability_id: vulnerability.id,
          source_branch: update_branch
        )

        success_response(payload: { skipped: true })
      end
    end
  end
end

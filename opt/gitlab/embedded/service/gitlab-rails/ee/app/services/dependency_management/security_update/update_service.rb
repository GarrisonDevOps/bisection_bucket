# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    UpdateServiceError = Class.new(StandardError)

    class UpdateService < BaseService
      include Gitlab::Utils::StrongMemoize

      ORCHESTRATOR_IMAGE = 'registry.gitlab.com/security-products/dependency-management/orchestrator:0'

      SERVICES = %w[docker:28-dind].freeze

      ARTIFACT_PATHS = %w[output.json].freeze

      # Written inside the orchestrator container's /tmp dir - safe because
      # the container is single-use and discarded after the job completes.
      JOB_FILE_PATH = '/tmp/dependency-update-job.json'

      BRANCH_PREFIX = 'dependency-management'

      # A batch sends REMEDIATIONS_VARIABLE in place of the two single-dependency ids.
      SOURCE_REF_VARIABLE = 'DEPENDENCY_MANAGEMENT_SOURCE_REF'
      VULNERABILITY_ID_VARIABLE = 'DEPENDENCY_MANAGEMENT_VULNERABILITY_ID'
      SBOM_OCCURRENCE_ID_VARIABLE = 'DEPENDENCY_MANAGEMENT_SBOM_OCCURRENCE_ID'
      REMEDIATIONS_VARIABLE = 'DEPENDENCY_MANAGEMENT_REMEDIATIONS'

      # @param request [DependencyManagement::SecurityUpdate::Request, DependencyManagement::SecurityUpdate::BatchRequest]
      # @return [ServiceResponse]
      def execute(request)
        return error_response(message: 'Automated dependency security updates not enabled') unless valid?
        return error_response(message: 'Security Update Request not found') unless request

        @request = request
        # Validated before the workload ref is created so an invalid file costs
        # neither a CI minute nor a stale ref.
        return invalid_repository_config_response if repository_config && !repository_config.valid?

        start_workload.tap { |response| log_workload(response) }
      end

      private

      attr_reader :request

      delegate :source_ref, :target_ref, to: :request, private: true

      def start_workload
        return error_response(message: 'Failed to retrieve or create bot user') unless service_account

        denial = merge_request_denial_response(service_account)
        return denial if denial

        create_workload_on_hidden_ref
      end

      # Once the hidden ref is deleted, this line is the only link from a branch to its workload.
      def log_workload(response)
        payload = { Labkit::Fields::GL_PROJECT_ID => project.id, source_branch: source_ref }

        if response.success?
          pipeline = response.payload[:pipeline]
          Gitlab::AppLogger.info(build_structured_payload_labkit(
            message: 'DependencyManagement: started an auto-remediation workload',
            Labkit::Fields::GL_PIPELINE_ID => pipeline.id, workload_ref: pipeline.ref, **payload
          ))
        else
          Gitlab::AppLogger.error(build_structured_payload_labkit(
            message: 'DependencyManagement: failed to start an auto-remediation workload',
            Labkit::Fields::ERROR_MESSAGE => response.message, **payload
          ))
        end
      end

      def valid?
        project.can_store_security_reports?
      end

      # The remediation branch is left as it is until CreateMergeRequestService writes the result.
      # The ref is passed to RunWorkloadService unchanged, so Ci::Workloads::Workload#cleanup_refs
      # removes it once the pipeline finishes.
      def create_workload_on_hidden_ref
        ref_response = Ci::Workloads::WorkloadBranchService
          .new(project: project, source_branch: target_ref, current_user: service_account)
          .execute
        return error_response(message: ref_response.message) unless ref_response.success?

        workload_ref = ref_response.payload[:ref]
        response = create_workload(ref: workload_ref)
        # Without a workload record nothing else removes the ref.
        delete_workload_ref(workload_ref) if response.error?

        response
      rescue StandardError
        delete_workload_ref(workload_ref) if workload_ref
        raise
      end

      def delete_workload_ref(workload_ref)
        project.repository.delete_refs(workload_ref)
      rescue StandardError => e
        log_error(e)
      end

      def create_workload(ref:)
        service = Ci::Workloads::RunWorkloadService.new(
          project: project,
          current_user: service_account,
          source: :dependency_management_security_update,
          workload_definition: build_workload_definition,
          ci_variables_included: repository_config&.variables || [],
          ref: ref
        )

        response = service.execute
        return error_response(message: response.message) unless response.success?

        success_response(payload: { pipeline: response.payload.pipeline })
      end

      def build_workload_definition
        job_json = JobBuilder.new(
          request: request,
          project: project,
          auto_remediation_configuration: auto_remediation_configuration,
          credentials: repository_config&.credentials || []
        ).to_json

        Ci::Workloads::WorkloadDefinition.new do |definition|
          definition.services = SERVICES
          definition.image = ORCHESTRATOR_IMAGE
          definition.commands = build_commands(job_json)
          definition.variables = build_variables
          definition.tags = auto_remediation_configuration[:runner_tags]
          # Expose output.json so CreateMergeRequestService can read
          # the updated file contents and dependency version changes.
          definition.artifacts_paths = ARTIFACT_PATHS
        end
      end

      def build_commands(job_json)
        [
          "echo #{Shellwords.shellescape(job_json)} > #{JOB_FILE_PATH}",
          "dependency-management-orchestrator update --job-file #{JOB_FILE_PATH}"
        ]
      end

      def build_variables
        variables = {
          'DEPENDENCY_MANAGEMENT_PROJECT_PATH' => project.full_path,
          SOURCE_REF_VARIABLE => source_ref,
          'DEPENDENCY_MANAGEMENT_TARGET_REF' => target_ref,
          'DOCKER_HOST' => 'tcp://docker:2376',
          'DOCKER_TLS_CERTDIR' => '/certs'
        }

        # Workload variables are set with expand: false, so the JSON reaches the job as written.
        if request.is_a?(BatchRequest)
          variables[REMEDIATIONS_VARIABLE] = request.remediation_pairs.to_json
        else
          variables[VULNERABILITY_ID_VARIABLE] = request.vulnerability.id.to_s
          variables[SBOM_OCCURRENCE_ID_VARIABLE] = request.sbom_occurrence.id.to_s
        end

        variables
      end

      # Both callers of this service (SchedulerService and the user-triggered
      # AutoRemediation mutation) already gate on a remediation profile being
      # present, so it is safe to look it up again here.
      def auto_remediation_configuration
        Eligibility.remediation_configuration(project).fetch(:auto_remediation, {})
      end
      strong_memoize_attr :auto_remediation_configuration

      # nil while the flag is off, so the file is not even read.
      def repository_config
        return unless Feature.enabled?(:dependency_management_registry_credentials, project)

        RepositoryConfig.new(project)
      end
      strong_memoize_attr :repository_config

      # An invalid file fails every remediation on the project the same way, so
      # it is logged once per request rather than once per vulnerable occurrence.
      def invalid_repository_config_response
        Gitlab::SafeRequestStore.fetch("dependency_management:invalid_repository_config:#{project.id}") do
          Gitlab::AppLogger.error(
            build_structured_payload_labkit(
              message: 'DependencyManagement: invalid auto-remediation repository config',
              Labkit::Fields::GL_PROJECT_ID => project.id,
              Labkit::Fields::ERROR_MESSAGE => repository_config.error
            )
          )
        end

        error_response(message: repository_config.error, reason: :invalid_repository_config)
      end

      def service_account
        result = DependencyManagement::ProvisionServiceAccountService
          .new(project: project)
          .execute

        unless result.success?
          log_error(UpdateServiceError.new(result.message))
          return
        end

        result.payload[:user]
      end
      strong_memoize_attr :service_account
    end
  end
end

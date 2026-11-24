# frozen_string_literal: true

module Security
  module DependencyFirewall
    class EvaluatePackageService
      include ::Gitlab::Loggable

      # The supported set lives here rather than at the transport layer, so every caller validates
      # against one list. An unsupported ecosystem would otherwise reach the metadata lookups, match
      # nothing, and come back as a confident allow.
      ECOSYSTEMS = %w[
        maven npm pypi gem
        composer conan golang nuget cargo swift pub
      ].freeze

      # Same reasoning as ECOSYSTEMS: the transport validates against this list, and the CLI proxy
      # only performs package downloads and uploads, so the container operations stay unexposed.
      OPERATIONS = {
        'download' => EnforcementService::PACKAGE_DOWNLOAD,
        'upload' => EnforcementService::PACKAGE_UPLOAD
      }.freeze

      # Only the transient conditions the uncached metadata path hits under load. Anything else
      # raises, so a defect surfaces as a 500 rather than as a transient failure the client would
      # fail closed on forever.
      TRANSIENT_METADATA_ERRORS = [
        ActiveRecord::QueryAborted,
        ActiveRecord::ConnectionNotEstablished
      ].freeze

      def initialize(project:, current_user:, ecosystem:, name:, version:, operation:, session_id: nil)
        @project = project
        @current_user = current_user
        @ecosystem = ecosystem
        @name = name
        @version = version
        @operation = operation
        @session_id = session_id
      end

      def execute
        return error(:invalid_coordinate) unless valid_coordinate?
        return error(:not_enforced) unless enforced_for_project?

        evaluate
      end

      private

      def error(reason)
        ServiceResponse.error(message: reason.to_s.humanize, reason: reason)
      end

      def evaluate
        started_at = ::Gitlab::Metrics::System.monotonic_time

        result = firewall_check
        return error(:evaluation_failed) if result.nil?

        outcome = outcome_for(result)
        log_evaluation(outcome, ::Gitlab::Metrics::System.monotonic_time - started_at)

        ServiceResponse.success(payload: { outcome: outcome, reason: reason_for(result) })
      end

      # Returns nil when the evaluation could not be performed. The rescue is scoped both to this
      # call and to TRANSIENT_METADATA_ERRORS, so neither a bug in the mapping below nor a defect
      # inside the evaluation can be misreported as a metadata failure.
      def firewall_check
        EnforcementService.firewall_check(
          project: @project,
          pkg_type: @ecosystem,
          name: normalized_name,
          version: @version,
          # fetch without a default: the transport validated the value, so a KeyError is our bug
          # and must surface as a 500 rather than an error the client acts on.
          operation: OPERATIONS.fetch(@operation.to_s),
          current_user: @current_user,
          session_id: @session_id
        )
      rescue *TRANSIENT_METADATA_ERRORS => e
        ::Gitlab::ErrorTracking.track_exception(e, project_id: @project.id, ecosystem: @ecosystem)

        nil
      end

      # The shared normalizer handles PyPI and passes other ecosystems through. Maven needs its own
      # step: callers supply `groupId:artifactId`, but the metadata database stores
      # `groupId/artifactId`.
      def normalized_name
        name = ::Sbom::PackageUrl::Normalizer.normalize_name(type: @ecosystem.to_s, text: @name)
        return name.sub(':', '/') if @ecosystem.to_s == 'maven'

        name
      end

      # A block arrives as ServiceResponse.error carrying reason:, while warn and allow arrive as
      # successes carrying payload[:status]. Read both.
      def outcome_for(result)
        case result.reason || result.payload&.dig(:status)
        when EnforcementService::SUCCESS_BLOCKED then :blocked
        when EnforcementService::SUCCESS_WARNING then :warned
        when EnforcementService::SUCCESS_ALLOWED then :allowed
        else raise ArgumentError, "DependencyFirewall: unknown outcome #{result.inspect}"
        end
      end

      def reason_for(result)
        result.message.presence || result.payload&.dig(:message)
      end

      # The metadata path is uncached, so this duration is the measurement the caching follow-up
      # needs. Reported, not gated.
      def log_evaluation(outcome, duration)
        ::Gitlab::AppJsonLogger.info(
          build_structured_payload_labkit(
            event: 'dependency_firewall_evaluation',
            ecosystem: @ecosystem.to_s,
            operation: @operation.to_s,
            outcome: outcome.to_s,
            evaluation_duration_s: duration.round(6),
            ::Labkit::Fields::GL_PROJECT_ID => @project.id
          )
        )
      end

      # EnforcementService rejects a blank name but not a blank version, and a blank version makes
      # every advisory match, so rejecting it here prevents a spurious block.
      def valid_coordinate?
        @name.present? && @version.present? && ECOSYSTEMS.include?(@ecosystem.to_s)
      end

      def enforced_for_project?
        Availability.enforced_for?(@project)
      end
    end
  end
end

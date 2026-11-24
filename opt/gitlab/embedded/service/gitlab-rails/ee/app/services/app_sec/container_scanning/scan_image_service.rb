# frozen_string_literal: true

module AppSec
  module ContainerScanning
    class ScanImageService
      include ::Gitlab::Utils::StrongMemoize

      attr_reader :image, :project_id

      SOURCE = :container_registry_push

      def initialize(image:, project_id:)
        @image = image
        @project_id = project_id
      end

      def execute
        return unless project

        if daily_limit_reached_for?(project)
          create_throttled_log_entry
          return
        end

        user = security_policy_bot
        return unless user

        service = ::Ci::CreatePipelineService.new(project, user, ref: project.default_branch_or_main)
        result = service.execute(SOURCE, content: pipeline_config)

        unless result.success?
          log_error(StandardError.new("Failed to create pipeline: #{result.payload.full_error_messages}"))
        end

        track(user, project, result)

        result
      end

      def pipeline_config
        <<~YAML
          include:
            - template: Security/Container-Scanning.gitlab-ci.yml
          container_scanning:
            variables:
              REGISTRY_TRIGGERED: true
              CS_IMAGE: '#{image}'
            artifacts:
              reports:
                container_scanning: []
                cyclonedx: "**/gl-sbom-*.cdx.json"
              paths: ["**/gl-sbom-*.cdx.json"]
        YAML
      end

      private

      def daily_limit_reached_for?(project)
        Gitlab::ApplicationRateLimiter.throttled?(
          :container_scanning_for_registry_scans, scope: { project: project })
      end

      def create_throttled_log_entry
        ::Gitlab::AppJsonLogger.info(
          class: self.class.name,
          project_id: project_id,
          image: image,
          scan_type: :container_scanning,
          pipeline_source: SOURCE,
          limit_type: :container_scanning_for_registry_scans,
          message: 'Daily rate limit container_scanning_for_registry_scans reached'
        )
      end

      def track(user, project, result)
        Gitlab::InternalEvents.track_event(
          'container_scanning_for_registry_pipeline',
          user: user,
          project: project,
          additional_properties: {
            property: result&.status&.to_s
          }
        )
      end

      def project
        Project.find_by_id(project_id)
      end
      strong_memoize_attr :project

      def security_policy_bot
        return project.security_policy_bot if project.security_policy_bot.present?

        response = Security::Orchestration::CreateBotService
          .new(project, nil, skip_authorization: true)
          .execute

        raise StandardError, "Security Orchestration Bot was not created." unless response.user&.persisted?

        response.user
      rescue StandardError => error
        log_error(error)

        nil
      end

      def log_error(error)
        ::Gitlab::ErrorTracking.track_exception(
          error,
          class: self.class.name,
          project_id: project_id,
          image: image,
          scan_type: :container_scanning,
          pipeline_source: SOURCE,
          message: error.full_message
        )
      end
    end
  end
end

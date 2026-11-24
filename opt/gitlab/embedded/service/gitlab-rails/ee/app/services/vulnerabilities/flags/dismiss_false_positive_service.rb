# frozen_string_literal: true

module Vulnerabilities
  module Flags
    class DismissFalsePositiveService
      include Gitlab::Allowable
      include Gitlab::InternalEventsTracking

      MANUAL_ORIGIN_PREFIX = 'manual'

      REPORT_TYPE_EVENTS = {
        'sast' => 'dismiss_sast_vulnerability_false_positive_analysis',
        'secret_detection' => 'dismiss_secret_detection_vulnerability_false_positive_analysis'
      }.freeze

      def initialize(user, vulnerability)
        @user = user
        @vulnerability = vulnerability
        @project = vulnerability&.project
      end

      def execute
        return ServiceResponse.error(message: 'Vulnerability not found') unless vulnerability
        return ServiceResponse.error(message: 'Unauthorized') unless authorized?
        return ServiceResponse.error(message: 'No current finding available') unless current_finding
        return ServiceResponse.error(message: 'No vulnerability flag available to dismiss') unless can_dismiss_flag?

        create_new_flag
      end

      private

      attr_reader :user, :vulnerability, :project

      def authorized?
        project && can?(user, :admin_vulnerability, project)
      end

      def current_finding
        # currently vulnerabilities only have a single finding but this is poised to change in the future
        @current_finding ||= vulnerability&.last_finding
      end

      def create_new_flag
        flag = current_finding.vulnerability_flags.build(
          flag_type: :false_positive,
          origin: unique_manual_origin,
          confidence_score: 0.0,
          project_id: project.id,
          status: :dismissed,
          description: 'Manually dismissed as false positive'
        )

        if flag.save
          send_audit_event
          ::Vulnerabilities::EsHelper.sync_elasticsearch([vulnerability.id])

          track_event(flag)

          ServiceResponse.success(payload: { flag: flag, is_new_flag: true })
        else
          ServiceResponse.error(message: flag.errors.full_messages.join(', '))
        end
      end

      def send_audit_event
        audit_context = {
          name: 'remove_vulnerability_false_positive_flag',
          author: user,
          scope: project,
          target: vulnerability,
          target_details: "#{vulnerability.title} (ID: #{vulnerability.id})",
          message: 'Removed false positive flag'
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def unique_manual_origin
        "#{MANUAL_ORIGIN_PREFIX}_#{Time.current.to_f}_#{SecureRandom.hex(4)}"
      end

      def can_dismiss_flag?
        latest_flag = current_finding.latest_flag
        return false unless latest_flag

        latest_flag.dismissable?
      end

      def track_event(flag)
        event_name = REPORT_TYPE_EVENTS[vulnerability.report_type.to_s]
        return unless event_name

        track_internal_event(
          event_name,
          user: user,
          project: project,
          additional_properties: {
            label: flag.origin,
            value: vulnerability.id,
            property: vulnerability.severity
          }
        )
      end
    end
  end
end

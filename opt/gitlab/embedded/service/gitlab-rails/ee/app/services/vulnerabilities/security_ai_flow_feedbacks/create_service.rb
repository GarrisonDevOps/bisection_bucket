# frozen_string_literal: true

module Vulnerabilities
  module SecurityAiFlowFeedbacks
    class CreateService
      include Gitlab::Allowable
      include Gitlab::Utils::StrongMemoize
      include Gitlab::InternalEvents::ServiceTracking

      SENTIMENTS = %w[agree disagree].freeze
      REASONS = %w[verdict_wrong ignored_data_flow explanation_inaccurate confidence_miscalibrated other].freeze

      track_internal_event 'submit_security_ai_flow_feedback',
        on: :success,
        additional_properties: ->(result) { result.payload[:event_properties] }

      def initialize(current_user:, vulnerability:, sentiment:, reasons: nil)
        @current_user = current_user
        @vulnerability = vulnerability
        @project = vulnerability.project
        @sentiment = sentiment.to_s
        @reasons = Array(reasons).map(&:to_s).uniq
      end

      def execute
        unless Feature.enabled?(:security_ai_flow_feedback, project)
          return error(s_('SecurityAiFlowFeedback|Feature not available'), :feature_disabled)
        end

        return error(s_('SecurityAiFlowFeedback|Unauthorized'), :forbidden) unless authorized?

        unless flag
          return error(s_('SecurityAiFlowFeedback|No AI assessment is available for this vulnerability'),
            :no_ai_assessment)
        end

        if throttled?
          return error(
            s_('SecurityAiFlowFeedback|You have submitted feedback too many times. Please try again later.'),
            :throttled)
        end

        validation_error = validate
        return error(validation_error, :invalid) if validation_error

        ServiceResponse.success(payload: { flag: flag, event_properties: event_properties })
      end

      private

      attr_reader :current_user, :vulnerability, :project, :sentiment, :reasons

      def authorized?
        can?(current_user, :create_security_ai_flow_feedback, project)
      end

      # The feedback is about the verdict the UI shows, which is the latest flag, so only accept it when that flag
      # is an AI assessment.
      def flag
        latest = vulnerability.finding&.latest_flag
        latest if latest && ::Vulnerabilities::Flag::AI_MANAGED_ORIGINS.include?(latest.origin) && latest.dismissable?
      end
      strong_memoize_attr :flag

      def throttled?
        ::Gitlab::ApplicationRateLimiter.throttled?(:security_ai_flow_feedback_create, scope: { user: current_user })
      end

      def validate
        return s_('SecurityAiFlowFeedback|Sentiment is invalid') unless SENTIMENTS.include?(sentiment)

        if reasons.any? && sentiment != 'disagree'
          return s_('SecurityAiFlowFeedback|Reasons are only allowed when the sentiment is disagree')
        end

        s_('SecurityAiFlowFeedback|Reasons contain an invalid value') unless (reasons - REASONS).empty?
      end

      def event_properties
        metadata = metadata_builder.build

        {
          label: metadata_builder.flow_type,
          property: sentiment,
          reasons: reasons.join(',').presence,
          vulnerability_id: vulnerability.id,
          flag_id: flag.id,
          workflow_id: metadata_builder.workflow&.id,
          **metadata,
          # Custom event properties only accept strings and numbers.
          has_data_flow: metadata[:has_data_flow].to_s
        }.compact
      end

      def metadata_builder
        @metadata_builder ||= MetadataBuilder.new(flag)
      end

      def error(message, reason)
        ServiceResponse.error(message: message, reason: reason)
      end

      def tracking_project_source(_result)
        project
      end

      def tracking_namespace_source(_result)
        project.namespace
      end
    end
  end
end

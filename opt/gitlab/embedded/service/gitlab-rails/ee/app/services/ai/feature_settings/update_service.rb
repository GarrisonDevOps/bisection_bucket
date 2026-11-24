# frozen_string_literal: true

module Ai
  module FeatureSettings
    class UpdateService
      include Gitlab::InternalEventsTracking

      def initialize(feature_setting, user, params)
        @feature_setting = feature_setting
        @user = user
        @params = params
      end

      def execute
        feature_setting.assign_attributes(@params)

        return ServiceResponse.success(payload: feature_setting) if unchanged?

        if feature_setting.save
          audit_event
          track_update_events

          ServiceResponse.success(payload: feature_setting)
        else
          ServiceResponse.error(payload: feature_setting, message: feature_setting.errors.full_messages.join(", "))
        end
      end

      private

      attr_accessor :feature_setting, :user

      def unchanged?
        feature_setting.persisted? && !feature_setting.changed?
      end

      def audit_event
        audit_context = {
          name: 'self_hosted_model_feature_changed',
          author: user,
          scope: Gitlab::Audit::InstanceScope.new,
          target: feature_setting,
          message: "Feature #{feature_setting.feature} changed to #{feature_setting.provider_title}"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def track_update_events
        track_transition_to_vendored_event if transitioned_to_vendored?
      end

      def transitioned_to_vendored?
        feature_setting.vendored? &&
          feature_setting.provider_previously_changed? &&
          feature_setting.provider_before_last_save != 'vendored'
      end

      def track_transition_to_vendored_event
        track_internal_event(
          'update_self_hosted_ai_feature_to_vendored_model',
          user: user,
          additional_properties: {
            label: 'gitlab_default',
            property: feature_setting.feature
          }
        )
      end
    end
  end
end

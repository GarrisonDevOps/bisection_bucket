# frozen_string_literal: true

module Ci
  module Minutes
    class Notification
      PERCENTAGES = {
        not_set: 100,
        warning: 25,
        danger: 5,
        exceeded: 0
      }.freeze

      def initialize(project, namespace)
        @context = Ci::Minutes::Context.new(project, namespace)
        @stage = calculate_notification_stage if eligible_for_notifications?
      end

      attr_reader :stage

      delegate :namespace, :total, :current_balance, to: :context

      def show_callout?(current_user)
        return false unless stage
        return false unless namespace
        return false unless current_user
        return false if callout_has_been_dismissed?(current_user)

        Ability.allowed?(current_user, :read_compute_minutes, namespace)
      end

      def no_remaining_minutes?
        stage == :exceeded
      end

      def running_out?
        [:danger, :warning].include?(stage)
      end

      def stage_percentage
        PERCENTAGES[stage]
      end

      def percentage
        context.percent_total_minutes_remaining
      end

      def eligible_for_notifications?
        context.shared_runners_minutes_limit_enabled?
      end

      def callout_feature_id
        "ci_minutes_limit_alert_#{stage}_stage"
      end

      private

      attr_reader :context

      def callout_has_been_dismissed?(current_user)
        if namespace.user_namespace?
          current_user.dismissed_callout?(
            feature_name: callout_feature_id,
            ignore_dismissal_earlier_than: 30.days.ago
          )
        else
          current_user.dismissed_callout_for_group?(
            feature_name: callout_feature_id,
            group: namespace,
            ignore_dismissal_earlier_than: 30.days.ago
          )
        end
      end

      def calculate_notification_stage
        if percentage <= PERCENTAGES[:exceeded]
          :exceeded
        elsif percentage <= PERCENTAGES[:danger]
          :danger
        elsif percentage <= PERCENTAGES[:warning]
          :warning
        end
      end
    end
  end
end

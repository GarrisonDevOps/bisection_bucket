# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    class ToggleNamespaceService
      include Gitlab::Utils::StrongMemoize

      def initialize(group:, current_user:, enabled:)
        @group = group
        @current_user = current_user
        @enabled = enabled
      end

      def execute
        unless Ability.allowed?(@current_user, :update_knowledge_graph_setting, @group)
          return ServiceResponse.error(
            message: s_('Orbit|You do not have permission to turn GitLab Orbit on or off for this group.'),
            reason: :forbidden
          )
        end

        return disable_namespace unless @enabled

        response = enable_namespace
        ::Ai::Orbit::Settings.expire_participating_cache(@current_user) if response.success?
        response
      end

      private

      def enable_namespace
        return success_response if @group.knowledge_graph_enabled_namespace
        return trial_blocked_response unless turn_on.allowed?

        record = EnabledNamespace.new(root_namespace_id: @group.id)

        ApplicationRecord.transaction do
          record.save!
          account.record_turned_on(@group)
        end

        # The check above cached a nil association, and callers return this group.
        @group.reset_knowledge_graph_enabled_namespace
        enqueue_member_notifications
        success_response
      rescue ActiveRecord::RecordInvalid
        ServiceResponse.error(message: record.errors.full_messages.to_sentence)
      rescue ActiveRecord::RecordNotUnique # concurrent request already created the record
        @group.reset
        success_response
      rescue ::Gitlab::SubscriptionPortal::ProductTrialResponse::Error => e
        ::Gitlab::ErrorTracking.track_exception(e, gl_namespace_id: @group.id)
        ServiceResponse.error(
          message: s_('Orbit|GitLab Orbit is not available right now. Try again later.'),
          reason: :unavailable
        )
      end

      def enqueue_member_notifications
        return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        ::Analytics::Orbit::MemberNotifications::TodoWorker.perform_in(
          ::Analytics::Orbit::MemberNotifications::DELAY, @group.id
        )
      end

      def account
        ::Analytics::Orbit::Billing.account_for(@group)
      end
      strong_memoize_attr :account

      def turn_on
        account.turn_on(@group)
      end
      strong_memoize_attr :turn_on

      def trial_blocked_response
        ServiceResponse.error(message: turn_on.message, reason: turn_on.denial_reason)
      end

      def disable_namespace
        record = @group.knowledge_graph_enabled_namespace
        return success_response unless record

        if record.destroy
          @group.reset_knowledge_graph_enabled_namespace
          success_response
        else
          ServiceResponse.error(message: record.errors.full_messages.to_sentence)
        end
      end

      def success_response
        ServiceResponse.success(payload: { group: @group })
      end
    end
  end
end

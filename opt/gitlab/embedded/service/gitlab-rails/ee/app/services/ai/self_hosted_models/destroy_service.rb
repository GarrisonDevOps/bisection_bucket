# frozen_string_literal: true

module Ai
  module SelfHostedModels
    class DestroyService
      include Gitlab::InternalEventsTracking

      def initialize(self_hosted_model, user)
        @self_hosted_model = self_hosted_model
        @user = user
      end

      def execute
        if self_hosted_model.destroy
          audit_destroy_event
          track_destroy_event

          ServiceResponse.success(payload: self_hosted_model)
        else
          ServiceResponse.error(message: self_hosted_model.errors.full_messages.join(", "))
        end
      end

      private

      attr_accessor :self_hosted_model, :user

      def audit_destroy_event
        model = self_hosted_model
        audit_context = {
          name: 'self_hosted_model_destroyed',
          author: user,
          scope: Gitlab::Audit::InstanceScope.new,
          target: model,
          message: "Self-hosted model #{model.name}/#{model.model}/#{model.endpoint} destroyed"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def track_destroy_event
        track_internal_event(
          'delete_ai_self_hosted_model',
          user: user,
          additional_properties: {
            label: self_hosted_model.model,
            property: self_hosted_model.identifier
          }
        )
      end
    end
  end
end

# frozen_string_literal: true

module Ai
  module ModelSelection
    class UpsertInstanceFeatureSettingService
      include Gitlab::InternalEventsTracking

      def initialize(user, feature, offered_model_ref, catalog: nil)
        @feature = feature
        @offered_model_ref = offered_model_ref
        @user = user
        @catalog = catalog
        @setting = nil
      end

      def execute
        @setting = ::Ai::ModelSelection::InstanceModelSelectionFeatureSetting.find_or_initialize_by_feature(
          @feature
        )

        # Nothing to validate, save, audit or track when a vendored feature keeps the same selection.
        return ServiceResponse.success(payload: @setting) if skip_unchanged_selection?

        return ServiceResponse.error(message: catalog.error_message) unless catalog.success?

        if @setting.update(offered_model_ref: @offered_model_ref, model_definitions: catalog.payload)
          audit_event
          track_update_event
          ServiceResponse.success(payload: @setting)
        else
          ServiceResponse.error(
            payload: @setting,
            message: @setting.errors.full_messages.join(", ")
          )
        end
      end

      def audit_event
        audit_context = {
          name: 'self_hosted_model_feature_changed',
          author: @user,
          scope: Gitlab::Audit::InstanceScope.new,
          target: @setting,
          message: "Feature #{@feature} changed to vendored #{@offered_model_ref}"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def track_update_event
        track_internal_event(
          'update_model_selection_feature',
          user: @user,
          additional_properties: {
            label: @offered_model_ref,
            property: @feature.to_s,
            selection_scope_gid: nil
          }
        )
      end

      private

      def catalog
        @catalog ||= ::Ai::ModelSelection::ModelDefinitions.fetch(@user)
      end

      def skip_unchanged_selection?
        @setting.persisted? && feature_vendored? && same_model_ref?
      end

      def feature_vendored?
        ::Ai::FeatureSetting.find_by_feature(@feature)&.vendored?
      end

      def same_model_ref?
        # nil and "" both mean the GitLab default model.
        @setting.offered_model_ref.to_s == @offered_model_ref.to_s
      end
    end
  end
end

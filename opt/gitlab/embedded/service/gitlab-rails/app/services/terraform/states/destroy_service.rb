# frozen_string_literal: true

module Terraform
  module States
    class DestroyService
      def initialize(state, permanent: false, current_user: nil)
        @state = state
        @permanent = permanent
        @current_user = current_user
      end

      def execute
        return unless state.deleted_at?

        return if !permanent && delayed_deletion_active? && state.within_grace_period?

        state.versions.each_batch(column: :version) do |batch|
          process_batch(batch)
        end

        state.destroy!
        log_permanent_destroy if permanent
      end

      private

      attr_reader :state, :permanent, :current_user

      def delayed_deletion_active?
        Feature.enabled?(:terraform_state_delayed_deletion, state.project)
      end

      # Overridden in EE
      def process_batch(batch)
        batch.each do |version|
          version.file.remove!
        end
      end

      # Overridden in EE to record an audit event.
      def log_permanent_destroy
        Gitlab::AppLogger.info("User #{current_user&.id} permanently deleted Terraform state #{state.id}")
      end
    end
  end
end

Terraform::States::DestroyService.prepend_mod

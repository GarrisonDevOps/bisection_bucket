# frozen_string_literal: true

module EE
  module Terraform
    module States
      module DestroyService
        extend ::Gitlab::Utils::Override

        private

        override :process_batch
        def process_batch(batch)
          return super unless ::Geo::EventStore.can_create_event?

          deleted_params = batch.map { |version| version.replicator.deleted_params }

          super

          ::Terraform::StateVersion.replicator_class.bulk_create_delete_events_async(deleted_params)
        end

        override :log_permanent_destroy
        def log_permanent_destroy
          super
          return unless current_user

          ::Gitlab::Audit::Auditor.audit(
            name: 'terraform_state_permanently_deleted',
            author: current_user,
            scope: state.project,
            target: state,
            message: 'Terraform state permanently deleted'
          )
        end
      end
    end
  end
end

# frozen_string_literal: true

module Analytics
  module CycleAnalytics
    class ConsistencyWorker
      include ApplicationWorker
      include CronjobQueue

      idempotent!

      data_consistency :always
      feature_category :value_stream_management

      def perform
        unless Feature.enabled?(:vsa_aggregation_per_organization, :instance)
          return OrganizationConsistencyWorker.new.perform(nil)
        end

        Organizations::Organization.each_batch(of: 100) do |batch|
          OrganizationConsistencyWorker.bulk_perform_async_with_contexts(
            batch,
            arguments_proc: ->(organization) { [organization.id] },
            context_proc: ->(organization) { { organization: organization } }
          )
        end
      end
    end
  end
end

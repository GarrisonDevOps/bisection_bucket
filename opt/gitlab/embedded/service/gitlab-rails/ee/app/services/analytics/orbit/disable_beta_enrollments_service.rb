# frozen_string_literal: true

module Analytics
  module Orbit
    # Turns off Orbit for groups that were enabled during the beta, so GA starts with an explicit opt-in.
    class DisableBetaEnrollmentsService
      BATCH_SIZE = 100
      MAX_RUNTIME = 4.minutes

      def execute
        disabled_count = 0
        converted_count = 0
        runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)

        NamespaceEnrollment.beta.each_batch(of: BATCH_SIZE) do |batch|
          disabled, converted = disable_batch(batch.pluck_primary_key)
          disabled_count += disabled
          converted_count += converted
          break if runtime_limiter.over_time?
        end

        ServiceResponse.success(payload: {
          disabled_count: disabled_count, converted_count: converted_count, over_time: runtime_limiter.was_over_time?
        })
      end

      private

      # Returns [disabled count, converted count].
      def disable_batch(namespace_ids)
        gated_ids = Billing.promo_gated_root_ids(namespace_ids)
        add_on_ids = ::GitlabSubscriptions::AddOnPurchase.for_orbit_promo.active
          .by_namespace(gated_ids).uniq_namespace_ids

        # Opted-out groups keep plan-tier access and add-on groups stay entitled, so both keep Orbit as a direct opt-in.
        converted_count = NamespaceEnrollment.convert_beta_to_direct((namespace_ids - gated_ids) | add_on_ids)

        trial_ids, no_trial_ids = split_by_cdot_trial(gated_ids - add_on_ids)
        converted_count += NamespaceEnrollment.convert_beta_to_trial(trial_ids)

        [disable(no_trial_ids), converted_count]
      end

      # A Sales trial exists only in CDot. A group that CDot cannot answer for is in neither list, so it stays beta.
      def split_by_cdot_trial(namespace_ids)
        trial_ids = []
        no_trial_ids = []

        ::Group.id_in(namespace_ids).select(:id).each do |group|
          status = Trial.request_status_for(group)
          next if status == :unavailable

          if status.trial_active?
            trial_ids << group.id
          else
            no_trial_ids << group.id
          end
        end

        [trial_ids, no_trial_ids]
      end

      def disable(namespace_ids)
        return 0 if namespace_ids.empty?

        disabled_ids = ApplicationRecord.transaction do
          beta_ids = NamespaceEnrollment.lock_beta_namespace_ids(namespace_ids)
          ::Analytics::KnowledgeGraph::EnabledNamespace.for_root_namespace_id(beta_ids).delete_all
          NamespaceEnrollment.delete_for(beta_ids)
          beta_ids
        end

        # Re-enabling these within 30 days cancels the indexer purge.
        if disabled_ids.any?
          Gitlab::AppLogger.info(message: 'Disabled beta Orbit enrollments', disabled_namespace_ids: disabled_ids)
        end

        disabled_ids.size
      end
    end
  end
end

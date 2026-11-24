# frozen_string_literal: true

module EE
  module Gitlab
    module BillingEvents
      module Client
        extend ::Gitlab::Utils::Override

        # Offline cloud and legacy licences never sync with CustomersDot, so they have no
        # route to the collector; the Secrets Manager entitlement draws the same line. A
        # connected instance on such a licence just gains a local record.
        #
        # The realm guard is belt and braces. GitLab.com is not provisioned from an
        # offline subscription, so the licence check alone should exclude it, but that
        # rests on CustomersDot data rather than on anything readable here. The realm
        # comes from `Gitlab.org_or_com?`, so this makes the exclusion structural and
        # keeps `billable_usage_daily_namespace_aggregates` unwritable on .com and on Cells.
        override :local_persistence_enabled?
        def local_persistence_enabled?
          return super unless ::Feature.enabled?(:local_billing_persistence, :instance)
          return super if ::CloudConnector.gitlab_realm_saas?

          licensed_offline?
        end

        # Independent of local_billing_persistence: whether or not the event is kept
        # locally, an offline-licensed instance has no route to the collector, and an
        # attempt holds an emitter thread until the connect timeout and logs an error.
        # The realm guard mirrors local_persistence_enabled?.
        override :emission_enabled?
        def emission_enabled?
          return super if ::CloudConnector.gitlab_realm_saas?

          !licensed_offline?
        end

        private

        # A licence that is not an online cloud licence. Unlike
        # SecretsManagement::InstanceEnrollment.offline_license?, no licence is not offline:
        # Free instances on the EE package keep the CE behaviour.
        def licensed_offline?
          license = ::License.current
          license.present? && !license.online_cloud_license?
        end

        def persist_local_aggregate(context, quantity_kind)
          ::Utilization::BillableUsage::RecordAggregateService
            .new(context, quantity_kind: quantity_kind)
            .execute
        end
      end
    end
  end
end

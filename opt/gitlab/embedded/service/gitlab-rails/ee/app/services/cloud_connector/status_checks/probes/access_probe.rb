# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      class AccessProbe < BaseProbe
        extend ::Gitlab::Utils::Override

        validate :check_access_catalog
        validate :validate_stale_catalog
        after_validation :collect_access_details

        private

        override :success_message
        def success_message
          _("Subscription synchronized successfully.")
        end

        def access_record
          @access_record ||= CloudConnector::Access.last
        end

        def check_access_catalog
          errors.add(:base, missing_access_catalog_text) unless access_record&.catalog
        end

        def validate_stale_catalog
          return unless access_record
          return unless access_record.updated_at < CloudConnector::Access::STALE_PERIOD.ago

          errors.add(:base, stale_access_catalog_text)
        end

        def collect_access_details
          return unless access_record

          details.add(:updated_at, access_record.updated_at)
          details.add(:catalog, access_record.catalog)
        end

        # Keeping this as a separate translation key since we want to eventually link this
        # to subscriptions/self_managed/index.html#manually-synchronize-subscription-data
        def synchronize_subscription_cta
          _('Synchronize your subscription.')
        end

        def missing_access_catalog_text
          format(_("Subscription has not yet been synchronized. %{cta}"), cta: synchronize_subscription_cta)
        end

        def stale_access_catalog_text
          format(_("Subscription has not been synchronized recently. %{cta}"), cta: synchronize_subscription_cta)
        end
      end
    end
  end
end

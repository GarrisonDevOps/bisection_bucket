# frozen_string_literal: true

module Ai
  class CatalogItemAbuseReportMailer < ApplicationMailer
    MUTATION_NAMES = {
      agent: 'aiCatalogAgentDelete',
      flow: 'aiCatalogFlowDelete',
      third_party_flow: 'aiCatalogThirdPartyFlowDelete'
    }.freeze

    helper EmailsHelper

    layout 'mailer'

    helper_method :mutation_name, :catalog_item_url

    def notify(user_id, args = {})
      @reason = args[:reason]
      return unless @reason.present? && deliverable?

      @ai_catalog_item = Ai::Catalog::Item.find_by_id(args[:item_id])
      @reporter = User.find_by_id(user_id)

      return unless @reporter.present? && @ai_catalog_item.present?

      @reported_at = Time.current
      @message = args[:message]

      mail_with_locale(
        to: admin_notification_email,
        subject: format(_("ATTENTION: %{name} flagged"), name: @ai_catalog_item.name)
      )
    end

    def mutation_name
      MUTATION_NAMES.fetch(@ai_catalog_item.item_type.to_sym)
    end

    def catalog_item_url
      Gitlab::UrlBuilder.build(@ai_catalog_item)
    end

    private

    def deliverable?
      admin_notification_email.present?
    end

    def admin_notification_email
      Gitlab::CurrentSettings.abuse_notification_email
    end
  end
end

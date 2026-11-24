# frozen_string_literal: true

module Ai
  class CatalogItemAbuseReportMailerPreview < ActionMailer::Preview
    def notify
      catalog_item = Ai::Catalog::Item.first || fake_catalog_item
      user = User.first

      Ai::CatalogItemAbuseReportMailer.notify(
        user.id,
        {
          item_id: catalog_item.id,
          reason: 'Inappropriate content',
          message: 'This model contains offensive material and should be reviewed immediately.'
        }
      )
    end

    private

    def fake_catalog_item
      Struct.new(:id, :name, :item_type, :to_global_id).new(
        1,
        'Example AI Catalog Item',
        :agent,
        'gid://gitlab/Ai::CatalogResource/1'
      )
    end
  end
end

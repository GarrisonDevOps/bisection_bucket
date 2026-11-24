# frozen_string_literal: true

module EE
  module GitlabUploader # rubocop:disable Gitlab/BoundedContexts -- EE module for existing uploader
    extend ActiveSupport::Concern

    prepended do
      after :migrate, :recalculate_checksum_for_geo
    end

    def recalculate_checksum_for_geo(_migrated_file = nil)
      return unless ::Gitlab::Geo.primary?
      return unless model.respond_to?(:verification_pending!)

      model.verification_pending!
    end
  end
end

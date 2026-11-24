# frozen_string_literal: true

module PackageMetadata # rubocop:disable Gitlab/BoundedContexts -- follows existing package_metadata services pattern
  class AdvisoryDataObjectV3 < AdvisoryDataObject
    def self.cvss_v4(data)
      data.dig('advisory', 'cvss_v4')
    end
  end
end

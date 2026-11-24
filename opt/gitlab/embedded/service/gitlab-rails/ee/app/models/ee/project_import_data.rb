# frozen_string_literal: true

module EE
  module ProjectImportData
    # Required for integration with MirrorAuthentication
    def url
      project&.unsafe_import_url
    end

    extend ActiveSupport::Concern

    prepended do
      include MirrorAuthentication
    end
  end
end

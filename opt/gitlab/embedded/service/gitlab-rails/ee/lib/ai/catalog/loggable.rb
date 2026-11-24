# frozen_string_literal: true

module Ai
  module Catalog
    module Loggable
      def ai_catalog_logger
        @ai_catalog_logger ||= Logger.build.context(klass: self.class.name)
      end
    end
  end
end

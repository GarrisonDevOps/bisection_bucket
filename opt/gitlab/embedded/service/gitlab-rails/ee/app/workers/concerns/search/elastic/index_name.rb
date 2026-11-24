# frozen_string_literal: true

module Search
  module Elastic
    module IndexName
      def index_name
        if self.class.const_defined?(:DOCUMENT_TYPE)
          document_type = self.class::DOCUMENT_TYPE

          if ::Search::Elastic::Types.const_defined?(document_type.to_s, false)
            klass = ::Search::Elastic::Types.const_get(document_type.to_s, false)
            return klass.index_name
          end

          # legacy implementation
          return document_type.__elasticsearch__.index_name
        end

        raise NotImplementedError
      end
    end
  end
end

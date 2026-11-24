# frozen_string_literal: true

module Search
  module Elastic
    module DocumentType
      private

      def document_type
        return self.class::DOCUMENT_TYPE if self.class.const_defined?(:DOCUMENT_TYPE)

        raise NotImplementedError
      end

      def es_document_type
        document_type.name.underscore
      end

      def document_type_fields
        raise NotImplementedError
      end

      def document_type_plural
        document_type.to_s.pluralize
      end
    end
  end
end

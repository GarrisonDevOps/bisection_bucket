# frozen_string_literal: true

module Search
  module Elastic
    module References
      class Legacy < Reference
        def self.serialize(record)
          Search::Elastic::DocumentReference.serialize_record(record)
        end

        def self.instantiate_from_array(array)
          instantiate(Search::Elastic::DocumentReference.serialize_array(array))
        end

        override :instantiate
        def self.instantiate(string)
          doc_ref = Search::Elastic::DocumentReference.deserialize(string)
          ref_class = Search::Elastic::Helper.ref_class(doc_ref.klass.to_s)
          return ref_class.for_indexing(doc_ref.database_id, doc_ref.es_parent) if ref_class

          doc_ref
        end

        def self.init(*args)
          Search::Elastic::DocumentReference.new(*args)
        end
      end
    end
  end
end

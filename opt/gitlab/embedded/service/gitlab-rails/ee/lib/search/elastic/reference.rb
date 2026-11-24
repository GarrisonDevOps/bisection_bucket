# frozen_string_literal: true

module Search
  module Elastic
    class Reference
      extend ::Gitlab::Utils::Override
      extend Search::Elastic::Concerns::ReferenceUtils

      DELIMITER = '|'
      PRELOAD_BATCH_SIZE = 1_000

      attr_accessor :database_record, :database_id

      InvalidError = Class.new(StandardError)
      ReferenceFailure = Class.new(StandardError)

      def serialize
        raise NotImplementedError
      end

      def identifier
        raise NotImplementedError
      end

      def routing
        nil
      end

      def operation
        raise NotImplementedError
      end

      def as_indexed_json
        raise NotImplementedError
      end

      def index_name
        raise NotImplementedError
      end

      def klass
        self.class.name.demodulize
      end

      def model_klass
        self.class.model_klass
      end

      class << self
        def ref(item, klass = ::Search::Elastic::References::Legacy)
          klass.serialize(item)
        end

        def build(item, klass = ::Search::Elastic::References::Legacy)
          deserialize(ref(item, klass))
        end

        def init(klass, id, es_id, es_parent)
          ref_class = Search::Elastic::Helper.ref_class(klass.to_s)

          return ref_class.for_indexing(id, es_parent) if ref_class

          ::Search::Elastic::References::Legacy.init(klass.to_s, id, es_id, es_parent)
        end

        # Factory method for creating a reference from an id and es_parent.
        # Subclasses may override this; the default assumes a (id, es_parent) constructor.
        def for_indexing(id, es_parent)
          new(id, es_parent)
        end

        def serialize(item)
          case item
          when String
            item
          when Search::Elastic::Reference, Search::Elastic::DocumentReference
            item.serialize
          when ApplicationRecord
            item.elastic_reference
          else
            raise InvalidError, "Don't know how to serialize #{item.class}"
          end
        end

        def deserialize(string)
          ref_klass = ref_klass(string)

          if ref_klass
            ref_klass.instantiate(string)
          else
            legacy_ref_klass.instantiate(string)
          end
        end

        def preload_database_records(refs)
          refs.group_by(&:class).each do |klass, class_refs|
            class_refs.each_slice(PRELOAD_BATCH_SIZE) do |group_slice|
              klass.preload_indexing_data(group_slice)
            end
          end

          refs
        end

        def instantiate(_)
          raise NotImplementedError
        end

        def preload_indexing_data(_)
          raise NotImplementedError
        end

        def model_klass
          raise NotImplementedError
        end
      end
    end
  end
end

# frozen_string_literal: true

module Search
  module Elastic
    # Tracks some essential information needed to tie database and elasticsearch
    # records together, and to delete ES documents when the database object no
    # longer exists.
    #
    # A custom serialisation format suitable for Redis is included.
    class DocumentReference
      include Gitlab::Utils::StrongMemoize

      DEFAULT_DELIMITER = '|'
      LEGACY_DELIMITER = ' '

      PRELOAD_BATCH_SIZE = 1_000

      InvalidError = Class.new(StandardError)

      class << self
        def build(instance)
          new(instance.class, instance.id, instance.es_id, instance.es_parent)
        end

        def serialize(anything)
          case anything
          when String
            anything
          when Search::Elastic::DocumentReference
            anything.serialize
          when ApplicationRecord
            serialize_record(anything)
          when Array
            serialize_array(anything)
          else
            raise InvalidError, "Don't know how to serialize #{anything.class}"
          end
        end

        def serialize_record(record)
          serialize_array([record.class.to_s, record.id, record.es_id, record.es_parent].compact)
        end

        def serialize_array(array)
          test_array!(array)

          array.join(LEGACY_DELIMITER)
        end

        def deserialize(string)
          delimiter = string.include?(DEFAULT_DELIMITER) ? DEFAULT_DELIMITER : LEGACY_DELIMITER
          deserialize_array(string.split(delimiter))
        end

        def deserialize_array(array)
          test_array!(array)

          new(*array)
        end

        def preload_indexing_data(refs)
          refs.group_by(&:klass).each do |klass, group|
            ids = group.map(&:db_id)

            records = klass.id_in(ids).preload_indexing_data
            records_by_id = records.index_by(&:id)

            group.each do |ref|
              ref.database_record = records_by_id[ref.database_id.to_i]
            end
          end

          refs
        end

        private

        def test_array!(array)
          raise InvalidError, "Bad array representation: #{array.inspect}" unless
            (3..4).cover?(array.size)
        end
      end

      attr_reader :klass, :db_id, :es_id, :es_parent

      alias_attribute :identifier, :es_id
      alias_method :routing, :es_parent
      alias_attribute :database_id, :db_id

      def initialize(klass_or_name, db_id, es_id, es_parent = nil)
        @klass = klass_or_name
        @klass = klass_or_name.constantize if @klass.is_a?(String)
        @db_id = db_id
        @es_id = es_id
        @es_parent = es_parent
      end

      def ==(other)
        other.instance_of?(self.class) &&
          serialize == other.serialize
      end

      def klass_name
        klass.to_s
      end

      def database_record
        klass.find_by_id(db_id)
      end
      strong_memoize_attr :database_record

      def database_record=(record)
        strong_memoize(:database_record) { record }
      end

      def serialize
        self.class.serialize_array([klass_name, db_id, es_id, es_parent].compact)
      end

      def operation
        database_record.present? ? index_operation : :delete
      end
      strong_memoize_attr :operation

      def as_indexed_json
        proxy.as_indexed_json
      end

      def index_name
        operation == :delete ? klass_proxy.index_name : proxy.index_name
      end

      def document_type
        operation == :delete ? klass_proxy.document_type : proxy.document_type
      end

      def proxy
        database_record.__elasticsearch__
      end

      def klass_proxy
        klass.__elasticsearch__
      end

      private

      def index_operation
        return :upsert if [Issue, Epic, WorkItem].include?(klass)

        :index
      end
    end
  end
end

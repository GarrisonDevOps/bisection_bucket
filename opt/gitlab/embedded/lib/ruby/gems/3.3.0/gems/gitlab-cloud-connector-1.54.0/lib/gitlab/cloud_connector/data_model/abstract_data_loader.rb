# frozen_string_literal: true

module Gitlab
  module CloudConnector
    module DataModel
      class AbstractDataLoader
        def initialize(model_class)
          @model_class = model_class
        end

        def load_with_index!
          with_cache do
            build_name_index(load!)
          end
        end

        protected

        attr_reader :model_class

        def load!
          raise NotImplementedError, "#{self.class} must implement #load!"
        end

        # Optional: subclasses can wrap caching around the computation
        def with_cache
          yield
        end

        def build_name_index(records)
          records.each_with_object({}) do |record, index|
            index[record.name.to_sym] = record

            next unless record.respond_to?(:alias_names)

            record.alias_names&.each do |alias_name|
              index[alias_name.to_sym] = record
            end
          end
        end
      end
    end
  end
end

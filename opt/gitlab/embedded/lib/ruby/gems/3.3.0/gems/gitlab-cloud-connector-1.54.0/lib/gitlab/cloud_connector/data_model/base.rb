# frozen_string_literal: true

require_relative 'associations'

module Gitlab
  module CloudConnector
    module DataModel
      class Base
        include Associations
        extend Enumerable

        class << self
          def model_name
            name&.demodulize
          end

          def each(&block)
            all.each(&block)
          end

          def find_by_name(name)
            name_index[name.to_sym]
          end

          def all
            name_index.values.uniq
          end

          private

          def name_index
            data_loader.load_with_index!
          end

          def data_loader
            @data_loader ||= Configuration.data_loader_class.new(self)
          end
        end

        def initialize(**opts)
          opts.each do |key, value|
            raise ArgumentError, "Cannot override association '#{key}'" if association_key?(key)

            instance_variable_set(:"@#{key}", value)
          end
        end

        def [](name)
          instance_variable_get(:"@#{name}")
        end

        def association_key?(key)
          self.class.association_cache_keys.include?(key.to_sym)
        end

        def to_hash
          instance_variables.each_with_object({}) do |var, hash|
            key = var.to_s.delete('@').to_sym

            hash[key] = instance_variable_get(var) unless association_key?(key)
          end
        end
      end
    end
  end
end

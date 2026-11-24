# frozen_string_literal: true

module Gitlab
  module CloudConnector
    module DataModel
      module Associations
        module ClassMethods
          def associations
            @associations ||= []
          end

          def association_cache_keys
            @association_cache_keys ||= associations.map { |a| :"#{a}_association" }
          end

          # rubocop:disable Naming/PredicateName
          def has_and_belongs_to_many(name)
            associations << name.to_sym

            remove_instance_variable(:@association_cache_keys) if instance_variable_defined?(:@association_cache_keys)

            define_method(name) do
              instance_variable_get(:"@#{name}_association") ||
                instance_variable_set(:"@#{name}_association", load_association_records(name))
            end
          end
          # rubocop:enable Naming/PredicateName
        end

        def self.included(base)
          base.extend ClassMethods
        end

        private

        def load_association_records(association_name)
          value = Array(instance_variable_get(:"@#{association_name}"))

          # Check if the association is already loaded.
          return value if !value.empty? && value.all?(Gitlab::CloudConnector::DataModel::Base)

          names = Array(self[association_name])
          association_class = Gitlab::CloudConnector::DataModel.const_get(association_name.to_s.classify)
          association_class.select { |record| names.include?(record.name.to_s) }
        end
      end
    end
  end
end

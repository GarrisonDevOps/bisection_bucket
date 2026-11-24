# frozen_string_literal: true

module Geo
  class CiSecureFileRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry

    belongs_to :ci_secure_file, class_name: 'Ci::SecureFile'

    def self.model_class
      ::Ci::SecureFile
    end

    def self.model_foreign_key
      :ci_secure_file_id
    end
  end
end

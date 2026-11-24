# frozen_string_literal: true

module Geo
  class PersonalSnippetUploadRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    include ::Geo::PartitionUploadRegistry

    belongs_to :personal_snippet_upload, class_name: 'Geo::PersonalSnippetUpload'

    def self.model_class
      ::Geo::PersonalSnippetUpload
    end

    def self.model_foreign_key
      :personal_snippet_upload_id
    end

    def self.model_updated_last
      :created_at
    end
  end
end

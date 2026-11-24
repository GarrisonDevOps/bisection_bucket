# frozen_string_literal: true

module Geo
  class PersonalSnippetUploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior
    extend ::Gitlab::Utils::Override

    def self.model
      ::Geo::PersonalSnippetUpload
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Personal Snippet Upload')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Personal Snippet Uploads')
    end
  end
end

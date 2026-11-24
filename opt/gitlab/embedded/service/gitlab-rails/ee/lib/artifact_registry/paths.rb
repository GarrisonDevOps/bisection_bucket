# frozen_string_literal: true

module ArtifactRegistry
  module Paths
    API_VERSION = 'api/v1'
    GITLAB_API_VERSION = 'api/gitlab/v1'
    NAMESPACES_PATH = "#{GITLAB_API_VERSION}/namespaces".freeze

    private

    def namespaces_path
      NAMESPACES_PATH
    end

    def namespace_path(uuid)
      "#{namespaces_path}/#{encode_segment(uuid)}"
    end

    def namespace_condition_path(uuid, action)
      "#{namespace_path(uuid)}/#{encode_segment(action)}"
    end

    def repositories_path(slug)
      "#{API_VERSION}/#{encode_segment(slug)}/repositories"
    end

    def namespace_statistics_path(slug)
      "#{API_VERSION}/#{encode_segment(slug)}/statistics"
    end

    def verifications_path(namespace_id)
      "#{namespace_path(namespace_id)}/repositories/verifications"
    end

    def repository_path(slug, name)
      "#{repositories_path(slug)}/#{encode_segment(name)}"
    end

    def repository_test_path(slug, name)
      "#{repository_path(slug, name)}/test"
    end

    def repository_statistics_path(slug, name)
      "#{repository_path(slug, name)}/statistics"
    end

    def connection_test_path(slug)
      "#{API_VERSION}/#{encode_segment(slug)}/connection_test"
    end

    def namespace_details_path(slug)
      "#{API_VERSION}/#{encode_segment(slug)}/namespace"
    end

    def artifacts_path(slug, repository_name, format, collection)
      "#{repository_path(slug, repository_name)}/#{encode_segment(format)}/#{collection}"
    end

    def artifact_path(slug, repository_name, format, collection, id)
      "#{artifacts_path(slug, repository_name, format, collection)}/#{encode_segment(id)}"
    end

    def sub_collection_path(slug, repository_name, format, collection, id, sub_collection)
      "#{artifacts_path(slug, repository_name, format, collection)}/#{encode_segment(id)}/#{sub_collection}"
    end

    def sub_collection_member_path(slug, repository_name, format, collection, id, sub_collection, member_id)
      path = sub_collection_path(slug, repository_name, format, collection, id, sub_collection)

      "#{path}/#{encode_segment(member_id)}"
    end

    def manifest_path(slug, repository_name, format, image_id, digest)
      sub_collection_member_path(slug, repository_name, format, 'images', image_id, 'manifests', digest)
    end

    def bulk_delete_path(slug, repository_name, format, collection)
      "#{artifacts_path(slug, repository_name, format, collection)}/bulk_delete"
    end

    def nested_bulk_delete_path(slug, repository_name, format, collection, id, sub_collection)
      "#{sub_collection_path(slug, repository_name, format, collection, id, sub_collection)}/bulk_delete"
    end

    def encode_segment(value)
      ERB::Util.url_encode(value.to_s)
    end
  end
end

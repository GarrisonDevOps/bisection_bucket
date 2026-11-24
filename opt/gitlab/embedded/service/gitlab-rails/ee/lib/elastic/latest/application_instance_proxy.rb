# frozen_string_literal: true

module Elastic
  module Latest
    class ApplicationInstanceProxy < Elasticsearch::Model::Proxy::InstanceMethodsProxy
      include InstanceProxyUtil

      def es_parent
        "project_#{target.project_id}" unless target&.project_id.nil?
      end

      def es_type
        self.class.es_type
      end

      def es_id
        ::Search::Elastic::Helper.build_es_id(es_type: es_type, target_id: target.id)
      end

      def namespace_ancestry
        project = target.is_a?(Project) ? target : target.project
        project.namespace.elastic_namespace_ancestry
      end

      private

      def generic_attributes
        { 'type' => es_type }
      end
    end
  end
end

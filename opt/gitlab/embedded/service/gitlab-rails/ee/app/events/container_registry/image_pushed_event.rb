# frozen_string_literal: true

module ContainerRegistry
  class ImagePushedEvent < ::Gitlab::EventStore::Event
    attr_accessor :project

    def schema
      {
        'type' => 'object',
        'required' => %w[project_id image],
        'properties' => {
          'project_id' => { 'type' => 'integer' },
          'image' => { 'type' => 'string' },
          'repository' => { 'type' => 'string' },
          'tag' => { 'type' => 'string' },
          'digest' => { 'type' => 'string' }
        }
      }
    end
  end
end

# frozen_string_literal: true

module Geo
  module SystemCheck
    class ContainerRegistryCheck < ::SystemCheck::BaseCheck
      set_name 'Container Registry replication enabled'
      set_skip_reason 'Container Registry replication is not enabled'

      def skip?
        !Gitlab.config.geo.registry_replication.enabled
      end

      def multi_check
        if skip?
          $stdout.puts "skipped (#{self.class.skip_reason})"
          return
        end

        $stdout.puts "yes"
        show_event_info
      end

      private

      def show_event_info
        last_event = find_last_container_registry_event

        if last_event.nil?
          $stdout.puts "Container Registry Geo events ... none found"
        else
          timestamp = last_event.created_at.utc.strftime('%Y-%m-%d %H:%M:%S UTC')
          $stdout.puts "Container Registry Geo events ... last event at #{timestamp}"
        end
      end

      def find_last_container_registry_event
        ::Geo::Event.for_replicable('container_repository').last
      end
    end
  end
end

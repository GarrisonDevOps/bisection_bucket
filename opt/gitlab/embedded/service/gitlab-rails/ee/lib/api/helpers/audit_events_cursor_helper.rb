# frozen_string_literal: true

module API
  module Helpers
    module AuditEventsCursorHelper
      def enrich_audit_event_cursor(cursor, resource)
        return cursor unless cursor.present?

        cursor_data = Gitlab::Pagination::Keyset::Paginator::Base64CursorConverter.parse(cursor)
        cursor_id = cursor_data['id']&.to_i

        return cursor unless cursor_id
        return cursor if cursor_data['created_at'].present?

        created_at = fetch_created_at_for_audit_event(cursor_id, resource)

        if created_at
          cursor_data['created_at'] = created_at.to_fs(:inspect)
          Gitlab::Pagination::Keyset::Paginator::Base64CursorConverter.dump(cursor_data)
        else
          cursor
        end
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e)
        cursor
      end

      def limit_keyset_per_page!
        params[:per_page] = [params[:per_page], Kaminari.config.max_per_page].min
      end

      def strip_created_at_from_cursor(cursor)
        return cursor unless cursor.present?

        cursor_data = Gitlab::Pagination::Keyset::Paginator::Base64CursorConverter.parse(cursor)

        if cursor_data['created_at'].present?
          cursor_data.delete('created_at')
          Gitlab::Pagination::Keyset::Paginator::Base64CursorConverter.dump(cursor_data)
        else
          cursor
        end
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e)
        cursor
      end

      private

      def fetch_created_at_for_audit_event(cursor_id, resource)
        if resource.is_a?(Group)
          ::AuditEvents::GroupAuditEvent.id_in(cursor_id).pick(:created_at)
        elsif resource.is_a?(Project)
          ::AuditEvents::ProjectAuditEvent.id_in(cursor_id).pick(:created_at)
        end
      end
    end
  end
end
